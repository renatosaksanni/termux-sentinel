"""Static APK analysis built on the pure-Python AXML decoder.

Extracts the facts the risk engine reasons about: identity, SDK levels,
requested permissions, exported components, signer certificate, and indicators
found inside the DEX bytecode.

Everything here treats the APK as hostile input. Archives are read entry by
entry with size caps so a zip bomb cannot exhaust memory on a phone.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
import zipfile
from dataclasses import dataclass, field

from .axml import AxmlError, parse

# A single entry is never read past this. DEX files in real apps run to tens of
# megabytes; anything larger is either irrelevant or an attempt to stall us.
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_DEX_SCAN_BYTES = 24 * 1024 * 1024

# Components that expose an app to other apps, and are therefore where an
# attacker reaches in from outside.
EXPOSED_TAGS = ("activity", "service", "receiver", "provider")

# Byte patterns hunted inside DEX. Each is a capability marker rather than a
# verdict on its own -- the scoring layer decides what a combination means.
DEX_INDICATORS: dict[str, bytes] = {
    "dynamic_code_loading": b"DexClassLoader",
    "dynamic_code_loading_path": b"PathClassLoader",
    "reflection_invoke": b"java/lang/reflect/Method",
    "runtime_exec": b"Ljava/lang/Runtime;",
    "process_builder": b"ProcessBuilder",
    "su_binary": b"/system/bin/su",
    "root_check": b"Superuser.apk",
    "sms_send": b"sendTextMessage",
    "sms_receive": b"android.provider.Telephony.SMS_RECEIVED",
    "accessibility_service": b"AccessibilityService",
    "device_admin": b"DeviceAdminReceiver",
    "package_installer": b"application/vnd.android.package-archive",
    "overlay_window": b"TYPE_APPLICATION_OVERLAY",
    "screen_capture": b"MediaProjection",
    "audio_record": b"android/media/AudioRecord",
    "keylogger_hint": b"onAccessibilityEvent",
    "crypto_miner": b"stratum+tcp",
    "native_load": b"System.loadLibrary",
    "base64_decode": b"android/util/Base64",
    "http_plain": b"http://",
    "telegram_c2": b"api.telegram.org/bot",
    "pastebin_c2": b"pastebin.com/raw",
    "hidden_launcher": b"setComponentEnabledSetting",
}

_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,120}")
# Reject matches embedded in longer dotted runs, which are almost always
# version tuples or resource identifiers rather than addresses.
_IP_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _plausible_public_ip(s: str) -> bool:
    """Filter DEX dotted-quads down to addresses worth reporting.

    DEX blobs are full of version strings that look like IPv4. Keeping only
    routable public addresses removes essentially all of that noise; the cost
    is that hardcoded LAN addresses are dropped, which we accept because they
    are rarely the C2 indicator anyone acts on.
    """
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if any(v > 255 for v in o):
        return False
    if all(v <= 20 for v in o):  # version-number shaped
        return False
    a, b = o[0], o[1]
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    return True


@dataclass
class Component:
    kind: str
    name: str
    exported: bool
    permission: str = ""


@dataclass
class ApkInfo:
    path: str
    size: int = 0
    sha256: str = ""
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    custom_permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True
    cleartext_traffic: bool | None = None
    shared_uid: str = ""
    signer_sha256: str = ""
    signer_subject: str = ""
    signer_approximate: bool = False
    has_signing_block: bool = False
    v1_signed: bool = True
    dex_truncated: bool = False
    dex_indicators: dict[str, bool] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    entry_count: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def exported_components(self) -> list[Component]:
        return [c for c in self.components if c.exported]

    @property
    def indicator_names(self) -> list[str]:
        return sorted(k for k, v in self.dex_indicators.items() if v)


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _read_entry(z: zipfile.ZipFile, name: str, cap: int = MAX_ENTRY_BYTES) -> bytes:
    """Read one archive entry, refusing absurd declared sizes."""
    try:
        zi = z.getinfo(name)
    except KeyError:
        return b""
    if zi.file_size > cap:
        raise ValueError(f"{name}: {zi.file_size} bytes exceeds cap")
    with z.open(zi, "r") as fh:
        return fh.read(cap + 1)[:cap]


def _has_signing_block(path: str) -> bool:
    """Detect the v2/v3+ APK Signing Block.

    The block sits immediately before the ZIP central directory, and its magic
    occupies the 16 bytes ending at that offset. Locating the central directory
    through the End Of Central Directory record is the only reliable way to
    find it: a naive scan of the last N bytes misses it on any APK whose
    central directory is larger than the window, which is most real apps.

    Its absence on a modern app means the APK carries only the legacy v1 JAR
    signature, which is trivially rewritable and a common repackaging tell.
    """
    magic = b"PK\x05\x06"  # EOCD signature
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            # The EOCD is at the very end, plus up to 64 KiB of comment.
            window = min(size, 66 * 1024)
            fh.seek(size - window)
            tail = fh.read(window)

            idx = tail.rfind(magic)
            if idx < 0 or idx + 20 > len(tail):
                return False
            cd_offset = struct.unpack_from("<I", tail, idx + 16)[0]
            if cd_offset == 0xFFFFFFFF or cd_offset < 24 or cd_offset > size:
                return False  # ZIP64 or nonsense; treat as undetermined

            # The 16-byte magic ends exactly at the central directory offset.
            fh.seek(cd_offset - 24)
            return fh.read(24)[8:24] == b"APK Sig Block 42"
    except (OSError, struct.error):
        return False


def _openssl(args: list[str], stdin: bytes) -> bytes:
    """Run openssl over binary stdin, returning stdout or b'' on any failure."""
    try:
        p = subprocess.run(
            ["openssl", *args],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=25,
        )
        return p.stdout if p.returncode == 0 else b""
    except (OSError, subprocess.SubprocessError):
        return b""


def _signer_info(z: zipfile.ZipFile, info: ApkInfo) -> None:
    """Recover the signing certificate fingerprint.

    Prefers openssl for a true certificate hash. Without it, falls back to
    hashing the PKCS#7 blob, which still groups identically-signed apps but is
    not the certificate digest Google Play would show -- flagged accordingly.
    """
    certs = [
        n
        for n in z.namelist()
        if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
    ]
    if not certs:
        # Optional since API 24. Only meaningful when v2+ is missing too, which
        # the caller decides; reporting it here produced noise on every modern app.
        info.v1_signed = False
        if not info.has_signing_block:
            info.errors.append("no signature found: neither v1 nor v2+")
        return
    try:
        blob = _read_entry(z, certs[0], cap = 8 * 1024 * 1024)
    except ValueError as exc:
        info.errors.append(str(exc))
        return
    if not blob:
        return

    # Convert PKCS#7 -> PEM, then fingerprint the first (signer) certificate.
    # Two openssl hops, because openssl cannot emit a cert chain as raw DER.
    pem = _openssl(["pkcs7", "-inform", "DER", "-print_certs"], blob)
    if pem and b"BEGIN CERTIFICATE" in pem:
        end = pem.find(b"-----END CERTIFICATE-----")
        start = pem.find(b"-----BEGIN CERTIFICATE-----")
        if start != -1 and end != -1:
            leaf = pem[start : end + len(b"-----END CERTIFICATE-----")] + b"\n"
            fp = _openssl(["x509", "-noout", "-fingerprint", "-sha256"], leaf)
            subj = _openssl(["x509", "-noout", "-subject"], leaf)
            if subj:
                info.signer_subject = subj.decode("utf-8", "replace").strip()[:200]
            if fp and b"=" in fp:
                digest = fp.decode("ascii", "replace").split("=", 1)[1]
                info.signer_sha256 = digest.strip().replace(":", "").lower()
                return

    # No openssl available: hashing the PKCS#7 blob still groups apps signed by
    # the same key, but it is not the certificate digest Play Store displays.
    info.signer_sha256 = hashlib.sha256(blob).hexdigest()
    info.signer_approximate = True


def _scan_dex(z: zipfile.ZipFile, info: ApkInfo) -> None:
    """Search DEX payloads for capability markers, URLs, and bare IPs."""
    dex_names = [n for n in z.namelist() if n.endswith(".dex")]
    budget = MAX_DEX_SCAN_BYTES
    urls: set[bytes] = set()
    ips: set[bytes] = set()

    for name in dex_names:
        try:
            zi = z.getinfo(name)
        except KeyError:
            continue
        if zi.file_size > budget:
            # Stop rather than fail: large multidex apps are normal, and the
            # indicators we look for are overwhelmingly in the first classes.dex.
            info.dex_truncated = True
            break
        try:
            blob = _read_entry(z, name, cap=min(budget, MAX_ENTRY_BYTES))
        except ValueError:
            info.dex_truncated = True
            continue
        budget -= len(blob)

        for key, needle in DEX_INDICATORS.items():
            if not info.dex_indicators.get(key) and needle in blob:
                info.dex_indicators[key] = True

        urls.update(_URL_RE.findall(blob)[:400])
        ips.update(_IP_RE.findall(blob)[:200])

    info.urls = sorted({u.decode("utf-8", "replace") for u in urls})[:60]
    info.ips = sorted(
        {s for s in (raw.decode("ascii", "replace") for raw in ips) if _plausible_public_ip(s)}
    )[:40]


def extract_dex(path: str, dest_dir: str, limit: int = 3) -> list[str]:
    """Unpack classes*.dex so a content scanner can actually see the bytecode.

    YARA does not decompress archives, so rules written against DEX would never
    fire on an APK. Extracting the payload is what makes them work at all.
    ClamAV needs none of this -- it unpacks archives internally.
    """
    out: list[str] = []
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return out
    with z:
        names = sorted(n for n in z.namelist() if n.endswith(".dex"))[:limit]
        for i, name in enumerate(names):
            try:
                blob = _read_entry(z, name, cap=MAX_DEX_SCAN_BYTES)
            except (ValueError, OSError, zipfile.BadZipFile):
                continue
            if not blob:
                continue
            dest = os.path.join(dest_dir, f"{os.path.basename(path)}.{i}.dex")
            try:
                with open(dest, "wb") as fh:
                    fh.write(blob)
                out.append(dest)
            except OSError:
                continue
    return out


def analyze(path: str, deep: bool = True) -> ApkInfo:
    """Analyse one APK. `deep=False` skips DEX and certificate work.

    Never raises for malformed archives: an unreadable APK is itself a finding,
    recorded in `errors`, and the caller decides what that means.
    """
    info = ApkInfo(path=path)
    try:
        info.size = os.path.getsize(path)
        info.sha256 = sha256_file(path)
    except OSError as exc:
        info.errors.append(f"unreadable: {exc}")
        return info

    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        info.errors.append(f"not a valid archive: {exc}")
        return info

    with z:
        info.entry_count = len(z.namelist())
        info.native_libs = sorted(
            {n.split("/")[1] for n in z.namelist() if n.startswith("lib/") and "/" in n[4:]}
        )[:12]

        try:
            manifest = _read_entry(z, "AndroidManifest.xml")
        except ValueError as exc:
            manifest = b""
            info.errors.append(str(exc))

        if not manifest:
            info.errors.append("AndroidManifest.xml missing or unreadable")
        else:
            try:
                _apply_manifest(parse(manifest), info)
            except AxmlError as exc:
                info.errors.append(f"manifest decode failed: {exc}")

        if deep:
            info.has_signing_block = _has_signing_block(path)
            try:
                _signer_info(z, info)
            except (OSError, ValueError) as exc:
                info.errors.append(f"signature read failed: {exc}")
            try:
                _scan_dex(z, info)
            except (OSError, ValueError) as exc:
                info.errors.append(f"dex scan failed: {exc}")

    return info


def _apply_manifest(elements, info: ApkInfo) -> None:
    """Fold decoded manifest elements into the ApkInfo record."""
    for el in elements:
        if el.name == "manifest":
            info.package = el.get("package")
            info.version_name = el.get("versionName")
            info.version_code = el.get("versionCode")
            info.shared_uid = el.get("sharedUserId")
            # Modern manifests may carry SDK levels here instead of <uses-sdk>.
            info.min_sdk = info.min_sdk or el.get_int("minSdkVersion")
            info.target_sdk = info.target_sdk or el.get_int("targetSdkVersion")

        elif el.name == "uses-sdk":
            info.min_sdk = el.get_int("minSdkVersion", info.min_sdk)
            info.target_sdk = el.get_int("targetSdkVersion", info.target_sdk)

        elif el.name == "uses-permission" or el.name == "uses-permission-sdk-23":
            name = el.get("name")
            if name:
                info.permissions.append(name)

        elif el.name == "permission":
            name = el.get("name")
            if name:
                info.custom_permissions.append(name)

        elif el.name == "application":
            info.debuggable = el.get_bool("debuggable", False)
            info.allow_backup = el.get_bool("allowBackup", True)
            if "usesCleartextTraffic" in el.attrs:
                info.cleartext_traffic = el.get_bool("usesCleartextTraffic", False)

        elif el.name in EXPOSED_TAGS:
            name = el.get("name")
            if not name:
                continue
            # Absent android:exported defaults to true only when the component
            # declares an intent filter; the decoder flattens the tree, so this
            # stays conservative and reports the declared value alone.
            info.components.append(
                Component(
                    kind=el.name,
                    name=name,
                    exported=el.get_bool("exported", False),
                    permission=el.get("permission"),
                )
            )

    info.permissions = sorted(set(info.permissions))
    info.custom_permissions = sorted(set(info.custom_permissions))
