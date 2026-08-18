"""Runtime environment and capability detection.

This tool can run from two places with very different powers:

  * Termux native  -> can exec Android binaries (pm, getprop, dumpsys)
  * PRoot / chroot -> exec of /system/bin is blocked (exit 126), files only

Every other module makes decisions from the Capabilities object built here
rather than guessing. The rule: never claim to have checked something that was
never actually reachable.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field

TERMUX_PREFIX = "/data/data/com.termux/files/usr"
TERMUX_HOME = "/data/data/com.termux/files/home"

# Directories that act as entry points for files arriving from outside. These
# are the primary anti-worm targets: almost every malicious APK lands in one.
DROP_DIRS = (
    "/sdcard/Download",
    "/sdcard/Documents",
    "/sdcard/Bluetooth",
    "/sdcard/Telegram/Telegram Documents",
    "/sdcard/WhatsApp/Media/WhatsApp Documents",
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents",
    TERMUX_HOME + "/downloads",
    TERMUX_HOME + "/storage/downloads",
)


def run(cmd: list[str], timeout: int = 15, **kw) -> tuple[int, str, str]:
    """Run a command that never raises.

    Returns (returncode, stdout, stderr). Return code 126 is what Linux uses
    for "found but not executable" -- exactly what happens to /system/bin
    binaries inside PRoot.
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            **kw,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except PermissionError:
        return 126, "", "exec denied: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except OSError as exc:
        return 126, "", str(exc)


def _executable(path: str) -> bool:
    """Check that an Android binary actually runs, not merely that it exists."""
    if not os.path.exists(path):
        return False
    rc, _, _ = run([path], timeout=8)
    return rc not in (126, 127)


@dataclass
class Capabilities:
    is_termux: bool = False
    is_proot: bool = False
    uid: int = -1

    # Android binary execution
    can_exec_system: bool = False
    has_pm: bool = False
    has_getprop: bool = False
    has_dumpsys: bool = False
    # Which PackageManager entry point answered, and why the others did not.
    pm_prefix: str = ""
    pm_error: str = ""

    # The adb backend (wireless debugging) grants 'shell' user rights, the only
    # way to get full dumpsys output on a device that is not rooted.
    has_adb: bool = False
    adb_devices: list[str] = field(default_factory=list)

    # Detection engines
    has_clamscan: bool = False
    has_clamd: bool = False
    has_freshclam: bool = False
    has_yara: bool = False
    has_termux_api: bool = False

    # File access
    storage_dirs: list[str] = field(default_factory=list)

    # Device identity
    android_release: str = ""
    sdk_int: int = 0
    model: str = ""
    security_patch: str = ""

    @property
    def android_visible(self) -> bool:
        """True when we can enumerate installed applications at all."""
        return self.has_pm or bool(self.adb_devices)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["android_visible"] = self.android_visible
        return d


def _getprop(name: str) -> str:
    rc, out, _ = run(["getprop", name], timeout=6)
    return out.strip() if rc == 0 else ""


def _probe_adb() -> list[str]:
    """Serials currently in the 'device' state, i.e. ready to use."""
    rc, out, _ = run(["adb", "devices"], timeout=20)
    if rc != 0:
        return []
    serials = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


@functools.lru_cache(maxsize=1)
def detect(probe_adb: bool = True) -> Capabilities:
    """Inspect the environment once and cache the result."""
    cap = Capabilities()
    cap.uid = os.getuid()
    cap.is_termux = os.path.isdir(TERMUX_PREFIX)

    # Inside PRoot we appear as uid 0 while the real process runs as the Termux
    # app uid. "uid 0 but cannot exec /system" is a reliable PRoot fingerprint.
    cap.can_exec_system = _executable("/system/bin/sh")
    cap.is_proot = cap.uid == 0 and not cap.can_exec_system

    if cap.can_exec_system:
        cap.has_getprop = _executable("/system/bin/getprop")
        cap.has_dumpsys = shutil.which("dumpsys") is not None
        # The service can be reached through `cmd package` or the `pm` wrapper.
        # Which one works varies by build -- on Android 16 the wrapper returns a
        # binder transaction error while `cmd package` answers normally -- so
        # test actual output from each rather than trusting either to exist.
        for prefix in (["cmd", "package"], ["pm"]):
            rc, out, err = run([*prefix, "list", "packages"], timeout=30)
            if rc == 0 and "package:" in out:
                cap.has_pm = True
                cap.pm_prefix = " ".join(prefix)
                cap.pm_error = ""
                break
            detail = (err or out or f"exit {rc}").strip().splitlines()
            cap.pm_error = (cap.pm_error + "; " if cap.pm_error else "") + (
                f"{' '.join(prefix)}: {detail[0] if detail else 'no output'}"
            )

    cap.has_adb = shutil.which("adb") is not None
    if cap.has_adb and probe_adb:
        cap.adb_devices = _probe_adb()

    cap.has_clamscan = shutil.which("clamscan") is not None
    cap.has_clamd = shutil.which("clamdscan") is not None
    cap.has_freshclam = shutil.which("freshclam") is not None
    cap.has_yara = shutil.which("yara") is not None
    cap.has_termux_api = shutil.which("termux-notification") is not None

    for d in ("/sdcard", "/storage/emulated/0", TERMUX_HOME):
        if os.path.isdir(d) and os.access(d, os.R_OK):
            try:
                os.listdir(d)
            except OSError:
                continue
            cap.storage_dirs.append(d)

    if cap.has_getprop:
        cap.android_release = _getprop("ro.build.version.release")
        cap.model = _getprop("ro.product.model")
        cap.security_patch = _getprop("ro.build.version.security_patch")
        sdk = _getprop("ro.build.version.sdk")
        cap.sdk_int = int(sdk) if sdk.isdigit() else 0

    return cap
