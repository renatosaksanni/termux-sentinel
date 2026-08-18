"""Behavioural risk engine.

Signature engines catch known malware. This module catches the rest: apps whose
declared capabilities, provenance, or structure are dangerous regardless of
whether anyone has seen the sample before.

Design rule: a single permission is never a verdict. Real Android malware is
identified by *combinations* -- an SMS reader that also talks to the network, an
accessibility service that can also draw over other apps. Each rule below
encodes one such combination and explains why it matters.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..apk import ApkInfo
from ..findings import Finding, Severity

P = "android.permission."

# Installers that imply a vetted distribution path. Anything else is sideloaded.
TRUSTED_INSTALLERS = {
    "com.android.vending",  # Google Play
    "com.google.android.packageinstaller",
    "com.android.packageinstaller",
    "com.sec.android.app.samsungapps",  # Galaxy Store
    "com.samsung.android.app.omcagent",
    "org.fdroid.fdroid",
    "com.amazon.venezia",
    "com.huawei.appmarket",
}

# High-value targets for overlay and accessibility theft. Weighted toward apps
# in common use in Indonesia, since that is where this tool runs.
PROTECTED_PACKAGES = {
    "com.whatsapp": "WhatsApp",
    "com.instagram.android": "Instagram",
    "com.facebook.katana": "Facebook",
    "com.google.android.gm": "Gmail",
    "com.android.vending": "Google Play",
    "com.bca": "BCA Mobile",
    "com.bca.mobile": "myBCA",
    "id.bmri.livin": "Livin by Mandiri",
    "id.co.bri.brimo": "BRImo",
    "id.co.bni.mobilebanking": "BNI Mobile",
    "com.btpn.dc": "Jenius",
    "id.dana": "DANA",
    "com.gojek.app": "Gojek",
    "ovo.id": "OVO",
    "com.shopee.id": "Shopee",
    "com.tokopedia.tkpd": "Tokopedia",
    "id.co.seabank": "SeaBank",
    "com.jago.digitalBanking": "Jago",
    "com.dbs.id.dbsdigibank": "digibank",
    "com.cimbniaga.mobile.octo": "OCTO Mobile",
}

# Permissions that meaningfully raise risk, with a short reason for the report.
SENSITIVE_PERMISSIONS = {
    P + "READ_SMS": "read SMS, including one-time passcodes",
    P + "RECEIVE_SMS": "intercept incoming SMS before you see it",
    P + "SEND_SMS": "send SMS at your cost, a common worm spreading channel",
    P + "READ_CALL_LOG": "read who you call",
    P + "RECORD_AUDIO": "record the microphone",
    P + "CAMERA": "use the camera",
    P + "ACCESS_FINE_LOCATION": "track precise location",
    P + "READ_CONTACTS": "read your address book, a worm target list",
    P + "REQUEST_INSTALL_PACKAGES": "install further APKs (dropper capability)",
    P + "SYSTEM_ALERT_WINDOW": "draw over other apps (overlay attacks)",
    P + "BIND_DEVICE_ADMIN": "act as device administrator",
    P + "QUERY_ALL_PACKAGES": "enumerate every installed app",
    P + "PACKAGE_USAGE_STATS": "see which apps you use and when",
    P + "READ_PHONE_STATE": "read device and SIM identifiers",
    P + "WRITE_SETTINGS": "change system settings",
    P + "RECEIVE_BOOT_COMPLETED": "start automatically at boot (persistence)",
    P + "FOREGROUND_SERVICE": "keep running in the background",
    P + "MANAGE_EXTERNAL_STORAGE": "read and write all shared storage",
}


@dataclass(frozen=True)
class Combo:
    """One dangerous capability combination."""

    key: str
    title: str
    severity: Severity
    permissions: frozenset[str]
    indicators: frozenset[str]  # DEX markers that must also be present
    why: str
    action: str
    require_all_indicators: bool = False


COMBOS: tuple[Combo, ...] = (
    Combo(
        key="dropper",
        title="Dropper capability: can download and install further apps",
        severity=Severity.CRITICAL,
        permissions=frozenset({P + "REQUEST_INSTALL_PACKAGES", P + "INTERNET"}),
        indicators=frozenset({"dynamic_code_loading", "package_installer"}),
        why=(
            "The app can fetch code from the network and install it. This is how "
            "a small clean-looking installer turns into banking malware after "
            "passing the store review."
        ),
        action="Uninstall unless this is a known app store or update tool.",
    ),
    Combo(
        key="sms_exfiltration",
        title="SMS interception combined with network access",
        severity=Severity.CRITICAL,
        permissions=frozenset({P + "RECEIVE_SMS", P + "INTERNET"}),
        indicators=frozenset(),
        why=(
            "One-time passcodes arrive by SMS. An app that can read incoming "
            "messages and reach the internet can forward them to an attacker "
            "and complete a bank transfer without you seeing anything."
        ),
        action="Uninstall immediately unless this is your chosen SMS app.",
    ),
    Combo(
        key="overlay_banker",
        title="Overlay plus accessibility: banking trojan pattern",
        severity=Severity.CRITICAL,
        permissions=frozenset({P + "SYSTEM_ALERT_WINDOW"}),
        indicators=frozenset({"accessibility_service"}),
        why=(
            "Drawing over other apps plus reading screen content is the exact "
            "toolkit used to paint a fake login form over a real banking app "
            "and capture the credentials typed into it."
        ),
        action="Revoke 'Display over other apps' and the accessibility service, then uninstall.",
    ),
    Combo(
        key="stalkerware",
        title="Surveillance capability set",
        severity=Severity.HIGH,
        permissions=frozenset({P + "RECORD_AUDIO", P + "ACCESS_FINE_LOCATION"}),
        # `hidden_launcher` alone is far too weak: setComponentEnabledSetting is
        # ordinary API used by any app that toggles a component, and on a real
        # device it flagged a terminal emulator and a chat client. Requiring
        # actual capture code alongside it removes that whole class of noise.
        indicators=frozenset({"hidden_launcher", "audio_record"}),
        require_all_indicators=True,
        why=(
            "Microphone access and precise location, combined with the ability "
            "to hide its own launcher icon, is the defining shape of stalkerware "
            "installed by someone with physical access to the phone."
        ),
        action="Check who installed this. Uninstall and change your passwords.",
    ),
    Combo(
        key="sms_worm",
        title="Contact list plus SMS sending: worm propagation vector",
        severity=Severity.HIGH,
        permissions=frozenset({P + "READ_CONTACTS", P + "SEND_SMS"}),
        indicators=frozenset(),
        why=(
            "An app that can read your contacts and send messages to them can "
            "spread itself, which is how SMS worms move between phones."
        ),
        action="Uninstall unless this is a messaging app you deliberately installed.",
    ),
    Combo(
        key="miner",
        title="Cryptocurrency mining code detected",
        severity=Severity.HIGH,
        permissions=frozenset(),
        indicators=frozenset({"crypto_miner"}),
        why=(
            "Mining pool protocol strings are present. On a phone this drains "
            "the battery, generates heat, and degrades the device for someone "
            "else's profit."
        ),
        action="Uninstall. Watch for battery drain and heat until it is gone.",
    ),
    Combo(
        key="chat_c2",
        title="Command and control over a public messaging API",
        severity=Severity.HIGH,
        permissions=frozenset({P + "INTERNET"}),
        indicators=frozenset({"telegram_c2"}),
        why=(
            "Hardcoded Telegram bot endpoints are a cheap, common way for "
            "malware to receive commands and exfiltrate data while blending "
            "into normal HTTPS traffic."
        ),
        action="Treat as compromised. Uninstall and review accounts used on this device.",
    ),
    Combo(
        key="admin_persistence",
        title="Device administrator with remote control capability",
        severity=Severity.HIGH,
        permissions=frozenset({P + "BIND_DEVICE_ADMIN", P + "INTERNET"}),
        indicators=frozenset({"device_admin"}),
        why=(
            "Device administrator rights make an app hard to uninstall and let "
            "it lock or wipe the device. Ransomware uses this to hold a phone "
            "hostage."
        ),
        action="Settings > Security > Device admin apps, revoke, then uninstall.",
    ),
)


# Apps whose whole purpose is installing other apps. Pinned to the signing
# certificate, so a hostile package cannot claim the name and inherit the
# exemption. Fingerprints are the SHA-256 of the signer certificate, the same
# value `apksigner verify --print-certs` reports.
TRUSTED_INSTALLER_PINS = {
    "org.fdroid.fdroid": "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab",
}


def _is_pinned_installer(info: ApkInfo) -> bool:
    pin = TRUSTED_INSTALLER_PINS.get(info.package)
    return bool(pin) and not info.signer_approximate and info.signer_sha256 == pin


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Edit distance with early exit once the cap is exceeded."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _impersonation(package: str) -> tuple[str, str] | None:
    """Detect a package name masquerading as a well-known app.

    Two shapes are caught: near-miss spellings of a real package, and names
    that borrow a trusted vendor prefix they have no right to.
    """
    if package in PROTECTED_PACKAGES:
        return None
    for real, label in PROTECTED_PACKAGES.items():
        d = _levenshtein(package, real)
        if 0 < d <= 2:
            return real, label
    if package.startswith(("com.google.android.", "com.android.", "com.samsung.android.")):
        return package, "system vendor namespace"
    return None


def evaluate(
    info: ApkInfo,
    installer: str = "",
    is_system: bool = False,
    device_sdk: int = 0,
) -> list[Finding]:
    """Score one APK and return every finding it earns.

    `installer` and `is_system` come from PackageManager when the app is
    installed; for a loose APK file on disk they are simply unknown, and the
    provenance rules below are skipped rather than guessed at.
    """
    out: list[Finding] = []
    target = info.package or info.path
    perms = set(info.permissions)
    indicators = {k for k, v in info.dex_indicators.items() if v}
    sideloaded = bool(installer) and installer not in TRUSTED_INSTALLERS

    def add(title, sev, detail, action, category="permission", **evidence):
        out.append(
            Finding(
                title=title,
                severity=sev,
                target=target,
                category=category,
                engine="heuristics",
                detail=detail,
                remediation=action,
                evidence=evidence,
            )
        )

    # System apps ship with broad permissions by design. Applying app-level
    # rules to them produces nothing but noise, so structural checks only.
    pinned_installer = _is_pinned_installer(info)
    if pinned_installer:
        add(
            "Verified app store, installer capability expected",
            Severity.INFO,
            (
                f"{info.package} matches its pinned signing certificate, so its "
                "ability to install other apps is by design rather than a dropper."
            ),
            "No action needed.",
            category="integrity",
            signer_sha256=info.signer_sha256,
        )

    if not is_system:
        for combo in COMBOS:
            if not combo.permissions <= perms:
                continue
            # An installer that proves its identity cryptographically is not a
            # dropper. Every other rule still applies to it.
            if pinned_installer and combo.key == "dropper":
                continue
            if combo.indicators:
                hit = combo.indicators & indicators
                need_all = combo.indicators <= indicators
                if not (need_all if combo.require_all_indicators else hit):
                    continue
            sev = combo.severity
            # Provenance is a real signal: the same capability set is far more
            # likely to be malicious when it did not come from a store.
            if sideloaded and sev < Severity.CRITICAL:
                sev = Severity(min(int(Severity.CRITICAL), int(sev) + 1))
            elif installer in TRUSTED_INSTALLERS and sev > Severity.LOW:
                # Store review is weak evidence, not proof, so this lowers the
                # grade rather than suppressing the finding. Without it, ordinary
                # store apps holding broad permissions drown out real detections.
                sev = Severity(int(sev) - 1)
            add(
                combo.title,
                sev,
                combo.why,
                combo.action,
                category="permission",
                rule=combo.key,
                installer=installer or "unknown",
                matched_permissions=sorted(combo.permissions & perms),
                matched_indicators=sorted(combo.indicators & indicators),
            )

    # An app targeting API < 23 predates runtime permissions: every permission
    # it declares was granted at install time with no prompt shown to you.
    if 0 < info.target_sdk < 23:
        sensitive = sorted(perms & set(SENSITIVE_PERMISSIONS))
        add(
            "Targets a pre-runtime-permission Android version",
            Severity.HIGH if sensitive else Severity.MEDIUM,
            (
                f"targetSdk {info.target_sdk} means Android grants every declared "
                "permission at install time without asking. Malware sets this "
                "deliberately to bypass the permission prompts you rely on."
            ),
            "Uninstall unless you specifically trust this app and its author.",
            category="integrity",
            target_sdk=info.target_sdk,
            auto_granted=sensitive,
        )

    if info.debuggable:
        add(
            "Application is marked debuggable",
            Severity.HIGH,
            (
                "A debuggable build lets any process with adb access attach to "
                "this app and read its memory, including credentials. Released "
                "apps are never shipped this way."
            ),
            "Uninstall. This is either a development build or a repackaged app.",
            category="integrity",
        )

    if info.shared_uid:
        sev = Severity.CRITICAL if "android.uid.system" in info.shared_uid else Severity.MEDIUM
        add(
            f"Shares a process UID: {info.shared_uid}",
            sev,
            (
                "Apps sharing a UID can read each other's private data. Claiming "
                "the system UID would grant platform-level reach."
            ),
            "Verify this app is genuinely part of the device firmware.",
            category="integrity",
            shared_uid=info.shared_uid,
        )

    # v1-only signatures are rewritable, which is how repackaged apps are made.
    if not info.has_signing_block and info.target_sdk >= 30:
        add(
            "Modern app carrying only a legacy v1 signature",
            Severity.MEDIUM,
            (
                f"targetSdk {info.target_sdk} requires v2+ signing, yet no APK "
                "Signing Block is present. Repackaging tools strip it when they "
                "re-sign a modified app."
            ),
            "Reinstall from the official store and compare the signer certificate.",
            category="integrity",
        )

    imp = _impersonation(info.package)
    if imp and sideloaded:
        real, label = imp
        add(
            f"Package name impersonates {label}",
            Severity.CRITICAL,
            (
                f"'{info.package}' closely resembles '{real}' but was installed "
                f"from {installer or 'an unknown source'} rather than an app store. "
                "Name lookalikes are how fake banking apps get onto phones."
            ),
            "Uninstall now and install the real app from the official store.",
            category="integrity",
            resembles=real,
            installer=installer or "unknown",
        )

    if sideloaded:
        risky = sorted(perms & set(SENSITIVE_PERMISSIONS))
        if len(risky) >= 4:
            add(
                "Sideloaded app holding a broad set of sensitive permissions",
                Severity.HIGH if len(risky) >= 6 else Severity.MEDIUM,
                (
                    f"Installed by '{installer}', outside any vetted store, while "
                    f"requesting {len(risky)} sensitive permissions."
                ),
                "Confirm you installed this deliberately and still need it.",
                category="permission",
                installer=installer,
                sensitive_permissions=risky,
            )

    if info.cleartext_traffic and P + "INTERNET" in perms:
        add(
            "Sends traffic over unencrypted HTTP",
            Severity.LOW,
            (
                "Cleartext traffic is explicitly enabled, so data this app sends "
                "can be read or altered on a shared or hostile network."
            ),
            "Avoid using this app on public Wi-Fi.",
            category="network",
        )

    # Unprotected exported components are reachable by any other installed app.
    unguarded = [c for c in info.exported_components if not c.permission]
    if len(unguarded) >= 5:
        add(
            f"{len(unguarded)} exported components with no permission guard",
            Severity.MEDIUM,
            (
                "Any other app on the device can invoke these entry points "
                "directly, which widens the attack surface considerably."
            ),
            "Relevant if you are auditing this app; harmless on its own for a user.",
            category="integrity",
            components=[f"{c.kind}:{c.name}" for c in unguarded[:10]],
        )

    if info.errors:
        add(
            "APK could not be fully parsed",
            Severity.MEDIUM,
            "; ".join(info.errors[:3])
            + ". Obfuscators and packers break parsers deliberately, so partial "
            "results here mean reduced confidence rather than safety.",
            "Scan this file with the signature engines before trusting it.",
            category="integrity",
            errors=info.errors[:5],
        )

    return out
