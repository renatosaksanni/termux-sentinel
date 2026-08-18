"""Device posture audit.

Malware is only half the picture. A phone with an 18-month-old security patch,
sideloading left wide open, and USB debugging enabled is exposed regardless of
what is currently installed. These checks describe that standing exposure.

Every check degrades honestly: when a property cannot be read, nothing is
reported for it rather than a reassuring "clean".
"""

from __future__ import annotations

import datetime
import os

from ..findings import Finding, Severity
from .android import Backend

# Android drops out of support roughly three years after release. Below this
# API level the device no longer receives platform security fixes at all.
SUPPORTED_SDK_FLOOR = 31  # Android 12

PATCH_WARN_DAYS = 120
PATCH_CRITICAL_DAYS = 365


def _prop(backend: Backend, name: str) -> str:
    rc, out, _ = backend.sh(["getprop", name], timeout=15)
    return out.strip() if rc == 0 else ""


def _setting(backend: Backend, namespace: str, key: str) -> str:
    rc, out, _ = backend.sh(["settings", "get", namespace, key], timeout=15)
    if rc != 0:
        return ""
    val = out.strip()
    return "" if val in ("null", "") else val


def _patch_age_days(patch: str) -> int | None:
    """ro.build.version.security_patch is YYYY-MM-DD."""
    try:
        d = datetime.date.fromisoformat(patch.strip())
    except (ValueError, AttributeError):
        return None
    return (datetime.date.today() - d).days


def audit(backend: Backend) -> list[Finding]:
    out: list[Finding] = []

    def add(title, sev, detail, action, target="device", **evidence):
        out.append(
            Finding(
                title=title,
                severity=sev,
                target=target,
                category="system",
                engine="system",
                detail=detail,
                remediation=action,
                evidence=evidence,
            )
        )

    if not backend.available:
        add(
            "Device posture could not be inspected",
            Severity.MEDIUM,
            (
                "No Android backend was available, so patch level, sideloading "
                "policy, and debugging state were never read. This scan covered "
                "files only."
            ),
            "Run this tool in native Termux, or connect adb over wireless debugging.",
        )
        return out

    patch = _prop(backend, "ro.build.version.security_patch")
    age = _patch_age_days(patch)
    if age is not None:
        if age >= PATCH_CRITICAL_DAYS:
            add(
                f"Security patches are {age} days out of date",
                Severity.HIGH,
                (
                    f"The last security patch is dated {patch}. Publicly documented "
                    "privilege escalation flaws fixed since then remain exploitable "
                    "on this device."
                ),
                "Settings > Software update. If no update exists, the device is end of life.",
                security_patch=patch,
                age_days=age,
            )
        elif age >= PATCH_WARN_DAYS:
            add(
                f"Security patches are {age} days behind",
                Severity.MEDIUM,
                f"The last security patch is dated {patch}.",
                "Settings > Software update.",
                security_patch=patch,
                age_days=age,
            )

    sdk = _prop(backend, "ro.build.version.sdk")
    if sdk.isdigit() and int(sdk) < SUPPORTED_SDK_FLOOR:
        add(
            f"Android API {sdk} no longer receives platform security updates",
            Severity.HIGH,
            (
                "This Android version is past its support window, so newly "
                "discovered vulnerabilities in the platform itself will never be "
                "fixed here."
            ),
            "Upgrade the OS if an update exists, otherwise avoid banking on this device.",
            sdk=int(sdk),
        )

    # Verified boot proves the system partition has not been altered.
    vbs = _prop(backend, "ro.boot.verifiedbootstate")
    if vbs and vbs.lower() != "green":
        add(
            f"Verified boot state is '{vbs}', not 'green'",
            Severity.HIGH,
            (
                "The bootloader reports that the system image is unlocked or "
                "modified. Anything running below the app layer, including a "
                "rootkit, would be invisible to this scanner."
            ),
            "Relock the bootloader and reflash stock firmware if you did not do this deliberately.",
            verifiedbootstate=vbs,
        )

    locked = _prop(backend, "ro.boot.flash.locked")
    if locked == "0":
        add(
            "Bootloader is unlocked",
            Severity.MEDIUM,
            (
                "An unlocked bootloader lets anyone with physical access flash a "
                "modified system, and disables hardware-backed integrity checks."
            ),
            "Relock the bootloader unless you need it unlocked for development.",
            flash_locked=locked,
        )

    if _prop(backend, "ro.debuggable") == "1":
        add(
            "System build is debuggable (ro.debuggable=1)",
            Severity.HIGH,
            "This is an engineering or userdebug build; app sandboxes are weaker than on a retail build.",
            "Flash a retail (user) firmware build.",
        )

    if _setting(backend, "global", "adb_enabled") == "1":
        add(
            "USB debugging is enabled",
            Severity.MEDIUM,
            (
                "Any computer you have authorised, and any malicious cable or "
                "adapter, can issue adb commands: install apps, read app data, "
                "and capture the screen."
            ),
            "Turn it off in Developer options when you are not actively using it.",
        )

    if _setting(backend, "global", "development_settings_enabled") == "1":
        add(
            "Developer options are enabled",
            Severity.LOW,
            "Not dangerous alone, but it unlocks settings that weaken the device.",
            "Disable Developer options if you are not using them.",
        )

    if _setting(backend, "secure", "install_non_market_apps") == "1":
        add(
            "Sideloading is allowed system-wide (legacy setting)",
            Severity.MEDIUM,
            "Apps can be installed from any source without a per-app prompt.",
            "Turn this off; grant install rights per app instead.",
        )

    # An unexpected su binary is the single strongest sign of compromise on a
    # device the owner believes is unrooted.
    su_paths = [p for p in ("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su")]
    found_su = []
    for p in su_paths:
        rc, _, _ = backend.sh(["ls", p], timeout=10)
        if rc == 0:
            found_su.append(p)
    if found_su:
        add(
            "Root binary present on the system partition",
            Severity.CRITICAL,
            (
                f"Found {', '.join(found_su)}. If you did not root this device "
                "yourself, something has gained privileges above the app sandbox "
                "and no app-level scan can be trusted."
            ),
            "If unintentional, back up your data and reflash stock firmware.",
            paths=found_su,
        )

    rc, enforce, _ = backend.sh(["getenforce"], timeout=10)
    if rc == 0 and enforce.strip().lower() == "permissive":
        add(
            "SELinux is in permissive mode",
            Severity.HIGH,
            (
                "Mandatory access control is not being enforced, so the isolation "
                "between apps is advisory only."
            ),
            "Restore an enforcing configuration by reflashing stock firmware.",
            selinux=enforce.strip(),
        )

    return out


def local_environment_audit() -> list[Finding]:
    """Checks on the Termux environment itself, which needs no Android backend."""
    out: list[Finding] = []

    # A world-writable Termux bin directory would let any process with the same
    # uid replace the tools this scanner relies on.
    prefix_bin = "/data/data/com.termux/files/usr/bin"
    try:
        mode = os.stat(prefix_bin).st_mode
        if mode & 0o002:
            out.append(
                Finding(
                    title="Termux bin directory is world writable",
                    severity=Severity.HIGH,
                    target=prefix_bin,
                    category="system",
                    engine="system",
                    detail="Any process could replace the binaries used to perform this scan.",
                    remediation=f"chmod o-w {prefix_bin}",
                )
            )
    except OSError:
        pass

    return out
