"""PackageManager access, with two interchangeable backends.

  direct : query PackageManager as the Termux app uid. Two entry points exist,
           `cmd package` and the `pm` wrapper; which one works varies by build,
           so both are probed and whichever answers is used.
  adb    : run through `adb shell` over wireless debugging, which executes as
           the `shell` user. This is the only way to reach full `dumpsys`
           output on a device that is not rooted.

Neither backend requires root. The scanner picks the richest one available and
records which was used, so a report always states how much was actually visible.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from ..env import run

# `pm list packages -f -u` -> package:/data/app/~~a==/com.foo-1/base.apk=com.foo
# The APK path itself can contain '=', so the package name is split from the
# right, where exactly one separator can appear.
_PKG_LINE = re.compile(r"^package:(?P<path>.+)=(?P<pkg>[A-Za-z][A-Za-z0-9_.]*)$")
_INSTALLER_LINE = re.compile(r"^package:(?P<pkg>\S+)\s+installer=(?P<installer>\S+)$")


@dataclass
class InstalledPackage:
    package: str
    apk_path: str = ""
    installer: str = ""
    is_system: bool = False
    first_install: int = 0  # epoch millis, 0 when unknown
    last_update: int = 0
    version_name: str = ""
    granted_permissions: list[str] = field(default_factory=list)
    readable: bool = False


class Backend:
    """A way to execute shell commands in the Android context."""

    name = "none"
    available = False
    # Entry point that answers for PackageManager queries, resolved at probe
    # time. Kept on the instance so callers never hardcode `pm`.
    pm_prefix: list[str] = ["pm"]
    # Why the backend is unavailable, surfaced to the user instead of discarded.
    last_error: str = ""

    def sh(self, argv: list[str], timeout: int = 60) -> tuple[int, str, str]:
        raise NotImplementedError

    def read_file(self, remote_path: str, dest: str) -> bool:
        raise NotImplementedError

    def pm(self, *args: str) -> list[str]:
        """Build a package-manager command using whichever entry point works."""
        return [*self.pm_prefix, *args]


# Two ways to reach the same PackageManager service. `pm` is a shell wrapper
# around `cmd package`; on some builds (observed on Android 16) the wrapper
# fails with a binder transaction error while `cmd package` succeeds. Probing
# both and keeping the one that answers avoids depending on either.
PM_CANDIDATES: tuple[list[str], ...] = (["cmd", "package"], ["pm"])


def _probe_pm(runner) -> tuple[list[str], str]:
    """Return (working prefix, error text). An empty prefix means none worked."""
    errors = []
    for prefix in PM_CANDIDATES:
        rc, out, err = runner([*prefix, "list", "packages"], 30)
        if rc == 0 and "package:" in out:
            return list(prefix), ""
        detail = (err or out or f"exit {rc}").strip().splitlines()
        errors.append(f"{' '.join(prefix)}: {detail[0] if detail else 'no output'}")
    return [], "; ".join(errors)


class DirectBackend(Backend):
    """Run Android binaries directly. Native Termux only."""

    name = "direct"

    def __init__(self) -> None:
        self.pm_prefix, self.last_error = _probe_pm(
            lambda argv, timeout: run(argv, timeout=timeout)
        )
        self.available = bool(self.pm_prefix)

    def sh(self, argv: list[str], timeout: int = 60) -> tuple[int, str, str]:
        return run(argv, timeout=timeout)

    def read_file(self, remote_path: str, dest: str) -> bool:
        """Direct read. Works when the APK is world readable, as most are."""
        try:
            shutil.copyfile(remote_path, dest)
            return True
        except (OSError, shutil.Error):
            return False


class AdbBackend(Backend):
    """Run through adb, gaining the shell user's much wider read access."""

    name = "adb"

    def __init__(self, serial: str = "") -> None:
        self.serial = serial
        self.available = False
        if not shutil.which("adb"):
            self.last_error = "adb is not installed"
            return
        rc, out, err = self.sh(["id"], timeout=20)
        if rc != 0 or "uid=" not in out:
            self.last_error = (err or out or f"exit {rc}").strip().splitlines()[:1] or ["no device"]
            self.last_error = self.last_error[0]
            return
        # The same wrapper failure can occur under adb, so probe here too.
        self.pm_prefix, probe_err = _probe_pm(lambda argv, timeout: self.sh(argv, timeout))
        self.available = bool(self.pm_prefix)
        if not self.available:
            self.last_error = probe_err

    def _prefix(self) -> list[str]:
        return ["adb"] + (["-s", self.serial] if self.serial else [])

    def sh(self, argv: list[str], timeout: int = 60) -> tuple[int, str, str]:
        # Quote each argument so paths containing spaces survive the remote shell.
        remote = " ".join(_shq(a) for a in argv)
        return run(self._prefix() + ["shell", remote], timeout=timeout)

    def read_file(self, remote_path: str, dest: str) -> bool:
        """Stream a file out via exec-out, which keeps the bytes binary clean."""
        try:
            with open(dest, "wb") as fh:
                p = subprocess.run(
                    self._prefix() + ["exec-out", "cat", _shq(remote_path)],
                    stdout=fh,
                    stderr=subprocess.DEVNULL,
                    timeout=600,
                )
            return p.returncode == 0 and os.path.getsize(dest) > 0
        except (OSError, subprocess.SubprocessError):
            return False


def _shq(s: str) -> str:
    """Quote for a remote sh -c context."""
    return "'" + s.replace("'", "'\\''") + "'"


def select_backend(prefer: str = "auto") -> Backend:
    """Choose a backend. 'auto' prefers adb for its wider visibility."""
    if prefer in ("auto", "adb"):
        adb = AdbBackend()
        if adb.available:
            return adb
        if prefer == "adb":
            return adb  # unavailable, but the caller asked for it explicitly
    if prefer in ("auto", "direct"):
        direct = DirectBackend()
        if direct.available:
            return direct
        return direct
    return Backend()


def list_packages(backend: Backend, third_party_only: bool = True) -> list[InstalledPackage]:
    """Enumerate installed applications with paths, installers, and flags."""
    if not backend.available:
        return []

    packages: dict[str, InstalledPackage] = {}

    args = backend.pm("list", "packages", "-f", "-u")
    if third_party_only:
        args.append("-3")
    rc, out, _ = backend.sh(args, timeout=120)
    if rc != 0:
        return []

    for line in out.splitlines():
        m = _PKG_LINE.match(line.strip())
        if not m:
            continue
        pkg = m.group("pkg")
        packages[pkg] = InstalledPackage(package=pkg, apk_path=m.group("path"))

    # System packages are marked rather than dropped: the heuristics engine
    # needs to know, and a compromised system app still matters.
    rc, out, _ = backend.sh(backend.pm("list", "packages", "-s"), timeout=120)
    if rc == 0:
        system = {l.strip()[8:] for l in out.splitlines() if l.startswith("package:")}
        for pkg, rec in packages.items():
            rec.is_system = pkg in system

    rc, out, _ = backend.sh(backend.pm("list", "packages", "-i"), timeout=120)
    if rc == 0:
        for line in out.splitlines():
            m = _INSTALLER_LINE.match(line.strip())
            if m and m.group("pkg") in packages:
                inst = m.group("installer")
                packages[m.group("pkg")].installer = "" if inst == "null" else inst

    for rec in packages.values():
        rec.readable = bool(rec.apk_path) and os.access(rec.apk_path, os.R_OK)

    return sorted(packages.values(), key=lambda p: p.package)


_TIME_RE = re.compile(r"(firstInstallTime|lastUpdateTime)=(\S+ \S+)")
_VERSION_RE = re.compile(r"versionName=(\S+)")


def enrich_from_dumpsys(backend: Backend, pkg: InstalledPackage) -> None:
    """Add install timestamps, version, and granted permissions when possible.

    `dumpsys package` needs the DUMP permission, which a plain app does not
    hold. Under the direct backend this usually returns nothing, and that is
    reported as reduced coverage rather than treated as a clean result.
    """
    rc, out, _ = backend.sh(["dumpsys", "package", pkg.package], timeout=45)
    if rc != 0 or not out.strip():
        return

    m = _VERSION_RE.search(out)
    if m:
        pkg.version_name = m.group(1)

    granted = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("android.permission.") and "granted=true" in line:
            granted.append(line.split(":")[0].strip())
    pkg.granted_permissions = sorted(set(granted))


def pull_apk(backend: Backend, pkg: InstalledPackage) -> tuple[str | None, str]:
    """Make the APK readable locally, copying it out only when necessary.

    Returns (path, note). When the APK is already readable in place, its own
    path is returned and nothing is copied -- important on a phone, where the
    installed app corpus can run to several gigabytes.
    """
    if not pkg.apk_path:
        return None, "no APK path reported"
    if pkg.readable:
        return pkg.apk_path, "read in place"

    fd, tmp = tempfile.mkstemp(prefix="sentinel-", suffix=".apk")
    os.close(fd)
    if backend.read_file(pkg.apk_path, tmp):
        return tmp, f"copied via {backend.name}"
    try:
        os.unlink(tmp)
    except OSError:
        pass
    return None, "unreadable: the platform denies access to this APK"
