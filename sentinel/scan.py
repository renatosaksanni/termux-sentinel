"""Scan orchestration: the layer that runs every engine and merges the results.

Each engine sees the same targets and contributes findings independently, so a
file flagged by ClamAV and also structurally suspicious produces two findings
rather than one blended verdict. Deduplication happens on fingerprint, not on
target, which keeps distinct reasons distinct.
"""

from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field

from . import apk as apk_mod
from .config import Config
from .engines import clamav, hashdb, heuristics, yara_engine
from .findings import Finding, FindingSet, Severity
from .scanners import android, files, system

# Signature engines load their database once per invocation, so files are sent
# in size-bounded batches rather than one at a time.
BATCH_BYTES = 192 * 1024 * 1024

APK_EXTS = (".apk", ".apks", ".xapk", ".aab")


def _looks_like_apk(path: str) -> bool:
    return path.lower().endswith(APK_EXTS)


@dataclass
class ScanStats:
    files_seen: int = 0
    apks_analysed: int = 0
    packages_seen: int = 0
    bytes_scanned: int = 0
    engines_used: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started


class Scanner:
    """Holds engine state that is expensive to build, so it is built once."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.stats = ScanStats()
        self.known_bad = hashdb.load_known_bad()
        self.vt = hashdb.VirusTotal(cfg)
        self._yara_bundle: str | None = None
        self._yara_note = ""

        if cfg.use_yara and yara_engine.available():
            self._yara_bundle, self._yara_note = yara_engine.compile_rules()
            self.stats.engines_used.append("yara")
        if cfg.use_clamav and clamav.db_present(cfg):
            self.stats.engines_used.append("clamav")
        if cfg.use_heuristics:
            self.stats.engines_used.append("heuristics")
        if self.vt.enabled:
            self.stats.engines_used.append("virustotal")
        if self._yara_note:
            self.stats.notes.append(f"yara: {self._yara_note}")

    def close(self) -> None:
        self.vt.save_cache()
        if self._yara_bundle:
            try:
                os.unlink(self._yara_bundle)
            except OSError:
                pass

    # ---------------------------------------------------------------- engines

    def _signature_pass(self, paths: list[str], sizes: dict[str, int]) -> list[Finding]:
        """Run ClamAV and YARA over a set of paths."""
        out: list[Finding] = []
        if not paths:
            return out
        for batch in files.batched(paths, BATCH_BYTES, sizes):
            if self.cfg.use_clamav:
                out.extend(clamav.scan_files(self.cfg, batch))
            if self.cfg.use_yara:
                out.extend(yara_engine.scan_files(batch, compiled=self._yara_bundle))
        if self.cfg.use_yara:
            out.extend(self._yara_inner_pass([p for p in paths if _looks_like_apk(p)]))
        return out

    def _yara_inner_pass(self, apk_paths: list[str]) -> list[Finding]:
        """Match YARA rules against DEX extracted from APKs.

        Without this step every DEX-targeted rule silently matches nothing,
        because the bytecode is compressed inside the archive. Findings are
        re-pointed at the APK, since that is the thing the user can act on.
        """
        if not apk_paths or not yara_engine.available():
            return []
        out: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="sentinel-dex-") as tmp:
            origin: dict[str, str] = {}
            for apk in apk_paths:
                for dex in apk_mod.extract_dex(apk, tmp):
                    origin[dex] = apk
            if not origin:
                return []
            for f in yara_engine.scan_files(list(origin), compiled=self._yara_bundle):
                src = origin.get(f.target)
                if src:
                    f.evidence = dict(f.evidence, matched_in=os.path.basename(f.target))
                    f.target = src
                out.append(f)
        return out

    def _reputation_pass(self, path: str, sha256: str) -> list[Finding]:
        out = []
        local = hashdb.check_local(sha256, path, self.known_bad)
        if local:
            out.append(local)
        remote = self.vt.lookup(sha256, path)
        if remote:
            out.append(remote)
        return out

    # ------------------------------------------------------------ file scans

    def scan_file(self, path: str) -> list[Finding]:
        """Scan a single file with every engine. Used by the watcher."""
        out: list[Finding] = []
        try:
            size = os.path.getsize(path)
        except OSError:
            return out
        if size == 0 or size > self.cfg.max_file_bytes:
            return out

        sizes = {path: size}
        out.extend(self._signature_pass([path], sizes))

        is_apk = path.lower().endswith((".apk", ".apks", ".xapk"))
        if not is_apk:
            try:
                with open(path, "rb") as fh:
                    is_apk = fh.read(4) == b"PK\x03\x04" and path.lower().endswith(".zip") is False
            except OSError:
                is_apk = False

        if is_apk:
            info = apk_mod.analyze(path, deep=True)
            self.stats.apks_analysed += 1
            if info.package:
                # A loose APK file has no installer; provenance rules are skipped.
                out.extend(heuristics.evaluate(info, installer="", is_system=False))
                out.extend(self._reputation_pass(path, info.sha256))
                out.append(
                    Finding(
                        title=f"APK file present: {info.package}",
                        severity=Severity.INFO,
                        target=path,
                        category="integrity",
                        engine="heuristics",
                        detail=(
                            f"{info.package} {info.version_name}, targetSdk "
                            f"{info.target_sdk}, {len(info.permissions)} permissions."
                        ),
                        remediation="Only install this if you know exactly where it came from.",
                        evidence={"sha256": info.sha256, "signer": info.signer_sha256[:32]},
                    )
                )
        elif self.known_bad or self.vt.enabled:
            try:
                out.extend(self._reputation_pass(path, apk_mod.sha256_file(path)))
            except OSError:
                pass

        self.stats.files_seen += 1
        self.stats.bytes_scanned += size
        return out

    def scan_paths(
        self,
        paths: list[str] | None = None,
        recent_hours: float = 0.0,
        on_progress=None,
        on_walk=None,
    ) -> FindingSet:
        """Walk the filesystem and scan every candidate found."""
        result = FindingSet()
        candidates = files.walk(
            self.cfg, paths, recent_hours=recent_hours, on_progress=on_walk
        )
        self.stats.files_seen += len(candidates)
        self.stats.bytes_scanned += sum(c.size for c in candidates)

        if not candidates:
            return result

        sizes = {c.path: c.size for c in candidates}
        all_paths = [c.path for c in candidates]

        if on_progress:
            on_progress(0, len(all_paths), "signature engines")
        result.extend(self._signature_pass(all_paths, sizes))

        apks = [c for c in candidates if c.is_apk]
        for i, cand in enumerate(apks):
            if on_progress:
                on_progress(i, len(apks), os.path.basename(cand.path))
            info = apk_mod.analyze(cand.path, deep=True)
            self.stats.apks_analysed += 1
            if not info.package and not info.errors:
                continue
            result.extend(heuristics.evaluate(info, installer="", is_system=False))
            result.extend(self._reputation_pass(cand.path, info.sha256))

        # Non-APK files still get a reputation check when there is a list to
        # check against; without one this would be pure wasted hashing.
        if self.known_bad or self.vt.enabled:
            for cand in candidates:
                if cand.is_apk:
                    continue
                try:
                    result.extend(self._reputation_pass(cand.path, apk_mod.sha256_file(cand.path)))
                except OSError:
                    continue

        return result

    # ------------------------------------------------------- installed apps

    def scan_installed(self, backend: android.Backend, on_progress=None) -> FindingSet:
        """Audit every installed application."""
        result = FindingSet()
        if not backend.available:
            result.add(
                Finding(
                    title="Installed applications could not be enumerated",
                    severity=Severity.HIGH,
                    target="PackageManager",
                    category="integrity",
                    engine="heuristics",
                    detail=(
                        "No Android backend was available, so no installed app was "
                        "examined. This scan says nothing about the apps on this device."
                    ),
                    remediation=(
                        "Run inside native Termux, or enable wireless debugging and "
                        "connect adb, then rerun."
                    ),
                )
            )
            return result

        packages = android.list_packages(backend, third_party_only=True)
        self.stats.packages_seen = len(packages)

        # Android 11+ filters which packages an app may even see. Under the
        # direct backend the list is therefore the apps visible to Termux, not
        # the apps installed. Reporting a handful as though it were the whole
        # device would be the exact false assurance this tool exists to avoid.
        if backend.name == "direct" and 0 < len(packages) <= 10:
            result.add(
                Finding(
                    title=f"Only {len(packages)} apps are visible to this scanner",
                    severity=Severity.HIGH,
                    target="PackageManager",
                    category="integrity",
                    engine="heuristics",
                    detail=(
                        "Android package visibility filtering restricts what a normal "
                        "app may enumerate, so this scan covered only the apps Termux "
                        "is permitted to see. The rest of the device was not examined."
                    ),
                    remediation=(
                        "Enable wireless debugging and rerun with --backend adb, which "
                        "runs as the shell user and sees every installed package."
                    ),
                    evidence={"visible": [p.package for p in packages]},
                )
            )
        if not packages:
            result.add(
                Finding(
                    title="PackageManager returned no third-party applications",
                    severity=Severity.MEDIUM,
                    target="PackageManager",
                    category="integrity",
                    engine="heuristics",
                    detail="The query succeeded but listed nothing, which is unusual.",
                    remediation="Check `pm list packages -3` manually.",
                )
            )
            return result

        temp_files: list[str] = []
        readable_apks: dict[str, int] = {}

        try:
            for i, pkg in enumerate(packages):
                if on_progress:
                    on_progress(i, len(packages), pkg.package)

                android.enrich_from_dumpsys(backend, pkg)
                path, note = android.pull_apk(backend, pkg)
                if path is None:
                    result.add(
                        Finding(
                            title=f"APK not readable: {pkg.package}",
                            severity=Severity.LOW,
                            target=pkg.package,
                            category="integrity",
                            engine="heuristics",
                            detail=(
                                f"{note}. This app was listed but its contents could "
                                "not be examined, so it was not actually scanned."
                            ),
                            remediation="Connect adb over wireless debugging for wider read access.",
                            evidence={"apk_path": pkg.apk_path, "backend": backend.name},
                        )
                    )
                    continue

                if path != pkg.apk_path:
                    temp_files.append(path)

                info = apk_mod.analyze(path, deep=True)
                self.stats.apks_analysed += 1
                result.extend(
                    heuristics.evaluate(
                        info, installer=pkg.installer, is_system=pkg.is_system
                    )
                )
                result.extend(self._reputation_pass(pkg.package, info.sha256))

                try:
                    readable_apks[path] = os.path.getsize(path)
                except OSError:
                    pass

            if readable_apks:
                if on_progress:
                    on_progress(len(packages), len(packages), "signature engines")
                sig = self._signature_pass(list(readable_apks), readable_apks)
                # Rewrite temp paths back to package names so the report names
                # something the user can act on.
                by_path = {
                    p: pkg.package
                    for pkg in packages
                    for p in ([pkg.apk_path] if pkg.apk_path else [])
                }
                for f in sig:
                    f.target = by_path.get(f.target, f.target)
                result.extend(sig)
        finally:
            for t in temp_files:
                try:
                    os.unlink(t)
                except OSError:
                    pass

        return result


def full_scan(cfg: Config, backend: android.Backend, on_progress=None) -> tuple[FindingSet, ScanStats]:
    """Everything: device posture, installed apps, then the filesystem."""
    scanner = Scanner(cfg)
    result = FindingSet()
    try:
        result.extend(system.audit(backend))
        result.extend(system.local_environment_audit())
        result.extend(scanner.scan_installed(backend, on_progress=on_progress).items)
        result.extend(scanner.scan_paths(on_progress=on_progress).items)
    finally:
        scanner.close()
    result.suppress(cfg.suppressed)
    return result, scanner.stats
