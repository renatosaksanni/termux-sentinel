"""Command line interface.

Verbose by default: a scan prints what it is doing, which engine is running,
and every finding at the moment it is produced. `--quiet` reduces this to
findings and the summary; `--debug` adds per-file tracing and raw evidence.

Exit codes are meaningful, so this composes with cron and shell scripts:
  0  clean
  1  medium findings
  2  high or critical findings
  3  the scan could not run
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__, config as config_mod
from .config import Config
from .engines import clamav, yara_engine
from .env import detect
from .findings import FindingSet, Severity
from .quarantine import Quarantine
from .scan import Scanner, full_scan
from .scanners import android, system
from .ui import C, Console, header, info, kv, paint, rule, section, set_color, success, warn, error

EXIT_CLEAN, EXIT_MEDIUM, EXIT_HIGH, EXIT_ERROR = 0, 1, 2, 3


# --------------------------------------------------------------------- banner


def show_environment(con: Console, cfg: Config, backend: android.Backend) -> None:
    """Print exactly what this run can and cannot see, before it starts."""
    cap = detect()
    section("Environment")
    where = "Termux (native)" if cap.can_exec_system else "PRoot / chroot"
    kv("runtime", where, ok=cap.can_exec_system)

    if cap.model or cap.android_release:
        kv("device", f"{cap.model or 'unknown'} · Android {cap.android_release or '?'} (API {cap.sdk_int or '?'})")
    if cap.security_patch:
        kv("security patch", cap.security_patch)

    kv(
        "android backend",
        f"{backend.name} ({'available' if backend.available else 'unavailable'})",
        ok=backend.available,
    )
    if backend.available and backend.pm_prefix:
        kv("package query", " ".join(backend.pm_prefix), ok=True)
    if not backend.available:
        warn("Installed apps cannot be enumerated. File scanning still works.")
        if backend.last_error:
            # The actual refusal is far more useful than a generic message: it
            # distinguishes a blocked wrapper from a missing device.
            info(f"reason: {backend.last_error}")
        info("Fix: run inside native Termux, or enable wireless debugging and pair adb.")

    db_age = clamav.db_age_days(cfg)
    con.engine(
        "clamav",
        f"database {db_age:.1f} days old" if db_age is not None else "no signature database",
        ok=cfg.use_clamav and db_age is not None,
    )
    con.engine(
        "yara",
        f"{len(yara_engine.rule_files())} rule files",
        ok=cfg.use_yara and yara_engine.available(),
    )
    con.engine("heuristics", "permission and structure rules", ok=cfg.use_heuristics)
    con.engine(
        "virustotal",
        "enabled" if cfg.virustotal_enabled else "disabled (no API key)",
        ok=True if cfg.virustotal_enabled else None,
    )
    kv("storage visible", ", ".join(cap.storage_dirs) or "none", ok=bool(cap.storage_dirs))


# --------------------------------------------------------------------- doctor


def cmd_doctor(args, cfg: Config) -> int:
    cap = detect()
    header(f"Termux Sentinel {__version__}", "environment and capability report")

    section("Runtime")
    kv("uid", str(cap.uid))
    kv("termux prefix", "present" if cap.is_termux else "absent", ok=cap.is_termux)
    kv("inside proot", "yes" if cap.is_proot else "no", ok=not cap.is_proot)
    kv("can exec /system", "yes" if cap.can_exec_system else "no", ok=cap.can_exec_system)

    section("Android access")
    kv(
        "package query",
        f"working via `{cap.pm_prefix}`" if cap.has_pm else "unavailable",
        ok=cap.has_pm,
    )
    if cap.pm_error:
        info(f"probe: {cap.pm_error}")
    kv("getprop", "working" if cap.has_getprop else "unavailable", ok=cap.has_getprop)
    kv("dumpsys binary", "present" if cap.has_dumpsys else "absent", ok=cap.has_dumpsys)
    kv("adb", "installed" if cap.has_adb else "not installed", ok=cap.has_adb)
    kv("adb devices", ", ".join(cap.adb_devices) or "none connected", ok=bool(cap.adb_devices))

    section("Engines")
    kv("clamscan", "installed" if cap.has_clamscan else "missing", ok=cap.has_clamscan)
    kv("freshclam", "installed" if cap.has_freshclam else "missing", ok=cap.has_freshclam)
    age = clamav.db_age_days(cfg)
    kv(
        "clamav database",
        f"{age:.1f} days old" if age is not None else "not downloaded",
        ok=age is not None and age < 7,
    )
    kv("yara", "installed" if cap.has_yara else "missing", ok=cap.has_yara)
    kv("yara rules", f"{len(yara_engine.rule_files())} files", ok=bool(yara_engine.rule_files()))
    kv("termux-api", "installed" if cap.has_termux_api else "missing (no notifications)", ok=cap.has_termux_api)

    section("Device")
    kv("model", cap.model or "unknown")
    kv("android", f"{cap.android_release or '?'} (API {cap.sdk_int or '?'})")
    kv("security patch", cap.security_patch or "unknown")
    kv("storage readable", ", ".join(cap.storage_dirs) or "none", ok=bool(cap.storage_dirs))

    section("Verdict")
    problems = []
    if not cap.can_exec_system:
        problems.append("Running inside PRoot: installed apps and device posture are invisible.")
    if not cap.android_visible:
        problems.append("No way to list installed apps: run in Termux or connect adb.")
    if not cap.has_clamscan:
        problems.append("ClamAV missing: pkg install clamav")
    if cap.has_clamscan and age is None:
        problems.append("No signature database: sentinel update")
    if not cap.has_yara:
        problems.append("YARA missing: pkg install yara")
    if not cap.storage_dirs:
        problems.append("No readable storage: run termux-setup-storage")

    if problems:
        for p in problems:
            warn(p)
        print()
        return EXIT_MEDIUM
    success("Fully operational: app enumeration, signature engines, and storage access all working.")
    print()
    return EXIT_CLEAN


# ----------------------------------------------------------------------- scan


def _emit(con: Console, result: FindingSet, args, min_sev: Severity) -> None:
    shown = [f for f in result.items if f.severity >= min_sev]
    if not shown:
        return
    section(f"Findings ({len(shown)})")
    for f in shown:
        con.finding(f)
        print()


def cmd_scan(args, cfg: Config) -> int:
    con = Console(verbose=not args.quiet, debug=args.debug)
    min_sev = Severity.parse(args.min_severity)

    scope_apps = args.apps or args.full or not (args.files or args.path)
    scope_files = args.files or args.full or bool(args.path)
    if args.path:
        scope_apps = args.apps

    header(
        f"Termux Sentinel {__version__}",
        "scanning: " + ", ".join(filter(None, ["installed apps" if scope_apps else "", "filesystem" if scope_files else ""])),
    )

    backend = android.select_backend(args.backend)
    show_environment(con, cfg, backend)

    total_phases = 1 + int(scope_apps) + int(scope_files)
    phase = 0
    result = FindingSet()
    seen_fp: set[str] = set()

    def stream(new_findings) -> None:
        """Print findings as they arrive, without repeating any."""
        for f in new_findings:
            if f.fingerprint in seen_fp:
                continue
            seen_fp.add(f.fingerprint)
            result.add(f)
            if f.severity >= min_sev and not args.json:
                con.finding(f)

    scanner = Scanner(cfg)
    t_start = time.time()
    try:
        phase += 1
        con.phase(phase, total_phases, "Device posture")
        con.step("reading system properties and security settings")
        stream(system.audit(backend))
        stream(system.local_environment_audit())
        con.step("posture check complete")

        if scope_apps:
            phase += 1
            con.phase(phase, total_phases, "Installed applications")

            def app_progress(i, total, name):
                con.detail(f"analysing {name}")
                con.counter(i + 1, total, "apps")

            con.step("enumerating packages via PackageManager")
            stream(scanner.scan_installed(backend, on_progress=app_progress).items)
            con.step(f"{scanner.stats.packages_seen} packages examined, {scanner.stats.apks_analysed} APKs parsed")

        if scope_files:
            phase += 1
            con.phase(phase, total_phases, "Filesystem")
            paths = args.path or cfg.scan_paths
            con.step("walking: " + ", ".join(paths))

            def file_progress(i, total, name):
                con.detail(f"scanning {name}")
                con.counter(i + 1, total, "files")

            def walk_progress(dirs, found, current):
                # Traversing shared storage takes minutes on a phone. Reporting
                # throughout is what separates "working" from "hung".
                con.detail(f"entering {current}")
                con.walking(dirs, found, current)

            stream(
                scanner.scan_paths(
                    paths=list(paths) if args.path else None,
                    recent_hours=args.recent or 0.0,
                    on_progress=file_progress,
                    on_walk=walk_progress,
                ).items
            )
            con.step(f"{scanner.stats.files_seen} candidate files inspected")

        result.suppress(cfg.suppressed)
        stats = scanner.stats
    finally:
        scanner.close()

    elapsed = time.time() - t_start

    if args.json:
        meta = {
            "version": __version__,
            "backend": backend.name,
            "engines": stats.engines_used,
            "packages_seen": stats.packages_seen,
            "files_seen": stats.files_seen,
            "elapsed_seconds": round(elapsed, 2),
        }
        payload = result.to_json(meta=meta)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(payload)
            success(f"report written to {args.output}")
        else:
            print(payload)
        return result.exit_code()

    print()
    print(rule())
    counts = result.counts()
    section("Summary")
    for sev in reversed(list(Severity)):
        n = counts.get(sev.label, 0)
        if n:
            kv(sev.label.lower(), str(n))
    kv("packages examined", str(stats.packages_seen))
    kv("files inspected", str(stats.files_seen))
    kv("apks parsed", str(stats.apks_analysed))
    kv("engines used", ", ".join(stats.engines_used) or "none")
    kv("elapsed", f"{elapsed:.1f}s")

    for note in stats.notes:
        info(note)

    if result.worst >= Severity.HIGH:
        print()
        error("Action required: high severity findings above.")
    elif len(result) == 0:
        print()
        success("No findings.")
    print()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(result.to_json(meta={"version": __version__, "backend": backend.name}))
        success(f"JSON report written to {args.output}")

    return result.exit_code()


# ---------------------------------------------------------------------- watch


def cmd_watch(args, cfg: Config) -> int:
    from .watch.daemon import Watcher

    con = Console(verbose=not args.quiet, debug=args.debug)
    header(f"Termux Sentinel {__version__}", "real-time drop watcher")

    watcher = Watcher(cfg, on_finding=lambda f: con.finding(f))
    try:
        watched = watcher.start()
    except OSError as exc:
        error(f"could not start inotify: {exc}")
        return EXIT_ERROR

    section("Coverage")
    for w in watched:
        kv("watching", w, ok=True)
    if not watched:
        error("No watchable directories. Run termux-setup-storage first.")
        return EXIT_ERROR
    warn("Directories inside other apps' private storage are not visible and are not covered.")

    if args.catch_up:
        section(f"Catch-up scan (last {args.catch_up}h)")
        for f in watcher.catch_up(args.catch_up):
            con.finding(f)

    section("Watching")
    info("Press Ctrl-C to stop.")
    try:
        watcher.run(once=args.once)
    except KeyboardInterrupt:
        print()
    finally:
        s = watcher.stats
        watcher.close()
        section("Session")
        kv("events", str(s.events))
        kv("files scanned", str(s.scanned))
        kv("detections", str(s.detections))
        kv("quarantined", str(s.quarantined))
        kv("uptime", f"{time.time() - s.started:.0f}s")
        print()
    return EXIT_CLEAN


# --------------------------------------------------------------------- update


def cmd_update(args, cfg: Config) -> int:
    con = Console(verbose=not args.quiet, debug=args.debug)
    header(f"Termux Sentinel {__version__}", "signature database update")
    config_mod.ensure_dirs(cfg)

    section("ClamAV")
    age = clamav.db_age_days(cfg)
    kv("current database", f"{age:.1f} days old" if age is not None else "not present")
    con.step("running freshclam (first run downloads roughly 250 MB)")
    ok, msg = clamav.update_db(cfg, quiet=args.quiet)
    if ok:
        success(f"signatures ready: {msg}")
    else:
        error(f"update failed: {msg}")

    section("YARA")
    bundle, note = yara_engine.compile_rules()
    if bundle:
        success(note)
        os.unlink(bundle)
    else:
        warn(note)

    print()
    return EXIT_CLEAN if ok else EXIT_MEDIUM


# ----------------------------------------------------------------- quarantine


def cmd_quarantine(args, cfg: Config) -> int:
    config_mod.ensure_dirs(cfg)
    q = Quarantine(cfg)
    header(f"Termux Sentinel {__version__}", "quarantine store")

    if args.action == "list":
        entries = q.list()
        if not entries:
            info("Quarantine is empty.")
            return EXIT_CLEAN
        section(f"{len(entries)} quarantined files")
        for e in entries:
            print(f"  {paint(e.id, C.BOLD)}  {paint(e.severity, C.YELLOW)}")
            kv("original", e.original_path)
            kv("reason", e.reason)
            kv("sha256", e.sha256[:32] + "…")
            kv("size", f"{e.size / 1024:.1f} KiB")
            print()
        return EXIT_CLEAN

    if not args.id:
        error(f"'{args.action}' needs an entry id. Run: sentinel quarantine list")
        return EXIT_ERROR

    if args.action == "restore":
        ok, msg = q.restore(args.id, args.to)
        (success if ok else error)(f"restored to {msg}" if ok else msg)
        return EXIT_CLEAN if ok else EXIT_ERROR

    ok, msg = q.delete(args.id)
    (success if ok else error)(f"deleted {msg}" if ok else msg)
    return EXIT_CLEAN if ok else EXIT_ERROR


# --------------------------------------------------------------------- config


def cmd_config(args, cfg: Config) -> int:
    header(f"Termux Sentinel {__version__}", "configuration")
    if args.action == "init":
        config_mod.ensure_dirs(cfg)
        if os.path.exists(config_mod.CONFIG_FILE) and not args.force:
            warn(f"{config_mod.CONFIG_FILE} already exists. Use --force to overwrite.")
            return EXIT_MEDIUM
        with open(config_mod.CONFIG_FILE, "w", encoding="utf-8") as fh:
            fh.write(config_mod.SAMPLE_CONFIG)
        os.chmod(config_mod.CONFIG_FILE, 0o600)
        success(f"wrote {config_mod.CONFIG_FILE}")
        return EXIT_CLEAN

    section("Effective configuration")
    kv("config file", config_mod.CONFIG_FILE if os.path.exists(config_mod.CONFIG_FILE) else "(defaults, no file)")
    kv("scan paths", ", ".join(cfg.scan_paths))
    kv("watch paths", f"{len(cfg.watch_paths)} directories")
    kv("max file size", f"{cfg.max_file_mb} MB")
    kv("clamav", "on" if cfg.use_clamav else "off")
    kv("yara", "on" if cfg.use_yara else "off")
    kv("heuristics", "on" if cfg.use_heuristics else "off")
    kv("auto quarantine", "on" if cfg.auto_quarantine else "off")
    kv("virustotal", "enabled" if cfg.virustotal_enabled else "disabled")
    kv("quarantine dir", cfg.quarantine_dir)
    print()
    return EXIT_CLEAN


# ------------------------------------------------------------------ argparser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Android malware and device posture scanner for the terminal.",
        epilog="Exit codes: 0 clean, 1 medium findings, 2 high or critical, 3 error.",
    )
    p.add_argument("--version", action="version", version=f"termux-sentinel {__version__}")
    p.add_argument("-q", "--quiet", action="store_true", help="only print findings and the summary")
    p.add_argument("--debug", action="store_true", help="per-file tracing and raw evidence")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("-c", "--config", metavar="FILE", help="path to config.toml")

    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="report what this environment can actually inspect")
    d.set_defaults(func=cmd_doctor)

    s = sub.add_parser("scan", help="scan installed apps, the filesystem, or both")
    s.add_argument("--apps", action="store_true", help="installed applications only")
    s.add_argument("--files", action="store_true", help="filesystem only")
    s.add_argument("--full", action="store_true", help="everything (default)")
    s.add_argument("--path", action="append", metavar="DIR", help="scan this path; repeatable")
    s.add_argument("--recent", type=float, metavar="HOURS", help="only files modified in the last N hours")
    s.add_argument("--deep", action="store_true", help="content-sniff files with no useful extension")
    s.add_argument("--backend", choices=("auto", "direct", "adb"), default="auto")
    s.add_argument("--min-severity", default="LOW", metavar="LEVEL", help="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    s.add_argument("--json", action="store_true", help="machine readable output")
    s.add_argument("-o", "--output", metavar="FILE", help="write a JSON report to FILE")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="watch download directories and scan new files in real time")
    w.add_argument("--catch-up", type=float, metavar="HOURS", help="first scan files written in the last N hours")
    w.add_argument("--once", action="store_true", help="drain pending events then exit")
    w.set_defaults(func=cmd_watch)

    u = sub.add_parser("update", help="download or refresh signature databases")
    u.set_defaults(func=cmd_update)

    qp = sub.add_parser("quarantine", help="inspect and manage quarantined files")
    qp.add_argument("action", choices=("list", "restore", "delete"))
    qp.add_argument("id", nargs="?", help="quarantine entry id")
    qp.add_argument("--to", metavar="PATH", help="restore to this path instead of the original")
    qp.set_defaults(func=cmd_quarantine)

    cp = sub.add_parser("config", help="show or create the configuration file")
    cp.add_argument("action", choices=("show", "init"), nargs="?", default="show")
    cp.add_argument("--force", action="store_true", help="overwrite an existing config file")
    cp.set_defaults(func=cmd_config)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        set_color(False)

    cfg = config_mod.load(args.config or config_mod.CONFIG_FILE)
    if getattr(args, "deep", False):
        cfg.deep_scan = True
    config_mod.ensure_dirs(cfg)

    try:
        return args.func(args, cfg)
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        return EXIT_ERROR
    except OSError as exc:
        error(str(exc))
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
