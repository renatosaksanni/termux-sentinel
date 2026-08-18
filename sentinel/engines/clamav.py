"""ClamAV integration.

ClamAV supplies the signature corpus this tool would otherwise lack: millions
of maintained definitions, including a substantial Android malware set. We
drive the CLI rather than link the library, because the Termux package ships
the binaries and no Python bindings.

Memory matters here. Loading the full signature database costs roughly 1.2 GB
of RAM. On a phone that is survivable but not free, so scans are batched and
the database is loaded once per batch rather than once per file.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

from ..config import Config
from ..findings import Finding, Severity

# "/path/to/file: Signature.Name FOUND"
_HIT_RE = re.compile(r"^(?P<path>.+?): (?P<sig>[^:]+?) FOUND\s*$")

# ClamAV signature name fragments that indicate a genuine Android threat rather
# than a generic or heuristic match. Used to weight severity.
_ANDROID_MARKERS = ("Andr", "Android", "Adware.AndrDrp", "Trojan.AndroidOS")


def db_present(cfg: Config) -> bool:
    """True when a usable signature database exists in our private db dir."""
    if not os.path.isdir(cfg.clamav_db_dir):
        return False
    names = os.listdir(cfg.clamav_db_dir)
    return any(n.endswith((".cvd", ".cld")) for n in names)


def db_age_days(cfg: Config) -> float | None:
    """Age of the freshest signature file, or None when no database exists."""
    if not os.path.isdir(cfg.clamav_db_dir):
        return None
    newest = 0.0
    for n in os.listdir(cfg.clamav_db_dir):
        if n.endswith((".cvd", ".cld")):
            try:
                newest = max(newest, os.path.getmtime(os.path.join(cfg.clamav_db_dir, n)))
            except OSError:
                continue
    if newest == 0.0:
        return None
    return (time.time() - newest) / 86400.0


def update_db(cfg: Config, quiet: bool = False) -> tuple[bool, str]:
    """Fetch or refresh signatures with freshclam into our own data directory.

    Uses a private datadir so the tool never fights the system freshclam
    configuration and needs no elevated rights.
    """
    if not shutil.which("freshclam"):
        return False, "freshclam not installed"
    os.makedirs(cfg.clamav_db_dir, mode=0o700, exist_ok=True)

    # freshclam refuses to start without a config file, but accepts one on
    # stdin via '-'; a minimal generated config avoids touching system files.
    conf = (
        f"DatabaseDirectory {cfg.clamav_db_dir}\n"
        "DatabaseMirror database.clamav.net\n"
        "CompressLocalDatabase yes\n"
        "ScriptedUpdates yes\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(conf)
        conf_path = fh.name

    try:
        cmd = ["freshclam", "--config-file", conf_path, "--datadir", cfg.clamav_db_dir]
        if quiet:
            cmd.append("--quiet")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        # Exit 1 means "already up to date" in some builds; treat db presence
        # as the real success criterion.
        ok = db_present(cfg)
        msg = (p.stdout or p.stderr or "").strip().splitlines()
        return ok, msg[-1] if msg else ("database ready" if ok else "update failed")
    except subprocess.TimeoutExpired:
        return db_present(cfg), "freshclam timed out after 30 minutes"
    except OSError as exc:
        return False, str(exc)
    finally:
        try:
            os.unlink(conf_path)
        except OSError:
            pass


def _severity_for(signature: str) -> Severity:
    """Map a ClamAV signature name onto our severity scale."""
    s = signature.lower()
    if "phish" in s or "pua" in s or "unwanted" in s or "adware" in s:
        return Severity.MEDIUM
    if "test" in s and "eicar" in s:
        # The EICAR test file is harmless by definition but proves the engine
        # is wired up correctly, which is worth reporting plainly.
        return Severity.LOW
    if any(m.lower() in s for m in (m.lower() for m in _ANDROID_MARKERS)):
        return Severity.CRITICAL
    return Severity.HIGH


def scan_files(cfg: Config, paths: list[str], timeout: int = 3600) -> list[Finding]:
    """Scan a batch of files in one clamscan invocation.

    Returns findings only for detections; clean files produce nothing. A failure
    to run the engine is reported as a finding too, because a security tool that
    silently scans nothing is worse than one that admits it.
    """
    if not paths:
        return []
    if not shutil.which("clamscan"):
        return [
            Finding(
                title="ClamAV engine unavailable",
                severity=Severity.MEDIUM,
                target="clamscan",
                category="integrity",
                engine="clamav",
                detail="clamscan is not installed, so signature scanning was skipped entirely.",
                remediation="pkg install clamav",
            )
        ]
    if not db_present(cfg):
        return [
            Finding(
                title="ClamAV signature database missing",
                severity=Severity.HIGH,
                target=cfg.clamav_db_dir,
                category="integrity",
                engine="clamav",
                detail=(
                    "No signature database was found, so every file was reported "
                    "clean without actually being compared to anything."
                ),
                remediation="sentinel update",
            )
        ]

    # A file list avoids ARG_MAX limits and keeps paths with spaces intact.
    with tempfile.NamedTemporaryFile("w", suffix=".lst", delete=False, encoding="utf-8") as fh:
        for p in paths:
            fh.write(p + "\n")
        list_path = fh.name

    cmd = [
        "clamscan",
        "--database", cfg.clamav_db_dir,
        "--file-list", list_path,
        "--infected",
        "--no-summary",
        "--stdout",
        f"--max-filesize={cfg.max_file_mb}M",
        f"--max-scansize={max(cfg.max_file_mb * 2, 256)}M",
        "--max-recursion=12",
        "--alert-broken=yes",
        "--alert-encrypted-archive=yes",
    ]

    out: list[Finding] = []
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # 0 = clean, 1 = virus found, 2 = error.
        if p.returncode == 2:
            detail = (p.stderr or p.stdout or "unknown error").strip().splitlines()
            out.append(
                Finding(
                    title="ClamAV reported an execution error",
                    severity=Severity.MEDIUM,
                    target="clamscan",
                    category="integrity",
                    engine="clamav",
                    detail=detail[-1] if detail else "clamscan exited with an error",
                    remediation="Check available RAM; the full database needs roughly 1.2 GB.",
                )
            )
        for line in p.stdout.splitlines():
            m = _HIT_RE.match(line.strip())
            if not m:
                continue
            sig = m.group("sig").strip()
            path = m.group("path").strip()
            out.append(
                Finding(
                    title=f"Malware signature match: {sig}",
                    severity=_severity_for(sig),
                    target=path,
                    category="signature",
                    engine="clamav",
                    detail=(
                        f"This file matches the known-malware signature '{sig}' in "
                        "the ClamAV database."
                    ),
                    remediation="sentinel quarantine '<path>' then delete it once confirmed.",
                    evidence={"signature": sig, "path": path},
                )
            )
    except subprocess.TimeoutExpired:
        out.append(
            Finding(
                title="ClamAV scan timed out",
                severity=Severity.MEDIUM,
                target="clamscan",
                category="integrity",
                engine="clamav",
                detail=f"The scan exceeded {timeout}s and was stopped, leaving files unchecked.",
                remediation="Narrow scan_paths or raise the timeout.",
            )
        )
    except OSError as exc:
        out.append(
            Finding(
                title="ClamAV could not be started",
                severity=Severity.MEDIUM,
                target="clamscan",
                category="integrity",
                engine="clamav",
                detail=str(exc),
                remediation="pkg install clamav",
            )
        )
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass

    return out
