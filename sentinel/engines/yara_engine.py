"""YARA integration.

YARA covers what ClamAV's hash-and-pattern corpus does not: behavioural shapes
that survive recompilation. A dropper rewritten to change its hash still has to
call DexClassLoader and still has to ship an installer intent, and a rule can
say so.

Rules live in rules/*.yar and are compiled once per run into a single bundle,
because invoking the CLI per rule file per target would be pathologically slow.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

from ..findings import Finding, Severity

# `yara -m` prints:  RuleName [key="value",key2="value2"] /path/to/file
_HIT_RE = re.compile(r"^(?P<rule>\w+)\s+(?:\[(?P<meta>.*?)\]\s+)?(?P<path>/.+)$")
_META_RE = re.compile(r'(\w+)="([^"]*)"')

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "rules")
RULES_DIR = os.path.normpath(RULES_DIR)


def available() -> bool:
    return shutil.which("yara") is not None


def rule_files(rules_dir: str = RULES_DIR) -> list[str]:
    if not os.path.isdir(rules_dir):
        return []
    return sorted(
        os.path.join(rules_dir, n)
        for n in os.listdir(rules_dir)
        if n.endswith((".yar", ".yara"))
    )


def compile_rules(rules_dir: str = RULES_DIR) -> tuple[str | None, str]:
    """Compile every rule file into one bundle. Returns (path, message).

    A compile failure is fatal for this engine but not for the scan, so the
    error text is handed back for reporting rather than raised.
    """
    files = rule_files(rules_dir)
    if not files:
        return None, f"no rule files found in {rules_dir}"
    if not shutil.which("yarac"):
        # Without the compiler we can still run rules, just less efficiently.
        return None, "yarac not available; rules will be interpreted per scan"

    fd, out_path = tempfile.mkstemp(suffix=".yarc")
    os.close(fd)
    try:
        p = subprocess.run(
            ["yarac", "-w", *files, out_path], capture_output=True, text=True, timeout=120
        )
        if p.returncode != 0:
            os.unlink(out_path)
            err = (p.stderr or p.stdout).strip().splitlines()
            return None, err[-1] if err else "rule compilation failed"
        return out_path, f"{len(files)} rule files compiled"
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)


def _severity_from_meta(meta: dict[str, str]) -> Severity:
    return Severity.parse(meta.get("severity", "HIGH"))


def scan_files(
    paths: list[str],
    compiled: str | None = None,
    rules_dir: str = RULES_DIR,
    timeout: int = 1800,
) -> list[Finding]:
    """Run the rule set over a batch of files."""
    if not paths:
        return []
    if not available():
        return [
            Finding(
                title="YARA engine unavailable",
                severity=Severity.LOW,
                target="yara",
                category="integrity",
                engine="yara",
                detail="yara is not installed, so behavioural rules were skipped.",
                remediation="pkg install yara",
            )
        ]

    files = rule_files(rules_dir)
    if compiled is None and not files:
        return [
            Finding(
                title="No YARA rules available",
                severity=Severity.LOW,
                target=rules_dir,
                category="integrity",
                engine="yara",
                detail="The rules directory is empty, so nothing was matched against.",
                remediation="Restore the rules/ directory from the repository.",
            )
        ]

    with tempfile.NamedTemporaryFile("w", suffix=".lst", delete=False, encoding="utf-8") as fh:
        for p in paths:
            fh.write(p + "\n")
        list_path = fh.name

    base = ["yara", "-w", "-m", "--scan-list"]
    # The CLI takes exactly one rule source per invocation. With a compiled
    # bundle that is a single pass; without one, every rule file is run in turn
    # so coverage is never silently reduced.
    rule_sets = [compiled] if compiled else files

    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    try:
        for rs in rule_sets:
            cmd = base + (["-C", rs] if compiled else [rs]) + [list_path]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            for line in p.stdout.splitlines():
                m = _HIT_RE.match(line.strip())
                if not m:
                    continue
                rule = m.group("rule")
                path = m.group("path")
                if (rule, path) in seen:
                    continue
                seen.add((rule, path))
                meta = dict(_META_RE.findall(m.group("meta") or ""))
                out.append(
                    Finding(
                        title=f"Behavioural rule match: {rule}",
                        severity=_severity_from_meta(meta),
                        target=path,
                        category="signature",
                        engine="yara",
                        detail=meta.get(
                            "description",
                            f"The file matches YARA rule '{rule}'.",
                        ),
                        remediation=meta.get(
                            "action", "Inspect this file before opening or installing it."
                        ),
                        evidence={k: v for k, v in meta.items() if k not in ("description", "action")}
                        | {"rule": rule},
                    )
                )
    except subprocess.TimeoutExpired:
        out.append(
            Finding(
                title="YARA scan timed out",
                severity=Severity.LOW,
                target="yara",
                category="integrity",
                engine="yara",
                detail=f"Rule matching exceeded {timeout}s and was stopped.",
                remediation="Narrow the scan scope.",
            )
        )
    except OSError as exc:
        out.append(
            Finding(
                title="YARA could not be started",
                severity=Severity.LOW,
                target="yara",
                category="integrity",
                engine="yara",
                detail=str(exc),
                remediation="pkg install yara",
            )
        )
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass

    return out
