"""Shared finding model used by every detection engine.

Each scanner -- permission heuristics, ClamAV, YARA, system audit -- emits the
same Finding object, so reporting, dedup, and exit codes are handled in one
place.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            return cls.INFO

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    """A single security observation.

    `target` is a package name or a file path. `evidence` carries the raw
    supporting data so a JSON report can be audited later without rescanning
    the device.
    """

    title: str
    severity: Severity
    target: str
    category: str  # permission | signature | integrity | system | network | worm
    engine: str  # heuristics | clamav | yara | hashdb | system
    detail: str = ""
    remediation: str = ""
    evidence: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        """Stable identity for dedup and suppression.

        Deliberately excludes the timestamp and free-form detail so the same
        issue yields an identical fingerprint on the next scan.
        """
        raw = "|".join([self.engine, self.category, self.title, self.target])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["fingerprint"] = self.fingerprint
        return d


class FindingSet:
    """A collection of findings with automatic fingerprint-based dedup."""

    def __init__(self) -> None:
        self._items: dict[str, Finding] = {}

    def add(self, finding: Finding | None) -> None:
        if finding is None:
            return
        fp = finding.fingerprint
        existing = self._items.get(fp)
        # On a duplicate, keep whichever carries the higher severity.
        if existing is None or finding.severity > existing.severity:
            self._items[fp] = finding

    def extend(self, findings) -> None:
        for f in findings:
            self.add(f)

    def suppress(self, fingerprints: set[str]) -> None:
        for fp in list(self._items):
            if fp in fingerprints:
                del self._items[fp]

    @property
    def items(self) -> list[Finding]:
        """Worst first, then alphabetically by target."""
        return sorted(
            self._items.values(),
            key=lambda f: (-int(f.severity), f.target, f.title),
        )

    def by_severity(self, minimum: Severity) -> list[Finding]:
        return [f for f in self.items if f.severity >= minimum]

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self._items.values():
            out[f.severity.label] += 1
        return out

    @property
    def worst(self) -> Severity:
        if not self._items:
            return Severity.INFO
        return max(f.severity for f in self._items.values())

    def exit_code(self) -> int:
        """0 clean, 1 medium findings, 2 high or critical findings.

        Shaped this way so the tool composes with shell scripts and cron.
        """
        w = self.worst
        if w >= Severity.HIGH:
            return 2
        if w >= Severity.MEDIUM:
            return 1
        return 0

    def to_json(self, meta: dict | None = None, indent: int = 2) -> str:
        payload = {
            "schema": 1,
            "generated_at": time.time(),
            "meta": meta or {},
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.items],
        }
        return json.dumps(payload, indent=indent, ensure_ascii=False)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self.items)
