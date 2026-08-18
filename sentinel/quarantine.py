"""Quarantine store.

Quarantine means: make the file harmless without destroying it. Deleting on
detection is hostile when a detection is wrong, and detections are sometimes
wrong. Files are moved into a private directory, stripped of every permission
bit, and recorded with enough metadata to be put back exactly where they were.

The store deliberately keeps the original bytes intact. Nothing here disarms a
file; it only makes it inert by removing the ability to read or execute it.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import asdict, dataclass, field

from .config import Config


@dataclass
class Entry:
    id: str
    original_path: str
    stored_path: str
    sha256: str
    size: int
    reason: str
    severity: str
    quarantined_at: float = field(default_factory=time.time)
    original_mode: int = 0o600

    def to_dict(self) -> dict:
        return asdict(self)


class Quarantine:
    def __init__(self, cfg: Config) -> None:
        self.dir = cfg.quarantine_dir
        self.index_path = os.path.join(self.dir, "index.json")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self._entries = self._load()

    def _load(self) -> dict[str, Entry]:
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
        out = {}
        for eid, d in raw.items():
            try:
                out[eid] = Entry(**d)
            except TypeError:
                continue  # index written by an older schema; skip that row
        return out

    def _save(self) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({k: v.to_dict() for k, v in self._entries.items()}, fh, indent=2)
        os.replace(tmp, self.index_path)  # atomic, so a crash cannot corrupt the index
        os.chmod(self.index_path, 0o600)

    def add(self, path: str, sha256: str, reason: str, severity: str) -> Entry | None:
        """Move a file into quarantine. Returns None when the move fails."""
        if not os.path.isfile(path):
            return None
        try:
            st = os.stat(path)
            eid = f"{int(time.time())}-{sha256[:12]}"
            stored = os.path.join(self.dir, eid + ".bin")

            # Copy-then-remove rather than rename: the source is usually on
            # /sdcard, a different filesystem from the app's private storage.
            shutil.copy2(path, stored)
            os.chmod(stored, 0o000)
            os.remove(path)
        except OSError:
            return None

        entry = Entry(
            id=eid,
            original_path=os.path.abspath(path),
            stored_path=stored,
            sha256=sha256,
            size=st.st_size,
            reason=reason,
            severity=severity,
            original_mode=st.st_mode & 0o777,
        )
        self._entries[eid] = entry
        self._save()
        return entry

    def restore(self, eid: str, dest: str | None = None) -> tuple[bool, str]:
        entry = self._entries.get(eid)
        if not entry:
            return False, f"no quarantine entry with id {eid}"
        target = dest or entry.original_path
        if os.path.exists(target):
            return False, f"refusing to overwrite existing file at {target}"
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.chmod(entry.stored_path, 0o600)
            shutil.copy2(entry.stored_path, target)
            os.chmod(target, entry.original_mode or 0o600)
            os.remove(entry.stored_path)
        except OSError as exc:
            return False, str(exc)
        del self._entries[eid]
        self._save()
        return True, target

    def delete(self, eid: str) -> tuple[bool, str]:
        entry = self._entries.get(eid)
        if not entry:
            return False, f"no quarantine entry with id {eid}"
        try:
            os.chmod(entry.stored_path, 0o600)
            os.remove(entry.stored_path)
        except OSError as exc:
            if os.path.exists(entry.stored_path):
                return False, str(exc)
        del self._entries[eid]
        self._save()
        return True, entry.original_path

    def list(self) -> list[Entry]:
        return sorted(self._entries.values(), key=lambda e: -e.quarantined_at)

    def __len__(self) -> int:
        return len(self._entries)
