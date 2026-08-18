"""Real-time drop watcher.

This is the closest thing to on-access protection that an unrooted Android
device permits. It cannot intercept a file before it is written -- nothing
without kernel privileges can -- but it does see the write complete and can
scan, quarantine, and warn within a second of the file landing.

Coverage is limited to directories readable by this process: shared storage and
the Termux home. Files written into another app's private storage are invisible,
and the daemon says so at startup rather than implying full coverage.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field

from ..apk import sha256_file
from ..config import Config
from ..findings import Finding, Severity
from ..quarantine import Quarantine
from ..scan import Scanner
from .inotify import IN_CREATE, IN_ISDIR, Inotify, InotifyError

# A download appears as a stream of writes. Waiting briefly after the last event
# avoids scanning a half-written file and re-scanning it moments later.
SETTLE_SECONDS = 1.5
MAX_PENDING = 512


@dataclass
class WatchStats:
    events: int = 0
    scanned: int = 0
    detections: int = 0
    quarantined: int = 0
    started: float = field(default_factory=time.time)
    watched: list[str] = field(default_factory=list)


def notify(title: str, body: str, urgent: bool = False) -> None:
    """Post an Android notification when termux-api is installed."""
    if not shutil.which("termux-notification"):
        return
    cmd = [
        "termux-notification",
        "--title", title,
        "--content", body,
        "--id", "termux-sentinel",
    ]
    if urgent:
        cmd += ["--priority", "max", "--vibrate", "500,200,500"]
    try:
        subprocess.run(cmd, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass


class Watcher:
    def __init__(self, cfg: Config, on_finding=None, on_event=None) -> None:
        self.cfg = cfg
        self.scanner = Scanner(cfg)
        self.quarantine = Quarantine(cfg)
        self.stats = WatchStats()
        self.on_finding = on_finding
        self.on_event = on_event
        self._pending: dict[str, float] = {}
        self._ino: Inotify | None = None

    def start(self) -> list[str]:
        """Register watches. Returns the directories actually being watched."""
        self._ino = Inotify()
        for path in self.cfg.watch_paths:
            path = os.path.expanduser(path)
            if not os.path.isdir(path):
                continue
            # One level of recursion: chat apps nest media directories, but a
            # full recursive walk of /sdcard would exhaust the watch limit.
            self._ino.add(path)
            try:
                for name in os.listdir(path):
                    sub = os.path.join(path, name)
                    if os.path.isdir(sub):
                        self._ino.add(sub)
            except OSError:
                continue
        self.stats.watched = self._ino.watched_paths
        return self.stats.watched

    def _handle(self, path: str) -> None:
        """Scan one settled file and act on what comes back."""
        if not os.path.isfile(path):
            return
        findings = self.scanner.scan_file(path)
        self.stats.scanned += 1

        actionable = [f for f in findings if f.severity >= Severity.HIGH]
        for f in findings:
            if f.severity >= Severity.MEDIUM and self.on_finding:
                self.on_finding(f)

        if not actionable:
            return
        self.stats.detections += 1
        worst = max(actionable, key=lambda f: f.severity)

        if self.cfg.auto_quarantine:
            try:
                sha = sha256_file(path)
            except OSError:
                sha = ""
            entry = self.quarantine.add(path, sha, worst.title, worst.severity.label)
            if entry:
                self.stats.quarantined += 1
                if self.cfg.notify:
                    notify(
                        "Threat quarantined",
                        f"{os.path.basename(path)}: {worst.title}",
                        urgent=True,
                    )
                return

        if self.cfg.notify:
            notify("Threat detected", f"{os.path.basename(path)}: {worst.title}", urgent=True)

    def run(self, once: bool = False, timeout: float = 1.0) -> None:
        """Event loop. Runs until interrupted."""
        if self._ino is None:
            self.start()
        assert self._ino is not None

        while True:
            try:
                events = self._ino.read(timeout=timeout)
            except (InotifyError, OSError):
                break

            for ev in events:
                self.stats.events += 1
                if not ev.path:
                    continue
                # A new directory inside a watched tree needs its own watch,
                # otherwise files dropped into it are never seen.
                if ev.is_dir and ev.mask & IN_CREATE:
                    self._ino.add(ev.path)
                    continue
                if not ev.is_write_complete:
                    continue
                if len(self._pending) < MAX_PENDING:
                    self._pending[ev.path] = time.monotonic()
                if self.on_event:
                    self.on_event(ev.path)

            now = time.monotonic()
            ready = [p for p, t in self._pending.items() if now - t >= SETTLE_SECONDS]
            for p in ready:
                del self._pending[p]
                try:
                    self._handle(p)
                except OSError:
                    continue

            if once and not self._pending:
                break

    def catch_up(self, hours: float = 24.0) -> list[Finding]:
        """Scan files written while the watcher was not running."""
        result = self.scanner.scan_paths(
            paths=[os.path.expanduser(p) for p in self.cfg.watch_paths],
            recent_hours=hours,
        )
        return result.items

    def close(self) -> None:
        if self._ino:
            self._ino.close()
        self.scanner.close()
