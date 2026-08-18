"""Filesystem traversal and candidate selection.

Scanning every byte of a phone is neither fast nor useful. This module decides
what is worth looking at: executables, archives, scripts, and anything recently
written into a directory that receives files from outside.

Symlinks are not followed by default. A symlink loop or a link into /proc would
otherwise turn a scan into an infinite walk.
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass

from ..config import EXECUTABLE_EXTS, Config

# Magic bytes checked when the extension says nothing useful. Files arriving
# from chat apps frequently have no extension at all.
MAGIC = {
    b"PK\x03\x04": "zip/apk",
    b"dex\n": "dex",
    b"\x7fELF": "elf",
    b"#!": "script",
    b"\xca\xfe\xba\xbe": "class",
    b"Rar!": "rar",
    b"7z\xbc\xaf": "7z",
}
MAGIC_MAX = max(len(k) for k in MAGIC)

# Files at or below this size are scanned regardless of extension, because
# shell droppers and miner configs arrive as .conf, .com, or with no extension
# at all.
SMALL_FILE_BYTES = 4 * 1024 * 1024

# Media is exempt from that rule, and is skipped on extension alone without
# reading the file. Measured on a real device, /sdcard/Android/media held 52k
# files; opening each one to check its header took longer than every other part
# of the scan combined, and found nothing, because these formats cannot carry a
# payload Android would execute.
#
# The trade is explicit: an executable renamed to .jpg is not detected here.
# Run with --deep to inspect media contents as well.
MEDIA_EXTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".heif", ".avif",
    ".mp4", ".mkv", ".avi", ".mov", ".webm", ".3gp", ".m4v", ".ts",
    ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac", ".amr",
    ".ttf", ".otf", ".woff", ".woff2", ".ico", ".svg",
    ".pdf", ".docx", ".xlsx", ".pptx", ".epub", ".csv",
)


@dataclass
class Candidate:
    path: str
    size: int
    mtime: float
    kind: str  # extension match, magic match, or "recent"

    @property
    def is_apk(self) -> bool:
        return self.path.lower().endswith((".apk", ".apks", ".xapk")) or self.kind == "zip/apk"


def _excluded(path: str, excludes: list[str]) -> bool:
    return any(path == e or path.startswith(e.rstrip("/") + "/") for e in excludes)


def _sniff(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(MAGIC_MAX)
    except OSError:
        return ""
    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            return kind
    return ""


def walk(
    cfg: Config,
    paths: list[str] | None = None,
    recent_hours: float = 0.0,
    on_progress=None,
) -> list[Candidate]:
    """Collect scan candidates.

    `recent_hours` restricts results to files written within that window, which
    is what the watcher uses for a fast catch-up pass after being offline.

    `on_progress(dirs_visited, candidates_found, current_dir)` is called once per
    directory. Walking shared storage on a phone can take minutes, and a silent
    traversal is indistinguishable from a hang, so callers are given something
    to display throughout.
    """
    roots = paths if paths is not None else cfg.scan_paths
    excludes = [os.path.expanduser(e) for e in cfg.exclude_paths]
    cutoff = time.time() - recent_hours * 3600 if recent_hours else 0.0
    seen_dirs: set[tuple[int, int]] = set()
    out: list[Candidate] = []
    dirs_visited = 0

    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(
            root, topdown=True, followlinks=cfg.follow_symlinks, onerror=None
        ):
            if _excluded(dirpath, excludes):
                dirnames[:] = []
                continue

            # Guard against hardlinked or bind-mounted directory cycles, which
            # do occur under /storage/emulated.
            try:
                st = os.stat(dirpath)
                key = (st.st_dev, st.st_ino)
                if key in seen_dirs:
                    dirnames[:] = []
                    continue
                seen_dirs.add(key)
            except OSError:
                dirnames[:] = []
                continue

            dirnames[:] = [d for d in dirnames if not _excluded(os.path.join(dirpath, d), excludes)]

            dirs_visited += 1
            if on_progress:
                on_progress(dirs_visited, len(out), dirpath)

            for name in filenames:
                fpath = os.path.join(dirpath, name)
                try:
                    st = os.lstat(fpath)
                except OSError:
                    continue
                # One lstat answers all three questions. Calling islink() and
                # isfile() as well would triple the syscall count, and shared
                # storage on Android is a FUSE mount where each one is costly:
                # /sdcard/Android/media alone holds tens of thousands of files.
                if stat.S_ISLNK(st.st_mode) and not cfg.follow_symlinks:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                size, mtime = st.st_size, st.st_mtime

                if size == 0 or size > cfg.max_file_bytes:
                    continue
                if cutoff and mtime < cutoff:
                    continue

                lower = name.lower()
                kind = ""
                if lower.endswith(EXECUTABLE_EXTS):
                    kind = os.path.splitext(lower)[1].lstrip(".")
                elif lower.endswith(MEDIA_EXTS):
                    # Skipped on extension alone, without opening the file.
                    # Sniffing every photo meant 52k file opens on shared
                    # storage here, which took longer than the rest of the scan
                    # combined. `--deep` restores content inspection for anyone
                    # who wants to catch an executable wearing a .jpg name.
                    if not cfg.deep_scan:
                        continue
                    kind = _sniff(fpath)
                elif size <= SMALL_FILE_BYTES:
                    # Extension is a poor signal: shell droppers, miner configs,
                    # and EICAR-style payloads arrive as .conf, .com, .txt, or
                    # nothing at all. Small files are cheap to scan, so scan
                    # them rather than trusting the name.
                    kind = _sniff(fpath) or "small"
                elif cfg.deep_scan:
                    kind = _sniff(fpath)

                if not kind:
                    continue

                out.append(Candidate(path=fpath, size=size, mtime=mtime, kind=kind))

    return out


def batched(items: list[str], batch_bytes: int, sizes: dict[str, int]) -> list[list[str]]:
    """Group paths into batches bounded by total size.

    Engines load their signature database once per invocation, so batching
    trades a little peak memory for a large reduction in repeated startup cost.
    """
    out: list[list[str]] = []
    current: list[str] = []
    total = 0
    for p in items:
        s = sizes.get(p, 0)
        if current and total + s > batch_bytes:
            out.append(current)
            current, total = [], 0
        current.append(p)
        total += s
    if current:
        out.append(current)
    return out
