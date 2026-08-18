"""Minimal inotify binding via ctypes.

Python has no inotify in the standard library, and adding a pip dependency to a
security tool that must run on a freshly installed Termux is a poor trade. The
kernel interface is three syscalls wide, so it is bound directly here.

This provides the closest thing to real-time protection available without root:
the kernel tells us the moment a file finishes being written into a watched
directory.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import select
import struct
from dataclasses import dataclass

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

IN_ONLYDIR = 0x01000000
IN_EXCL_UNLINK = 0x04000000

# A file is interesting once it is fully written (CLOSE_WRITE) or moved into
# place (MOVED_TO). Watching CREATE alone would fire on empty, still-downloading
# files and produce a scan of nothing.
DEFAULT_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ISDIR

_HEADER = struct.Struct("iIII")  # wd, mask, cookie, len


class InotifyError(OSError):
    pass


@dataclass
class Event:
    wd: int
    mask: int
    cookie: int
    name: str
    path: str

    @property
    def is_dir(self) -> bool:
        return bool(self.mask & IN_ISDIR)

    @property
    def is_write_complete(self) -> bool:
        return bool(self.mask & (IN_CLOSE_WRITE | IN_MOVED_TO))


def _load_libc() -> ctypes.CDLL:
    # Termux resolves plain "libc.so"; glibc systems need the versioned name.
    for name in ("libc.so", ctypes.util.find_library("c"), "libc.so.6"):
        if not name:
            continue
        try:
            return ctypes.CDLL(name, use_errno=True)
        except OSError:
            continue
    raise InotifyError("could not load libc for inotify")


class Inotify:
    """A single inotify instance watching a set of directories."""

    def __init__(self) -> None:
        self._libc = _load_libc()
        self._libc.inotify_init1.argtypes = [ctypes.c_int]
        self._libc.inotify_init1.restype = ctypes.c_int
        self._libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._libc.inotify_add_watch.restype = ctypes.c_int
        self._libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        self._libc.inotify_rm_watch.restype = ctypes.c_int

        fd = self._libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if fd < 0:
            raise InotifyError(ctypes.get_errno(), "inotify_init1 failed")
        self.fd = fd
        self._watches: dict[int, str] = {}

    def add(self, path: str, mask: int = DEFAULT_MASK) -> int | None:
        """Watch a directory. Returns None when the path cannot be watched.

        Failure is normal here: /sdcard directories come and go, and scoped
        storage hides some of them entirely. The caller reports coverage rather
        than aborting.
        """
        if not os.path.isdir(path):
            return None
        wd = self._libc.inotify_add_watch(self.fd, path.encode("utf-8"), mask)
        if wd < 0:
            return None
        self._watches[wd] = path
        return wd

    def add_recursive(self, root: str, mask: int = DEFAULT_MASK, max_dirs: int = 2000) -> int:
        """Watch a tree. inotify is not recursive, so every directory needs one.

        Capped, because each watch consumes a kernel slot and the per-user limit
        is commonly 8192 -- exhausting it would break watching elsewhere.
        """
        added = 0
        if self.add(root, mask) is not None:
            added += 1
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            for d in list(dirnames):
                if added >= max_dirs:
                    return added
                if self.add(os.path.join(dirpath, d), mask) is not None:
                    added += 1
        return added

    def remove(self, wd: int) -> None:
        self._libc.inotify_rm_watch(self.fd, wd)
        self._watches.pop(wd, None)

    def read(self, timeout: float | None = 1.0) -> list[Event]:
        """Block until events arrive or the timeout expires."""
        try:
            ready, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            return []
        if not ready:
            return []

        try:
            buf = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return []
        except OSError as exc:
            if exc.errno == errno.EINTR:
                return []
            raise

        events: list[Event] = []
        offset = 0
        while offset + _HEADER.size <= len(buf):
            wd, mask, cookie, length = _HEADER.unpack_from(buf, offset)
            offset += _HEADER.size
            raw = buf[offset : offset + length]
            offset += length
            name = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
            base = self._watches.get(wd, "")
            events.append(
                Event(
                    wd=wd,
                    mask=mask,
                    cookie=cookie,
                    name=name,
                    path=os.path.join(base, name) if base and name else base,
                )
            )
        return events

    @property
    def watch_count(self) -> int:
        return len(self._watches)

    @property
    def watched_paths(self) -> list[str]:
        return sorted(self._watches.values())

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass
