"""User configuration, quarantine paths, and state directories.

Config lives at ~/.config/termux-sentinel/config.toml and is optional: every
value has a working default, so the tool runs correctly on first launch with no
setup at all.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace

from .env import DROP_DIRS, TERMUX_HOME

XDG_CONFIG = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
    os.path.expanduser("~"), ".config"
)
XDG_DATA = os.environ.get("XDG_DATA_HOME") or os.path.join(
    os.path.expanduser("~"), ".local", "share"
)

CONFIG_DIR = os.path.join(XDG_CONFIG, "termux-sentinel")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.toml")
DATA_DIR = os.path.join(XDG_DATA, "termux-sentinel")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
CLAMAV_DB_DIR = os.path.join(DATA_DIR, "clamav-db")
LOG_FILE = os.path.join(DATA_DIR, "sentinel.log")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

# The scanner's own installation directory.
#
# This MUST be excluded. Detection rules necessarily contain the very strings
# they hunt for, so scanning rules/*.yar makes every rule match itself and
# reports the tool as a reverse shell, a miner, and a root exploit at once.
# Observed on a real run before this exclusion existed.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Skipped during file scans: large, high-churn, and never the place malware
# hides in a way we could act on anyway.
DEFAULT_EXCLUDES = (
    REPO_ROOT,
    "/sdcard/Android/data",
    "/sdcard/Android/obb",
    "/proc",
    "/sys",
    "/dev",
    TERMUX_HOME + "/termux-sentinel/.git",
    "/data/data/com.termux/files/usr/var/cache",
)

# Extensions worth full signature scanning. Media files are hashed but not fed
# to the engines unless deep mode is on, which keeps a full scan tolerable on
# a phone.
EXECUTABLE_EXTS = (
    ".apk", ".apks", ".xapk", ".aab", ".dex", ".jar", ".so", ".elf", ".bin",
    ".sh", ".bash", ".py", ".pl", ".rb", ".js", ".php", ".zip", ".rar", ".7z",
)


@dataclass
class Config:
    scan_paths: list[str] = field(default_factory=lambda: ["/sdcard", TERMUX_HOME])
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    watch_paths: list[str] = field(default_factory=lambda: list(DROP_DIRS))

    max_file_mb: int = 128
    deep_scan: bool = False
    follow_symlinks: bool = False

    use_clamav: bool = True
    use_yara: bool = True
    use_heuristics: bool = True

    clamav_db_dir: str = CLAMAV_DB_DIR
    quarantine_dir: str = QUARANTINE_DIR
    auto_quarantine: bool = False

    # VirusTotal stays inert until a key is present; nothing leaves the device
    # before then. Only hashes are ever sent, never file contents.
    virustotal_api_key: str = ""
    virustotal_enabled: bool = False

    notify: bool = True
    suppress: list[str] = field(default_factory=list)

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1024 * 1024

    @property
    def suppressed(self) -> set[str]:
        return set(self.suppress)


def _coerce(cfg: Config, table: dict) -> Config:
    """Apply a parsed TOML table over defaults, ignoring unknown keys.

    Type mismatches are dropped rather than raising: a typo in a config file
    should never stop a security scan from running.
    """
    updates = {}
    for key, value in table.items():
        if not hasattr(cfg, key):
            continue
        current = getattr(cfg, key)
        if isinstance(current, bool) and isinstance(value, bool):
            updates[key] = value
        elif isinstance(current, int) and not isinstance(current, bool) and isinstance(value, int):
            updates[key] = value
        elif isinstance(current, str) and isinstance(value, str):
            updates[key] = value
        elif isinstance(current, list) and isinstance(value, list):
            updates[key] = [str(v) for v in value]
    return replace(cfg, **updates)


def load(path: str = CONFIG_FILE) -> Config:
    cfg = Config()
    try:
        with open(path, "rb") as fh:
            table = tomllib.load(fh)
    except FileNotFoundError:
        return cfg
    except (tomllib.TOMLDecodeError, OSError):
        # Surfaced by `sentinel doctor`; scanning continues on defaults.
        return cfg

    cfg = _coerce(cfg, {k: v for k, v in table.items() if not isinstance(v, dict)})
    for section in ("scan", "engines", "quarantine", "virustotal", "watch"):
        if isinstance(table.get(section), dict):
            cfg = _coerce(cfg, table[section])
    if cfg.virustotal_api_key:
        cfg = replace(cfg, virustotal_enabled=True)
    return _enforce_invariants(cfg)


def _enforce_invariants(cfg: Config) -> Config:
    """Re-apply exclusions that configuration must never be able to remove.

    A user-supplied `exclude_paths` replaces the default list wholesale. That is
    the right behaviour for ordinary paths, but it silently re-enabled scanning
    of this tool's own directory -- where the detection rules live, and where
    every rule inevitably matches itself. Observed in the field: four CRITICAL
    findings, all of them the scanner reading its own signatures.
    """
    if not any(
        REPO_ROOT == e or REPO_ROOT.startswith(e.rstrip("/") + "/") for e in cfg.exclude_paths
    ):
        return replace(cfg, exclude_paths=[REPO_ROOT, *cfg.exclude_paths])
    return cfg


def ensure_dirs(cfg: Config) -> None:
    for d in (CONFIG_DIR, DATA_DIR, cfg.quarantine_dir, cfg.clamav_db_dir):
        os.makedirs(d, mode=0o700, exist_ok=True)


SAMPLE_CONFIG = """\
# Termux Sentinel configuration
# Every key is optional; delete a line to fall back to the built-in default.

[scan]
scan_paths     = ["/sdcard", "~/"]
max_file_mb    = 128
deep_scan      = false

# Setting exclude_paths REPLACES the built-in list rather than adding to it, so
# uncomment this only if you intend to manage the whole set yourself. The
# scanner's own directory is always excluded regardless of what you put here.
# exclude_paths = ["/sdcard/Android/data", "/sdcard/Android/obb"]

[engines]
use_clamav     = true
use_yara       = true
use_heuristics = true

[quarantine]
auto_quarantine = false

[virustotal]
# Only SHA-256 hashes are sent, never file contents. Leave empty to stay offline.
virustotal_api_key = ""

[watch]
notify = true
"""
