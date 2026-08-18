"""Hash reputation: a local known-bad list plus an optional VirusTotal lookup.

The local list is authoritative and offline. VirusTotal is strictly opt-in and
sends only SHA-256 digests, never file contents -- a hash reveals nothing about
a file's contents to anyone who does not already possess the file.

The free VirusTotal tier allows 4 requests per minute, so lookups are rate
limited and cached on disk. Without an API key this module is inert.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from ..config import DATA_DIR, Config
from ..findings import Finding, Severity

DATA_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "data")
DATA_ROOT = os.path.normpath(DATA_ROOT)
KNOWN_BAD_FILE = os.path.join(DATA_ROOT, "known_bad_hashes.txt")
VT_CACHE_FILE = os.path.join(DATA_DIR, "vt-cache.json")

VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_MIN_INTERVAL = 16.0  # seconds between requests, keeps us under 4/min


def load_known_bad(path: str = KNOWN_BAD_FILE) -> dict[str, str]:
    """Parse 'sha256<space>label' lines, ignoring blanks and comments."""
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                digest = parts[0].lower()
                if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                    out[digest] = parts[1].strip() if len(parts) > 1 else "known malicious file"
    except OSError:
        pass
    return out


def check_local(sha256: str, target: str, known_bad: dict[str, str]) -> Finding | None:
    label = known_bad.get(sha256.lower())
    if not label:
        return None
    return Finding(
        title=f"Known malicious file: {label}",
        severity=Severity.CRITICAL,
        target=target,
        category="signature",
        engine="hashdb",
        detail=f"The SHA-256 of this file appears in the local known-bad list ({label}).",
        remediation="Quarantine and delete this file.",
        evidence={"sha256": sha256},
    )


class VirusTotal:
    """Minimal VirusTotal v3 client for hash reputation only."""

    def __init__(self, cfg: Config) -> None:
        self.key = cfg.virustotal_api_key
        self.enabled = bool(self.key) and cfg.virustotal_enabled
        self._last_call = 0.0
        self._cache = self._load_cache()

    def _load_cache(self) -> dict:
        try:
            with open(VT_CACHE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    def save_cache(self) -> None:
        if not self._cache:
            return
        try:
            os.makedirs(os.path.dirname(VT_CACHE_FILE), mode=0o700, exist_ok=True)
            with open(VT_CACHE_FILE, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh)
        except OSError:
            pass

    def _throttle(self) -> None:
        wait = VT_MIN_INTERVAL - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def lookup(self, sha256: str, target: str) -> Finding | None:
        """Return a finding when the hash is flagged by multiple vendors.

        A single vendor detection is treated as noise: false positives on
        obscure files are common and acting on one alone is not useful.
        """
        if not self.enabled:
            return None
        digest = sha256.lower()
        cached = self._cache.get(digest)
        if cached is None:
            self._throttle()
            req = urllib.request.Request(
                VT_URL.format(sha256=digest),
                headers={"x-apikey": self.key, "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = json.loads(resp.read().decode("utf-8", "replace"))
                stats = body["data"]["attributes"]["last_analysis_stats"]
                names = body["data"]["attributes"].get("popular_threat_classification", {})
                cached = {
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "label": names.get("suggested_threat_label", ""),
                }
            except urllib.error.HTTPError as exc:
                # 404 simply means nobody has ever submitted this file.
                cached = {"malicious": 0, "suspicious": 0, "label": "", "unknown": exc.code == 404}
            except (urllib.error.URLError, KeyError, ValueError, TimeoutError):
                return None
            self._cache[digest] = cached

        malicious = cached.get("malicious", 0)
        if malicious < 2:
            return None
        label = cached.get("label") or "flagged by multiple engines"
        return Finding(
            title=f"VirusTotal: {malicious} engines flag this file",
            severity=Severity.CRITICAL if malicious >= 5 else Severity.HIGH,
            target=target,
            category="signature",
            engine="hashdb",
            detail=f"{malicious} antivirus engines classify this file as malicious ({label}).",
            remediation="Quarantine and delete this file.",
            evidence={"sha256": digest, "malicious": malicious, "label": label},
        )
