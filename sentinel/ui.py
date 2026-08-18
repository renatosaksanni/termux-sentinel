"""Terminal presentation: colour, tables, and progress bars.

No external dependencies, so the tool works on a freshly installed Termux.
Colour turns itself off when output is redirected or NO_COLOR is set.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import time

from .findings import Finding, Severity

_ENABLED = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"
    BG_RED = "\033[41m\033[97m"


SEV_COLOR = {
    Severity.INFO: C.GREY,
    Severity.LOW: C.BLUE,
    Severity.MEDIUM: C.YELLOW,
    Severity.HIGH: C.RED,
    Severity.CRITICAL: C.BG_RED,
}


# Braille frames give smooth motion in one character cell. Termux renders these
# correctly; terminals that cannot are also the ones where _ENABLED is false,
# so the animation never runs there.
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def visible_len(text: str) -> int:
    """Length as rendered, ignoring colour escapes.

    Padding a coloured string with ljust would count the escape bytes and pad
    far too little, leaving fragments of the previous frame on screen.
    """
    return len(_ANSI_RE.sub("", text))


def fit(text: str, cols: int) -> str:
    """Truncate to a visible width without cutting an escape sequence in half.

    A status line wider than the terminal wraps to a second row, and the
    carriage return then only overwrites the second row -- leaving a trail of
    stale frames up the screen. Everything transient goes through here.
    """
    if visible_len(text) <= cols:
        return text
    out = []
    shown = 0
    i = 0
    while i < len(text) and shown < cols:
        m = _ANSI_RE.match(text, i)
        if m:  # escapes cost no visible width, so copy them intact
            out.append(m.group())
            i = m.end()
            continue
        out.append(text[i])
        shown += 1
        i += 1
    return "".join(out) + C.RESET


def _write_line(line: str) -> None:
    """Draw a transient status line, overwriting whatever was there."""
    cols = width() - 1
    line = fit(line, cols)
    pad = max(0, cols - visible_len(line))
    sys.stdout.write("\r" + line + " " * pad)
    sys.stdout.flush()


def progress_bar(done: int, total: int, cells: int = 24) -> str:
    """A filled green bar, in the shape package installers use.

    Green reads as "proceeding normally" at a glance, which is the whole point:
    the bar exists so a long scan is visibly alive, not to convey precision.
    """
    total = max(1, total)
    done = max(0, min(done, total))
    filled = int(cells * done / total)
    pct = int(100 * done / total)
    bar = paint("█" * filled, C.GREEN) + paint("░" * (cells - filled), C.GREY)
    return f"{bar} {pct:3d}% {paint(f'{done}/{total}', C.GREY)}"


def indeterminate_bar(tick: int, cells: int = 24) -> str:
    """A bouncing block for work whose total is not known in advance.

    A directory walk cannot report a percentage without first walking the tree,
    so motion stands in for progress.
    """
    span = 5
    pos = tick % (2 * max(1, cells - span))
    if pos >= cells - span:
        pos = 2 * (cells - span) - pos
    cell = ["░"] * cells
    for i in range(pos, min(pos + span, cells)):
        cell[i] = "█"
    lit = "".join(cell)
    return paint(lit[: pos], C.GREY) + paint(lit[pos : pos + span], C.GREEN) + paint(
        lit[pos + span :], C.GREY
    )


def clear_line() -> None:
    """Erase the transient line so permanent output starts clean."""
    if _ENABLED:
        sys.stdout.write("\r" + " " * (width() - 1) + "\r")
        sys.stdout.flush()


def paint(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    return "".join(styles) + text + C.RESET


def set_color(enabled: bool) -> None:
    global _ENABLED
    _ENABLED = enabled


def width(default: int = 80) -> int:
    try:
        return max(48, shutil.get_terminal_size().columns)
    except OSError:
        return default


def rule(char: str = "─") -> str:
    return paint(char * width(), C.GREY)


def header(title: str, subtitle: str = "") -> None:
    print()
    print(paint(f" {title} ", C.BOLD, C.CYAN))
    if subtitle:
        print(paint(f" {subtitle}", C.GREY))
    print(rule())


def section(title: str) -> None:
    print()
    print(paint(f"▸ {title}", C.BOLD))


def kv(key: str, value: str, ok: bool | None = None) -> None:
    """Key-value line. `ok` tints the value green or red when supplied."""
    mark = ""
    color: tuple = ()
    if ok is True:
        mark, color = "✓ ", (C.GREEN,)
    elif ok is False:
        mark, color = "✗ ", (C.RED,)
    print(f"  {paint(key.ljust(22), C.GREY)} {mark}{paint(str(value), *color)}")


def info(msg: str) -> None:
    print(f"  {paint('i', C.BLUE)} {msg}")


def warn(msg: str) -> None:
    print(f"  {paint('!', C.YELLOW)} {msg}")


def error(msg: str) -> None:
    print(f"  {paint('✗', C.RED)} {msg}", file=sys.stderr)


def success(msg: str) -> None:
    print(f"  {paint('✓', C.GREEN)} {msg}")


def _truncate(text: str, limit: int) -> str:
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def print_finding(f: Finding, verbose: bool = False) -> None:
    color = SEV_COLOR[f.severity]
    tag = paint(f" {f.severity.label:<8} ", color)
    print(f"{tag} {paint(f.title, C.BOLD)}")
    print(f"           {paint('target', C.GREY)}  {_truncate(f.target, width() - 20)}")
    if f.detail:
        print(f"           {paint('reason', C.GREY)}  {_truncate(f.detail, width() - 20)}")
    if f.remediation:
        print(f"           {paint('action', C.GREY)}  {_truncate(f.remediation, width() - 20)}")
    if verbose and f.evidence:
        for k, v in f.evidence.items():
            print(f"           {paint(k[:6].ljust(6), C.GREY)}  {_truncate(str(v), width() - 20)}")
    print()


def summary(counts: dict[str, int], elapsed: float, scanned: int) -> None:
    print(rule())
    parts = []
    for sev in reversed(list(Severity)):
        n = counts.get(sev.label, 0)
        if n:
            parts.append(paint(f"{n} {sev.label.lower()}", SEV_COLOR[sev]))
    verdict = " · ".join(parts) if parts else paint("no findings", C.GREEN)
    print(f"  {paint('Result', C.BOLD)}   {verdict}")
    print(f"  {paint('Coverage', C.GREY)} {scanned} objects inspected in {elapsed:.1f}s")
    print()


class Console:
    """Verbose-by-default run log.

    A security scan is something you watch. Every phase, engine decision, and
    finding is printed as it happens, with elapsed time, so a long run stays
    legible and a hang is obvious. `--quiet` drops the running commentary but
    never the findings.
    """

    def __init__(self, verbose: bool = True, debug: bool = False) -> None:
        self.verbose = verbose
        self.debug = debug
        self.t0 = time.monotonic()
        self._phase = 0
        self._phase_total = 0

    def _stamp(self) -> str:
        el = time.monotonic() - self.t0
        return paint(f"[{int(el) // 60:02d}:{el % 60:05.2f}]", C.GREY)

    def phase(self, index: int, total: int, title: str) -> None:
        self._phase, self._phase_total = index, total
        clear_line()
        print()
        print(f"{self._stamp()} {paint(f'▸ Phase {index}/{total}', C.BOLD, C.CYAN)} {paint(title, C.BOLD)}")

    def step(self, msg: str) -> None:
        """A meaningful action. Shown unless quiet."""
        if self.verbose:
            clear_line()
            print(f"{self._stamp()}   {msg}")

    def detail(self, msg: str) -> None:
        """Fine-grained trace. Shown only with --debug."""
        if self.debug:
            print(f"{self._stamp()}   {paint(msg, C.GREY)}")

    def engine(self, name: str, state: str, ok: bool | None = None) -> None:
        if not self.verbose:
            return
        mark = "·"
        color: tuple = (C.GREY,)
        if ok is True:
            mark, color = "✓", (C.GREEN,)
        elif ok is False:
            mark, color = "✗", (C.RED,)
        print(f"{self._stamp()}   {paint(mark, *color)} {name.ljust(14)} {paint(state, C.GREY)}")

    def finding(self, f: Finding) -> None:
        """Print a finding the moment it is produced."""
        clear_line()
        color = SEV_COLOR[f.severity]
        print(f"{self._stamp()} {paint(f' {f.severity.label:<8} ', color)} {paint(f.title, C.BOLD)}")
        print(f"           {paint('target', C.GREY)}  {_truncate(f.target, width() - 22)}")
        if f.detail:
            print(f"           {paint('reason', C.GREY)}  {_truncate(f.detail, width() - 22)}")
        if f.remediation:
            print(f"           {paint('action', C.GREY)}  {_truncate(f.remediation, width() - 22)}")
        if self.debug and f.evidence:
            for k, v in f.evidence.items():
                print(f"           {paint(k[:6].ljust(6), C.GREY)}  {_truncate(str(v), width() - 22)}")

    def _spin(self) -> str:
        """Next animation frame.

        A moving glyph is the cheapest possible proof of life. A directory walk
        over shared storage can sit on one slow path for seconds, and without
        motion there is no way to tell that apart from a hang.
        """
        self._tick = getattr(self, "_tick", -1) + 1
        return SPINNER[self._tick % len(SPINNER)]

    def walking(self, dirs: int, found: int, current: str) -> None:
        """Live traversal status on one rewritten line.

        Throttled, because a directory walk fires far faster than a terminal can
        usefully redraw.
        """
        if not self.verbose:
            return
        now = time.monotonic()
        if now - getattr(self, "_walk_last", 0.0) < 0.12:
            return
        self._walk_last = now
        if not _ENABLED:
            # Without a TTY, carriage returns produce noise, so report sparsely.
            if dirs % 500 == 0:
                print(f"{self._stamp()}   walked {dirs} dirs, {found} candidates")
            return
        base = os.path.basename(current.rstrip("/")) or current
        self._tick = getattr(self, "_tick", -1) + 1
        line = (
            f"{self._stamp()} {paint(SPINNER[self._tick % len(SPINNER)], C.GREEN)} "
            f"walking  {indeterminate_bar(self._tick)} "
            f"{dirs} dirs · {found} found · {paint(base[:22], C.GREY)}"
        )
        _write_line(line)

    def counter(self, done: int, total: int, label: str, note: str = "") -> None:
        """Single-line progress that does not scroll the log away."""
        if not self.verbose or not _ENABLED:
            return
        now = time.monotonic()
        if now - getattr(self, "_count_last", 0.0) < 0.12 and done < total:
            return
        self._count_last = now
        line = (
            f"{self._stamp()} {paint(self._spin(), C.GREEN)} {label:<9}"
            f"{progress_bar(done, total)} {paint(note[:26], C.GREY)}"
        )
        _write_line(line)
        if done >= total:
            clear_line()


class Progress:
    """Simple progress bar that stays quiet on non-TTY output."""

    def __init__(self, total: int, label: str = "") -> None:
        self.total = max(1, total)
        self.label = label
        self.n = 0
        self._last = 0.0
        self._active = _ENABLED

    def step(self, n: int = 1, note: str = "") -> None:
        self.n += n
        if not self._active:
            return
        now = time.monotonic()
        # Throttle redraws so terminal I/O never becomes the bottleneck.
        if now - self._last < 0.08 and self.n < self.total:
            return
        self._last = now
        frac = min(1.0, self.n / self.total)
        avail = max(10, width() - len(self.label) - 34)
        filled = int(avail * frac)
        bar = "█" * filled + "░" * (avail - filled)
        tail = _truncate(note, 24).ljust(24)
        sys.stdout.write(
            f"\r  {self.label} {paint(bar, C.CYAN)} {int(frac * 100):3d}% {paint(tail, C.GREY)}"
        )
        sys.stdout.flush()

    def done(self) -> None:
        if self._active:
            sys.stdout.write("\r" + " " * width() + "\r")
            sys.stdout.flush()
