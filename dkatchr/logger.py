"""
Logging — tqdm-aware so the progress bar stays intact when active.

When the bar is on (`set_quiet_repos(True)`), per-repo INFO lines are
suppressed and top-level/error lines route through `tqdm.write` so they
print above the bar without disrupting it.

When a log file is configured via `set_log_file(path)`, every line that
goes to stderr is also appended to that file (with an ISO timestamp).
Used by the CLI's optional `--log-file` flag.
"""

import os
import re
import sys
import threading
from datetime import datetime, timezone

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    tqdm = None  # type: ignore


_QUIET_REPOS = False

_LOG_FILE_HANDLE = None        # file object or None
_LOG_FILE_LOCK   = threading.Lock()

# Strip ANSI color codes when writing to a file — the terminal interprets
# them but `cat output.log` shows raw escape sequences.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def set_quiet_repos(value: bool) -> None:
    global _QUIET_REPOS
    _QUIET_REPOS = bool(value)


def is_quiet_repos() -> bool:
    return _QUIET_REPOS


def set_log_file(path: str | None) -> None:
    """
    Tee every log() / repo_log() line to `path` (in addition to stderr).

    Pass None to disable. Safe to call multiple times — replaces the
    previous handle. The parent directory is created if missing.
    """
    global _LOG_FILE_HANDLE
    with _LOG_FILE_LOCK:
        if _LOG_FILE_HANDLE is not None:
            try:
                _LOG_FILE_HANDLE.close()
            except Exception:
                pass
            _LOG_FILE_HANDLE = None

        if path:
            try:
                parent = os.path.dirname(os.path.abspath(path))
                if parent:
                    os.makedirs(parent, exist_ok=True)
                _LOG_FILE_HANDLE = open(path, "a", encoding="utf-8")
            except Exception as e:
                # Don't crash on a bad path — log the failure to stderr and
                # carry on. The CLI keeps running, just without a log file.
                print(f"[!] --log-file disabled: cannot open {path}: {e}",
                      file=sys.stderr, flush=True)
                _LOG_FILE_HANDLE = None


def _write_to_file(msg: str) -> None:
    """Best-effort append. Never raises."""
    handle = _LOG_FILE_HANDLE
    if handle is None:
        return
    try:
        stamped = f"{datetime.now(timezone.utc).isoformat()} {_ANSI_RE.sub('', msg)}\n"
        with _LOG_FILE_LOCK:
            handle.write(stamped)
            handle.flush()
    except Exception:
        pass


def log(msg: str) -> None:
    """Top-level / setup / error line — always prints."""
    if _QUIET_REPOS and HAS_TQDM:
        tqdm.write(msg, file=sys.stderr)
    else:
        print(msg, file=sys.stderr, flush=True)
    _write_to_file(msg)


def repo_log(msg: str) -> None:
    """Per-repo INFO line — suppressed when the progress bar is active."""
    if not _QUIET_REPOS:
        print(msg, file=sys.stderr, flush=True)
    # Even when the bar suppresses these on stdout, write them to the file
    # if one is configured — that's the whole point of `--log-file`.
    _write_to_file(msg)


# ---- Reachability display --------------------------------------------------

_REACHABILITY_COLORS = {
    "REACHABLE": "\033[91m",   # red    — needs attention
    "UNUSED":    "\033[92m",   # green  — good news, the user wants to see this
    "UNKNOWN":   "\033[93m",   # yellow — couldn't determine
}
_ANSI_RESET = "\033[0m"


def reachability_badge(label: str) -> str:
    """Return an ANSI-coloured [LABEL] string for terminal output."""
    color = _REACHABILITY_COLORS.get(label, "")
    return f"{color}[{label}]{_ANSI_RESET}" if label else ""
