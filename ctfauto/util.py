"""Shared utilities: logging, command execution, output formatting."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Auto-disable ANSI colour when output isn't a TTY (logs/pipes stay clean).
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str) -> str:
    return code if _USE_COLOR else ""


# ANSI colors (no dependency on external libs). Empty strings when colour off.
class C:
    RESET = _c("\033[0m")
    BOLD = _c("\033[1m")
    RED = _c("\033[31m")
    GREEN = _c("\033[32m")
    YELLOW = _c("\033[33m")
    BLUE = _c("\033[34m")
    CYAN = _c("\033[36m")
    GREY = _c("\033[90m")


# Worker threads all write to stdout; serialise to avoid interleaved lines (#19).
_print_lock = threading.Lock()


def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _emit(msg: str, stream=None) -> None:
    with _print_lock:
        print(msg, file=stream) if stream else print(msg)


def info(msg: str) -> None:
    _emit(f"{C.GREY}[{stamp()}]{C.RESET} {C.BLUE}[*]{C.RESET} {msg}")


def good(msg: str) -> None:
    _emit(f"{C.GREY}[{stamp()}]{C.RESET} {C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    _emit(f"{C.GREY}[{stamp()}]{C.RESET} {C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    _emit(f"{C.GREY}[{stamp()}]{C.RESET} {C.RED}[-]{C.RESET} {msg}", stream=sys.stderr)


def banner(text: str) -> None:
    bar = "=" * (len(text) + 4)
    _emit(f"\n{C.BOLD}{C.CYAN}{bar}\n  {text}\n{bar}{C.RESET}")


# --- warn-once (issue #18) ---------------------------------------------------
_warned_once: set[str] = set()


def warn_once(key: str, msg: str) -> None:
    """Emit a warning only the first time for a given key (e.g. a tool name)."""
    if key in _warned_once:
        return
    _warned_once.add(key)
    warn(msg)


# --- NDJSON event log (issue #25) --------------------------------------------
_events_lock = threading.Lock()


def events_init(path: str) -> None:
    """Truncate/create the NDJSON event log for a fresh run."""
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        open(path, "w").close()
    except OSError:
        pass


def event(cfg, kind: str, **fields) -> None:
    """Append one NDJSON event. cfg may be a RunConfig (uses cfg.events_path)
    or a path string. Never raises — telemetry must not break a run."""
    path = getattr(cfg, "events_path", cfg if isinstance(cfg, str) else "")
    if not path:
        return
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "event": kind}
    rec.update(fields)
    try:
        with _events_lock, open(path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass


# --- global wall-clock budget (issue #17) ------------------------------------
# A single per-run deadline. When set, run() clamps each command's timeout to the
# remaining budget and phases can check budget_exceeded() to stop early instead of
# grinding for an unbounded total. 0/None = unlimited (back-compat default).
_deadline: float | None = None


def start_budget(seconds: float | None) -> None:
    """Begin a wall-clock budget of `seconds` from now (None/<=0 disables)."""
    global _deadline
    _deadline = (time.time() + seconds) if seconds and seconds > 0 else None


def budget_remaining() -> float | None:
    """Seconds left in the budget, or None if no budget is set."""
    if _deadline is None:
        return None
    return max(0.0, _deadline - time.time())


def budget_exceeded() -> bool:
    rem = budget_remaining()
    return rem is not None and rem <= 0


class _Heartbeat:
    """Emit a 'still running (Ns)' line every `interval`s for a long call (#17)."""
    def __init__(self, label: str, interval: float = 30.0):
        self.label = label
        self.interval = interval
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        waited = 0.0
        while not self._stop.wait(self.interval):
            waited += self.interval
            info(f"  …still running {self.label} ({int(waited)}s)")

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()


def run(cmd: list[str], timeout: int = 300, capture: bool = True) -> tuple[int, str, str]:
    """Run a command. Returns (returncode, stdout, stderr).
    Never raises on non-zero exit; returns the captured output instead.

    Honours the global wall-clock budget (#17): the effective timeout is the
    smaller of the requested timeout and the remaining budget, and a call that's
    refused because the budget is spent returns rc=125 without executing."""
    rem = budget_remaining()
    if rem is not None:
        if rem <= 0:
            warn(f"global time budget exhausted — skipping: {cmd[0]}")
            return 125, "", "budget-exhausted"
        timeout = int(min(timeout, rem)) or 1
    info(f"exec: {C.GREY}{' '.join(cmd)}{C.RESET}")
    start = time.time()
    # Heartbeat only for calls we expect could be long.
    hb = _Heartbeat(cmd[0], interval=30.0) if timeout >= 60 else None
    try:
        if hb:
            hb.__enter__()
        proc = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        dur = time.time() - start
        if dur > 1:
            info(f"  -> finished in {dur:.1f}s (rc={proc.returncode})")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        err(f"tool not found: {cmd[0]}")
        return 127, "", "tool-not-found"
    except subprocess.TimeoutExpired:
        warn(f"timed out after {timeout}s: {cmd[0]}")
        return 124, "", "timeout"
    finally:
        if hb:
            hb.__exit__()


def parallel_map(fn, items, workers: int = 4):
    """Run fn over items concurrently; return results in completion order.
    Exceptions in a worker are caught and surfaced as warnings, not fatal."""
    results = []
    if workers <= 1 or len(items) <= 1:
        for it in items:
            try:
                results.append(fn(it))
            except Exception as e:  # noqa: BLE001
                err(f"worker error on {it!r}: {e}")
        return results
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                err(f"worker error on {futs[fut]!r}: {e}")
    return results


# --- simple JSON state for resume support ------------------------------------
def state_path(out_dir: str, target: str) -> str:
    return os.path.join(out_dir, f"state_{target.replace('/', '_')}.json")


def load_state(out_dir: str, target: str) -> dict:
    p = state_path(out_dir, target)
    if os.path.exists(p):
        try:
            with open(p) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}
    return {}


def save_state(out_dir: str, target: str, state: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(state_path(out_dir, target), "w") as f:
        json.dump(state, f, indent=2)
