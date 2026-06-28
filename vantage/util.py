"""Shared utilities: logging, command execution, output formatting."""
from __future__ import annotations

import json
import os
import re
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
# Set by events_init so the low-level run() can log per-command exec events to the
# same stream WITHOUT every caller threading cfg through (drives the live web view).
_events_path_cur: str = ""


def events_init(path: str) -> None:
    """Truncate/create the NDJSON event log for a fresh run."""
    global _events_path_cur
    _events_path_cur = path or ""
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        open(path, "w").close()
    except OSError:
        pass


def _log_event(kind: str, **fields) -> None:
    """Append an event to the current run's NDJSON stream. Never raises."""
    if not _events_path_cur:
        return
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "event": kind}
    rec.update(fields)
    try:
        with _events_lock, open(_events_path_cur, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
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


# nmap's runtime progress lines (emitted with --stats-every), e.g.
#   "SYN Stealth Scan Timing: About 47.13% done; ETC: 14:23 (0:00:34 remaining)"
# We surface the live percentage instead of a blind 'still running' heartbeat.
_NMAP_PCT = re.compile(r"About\s+([\d.]+)%\s+done(?:.*?\(([\d:]+)\s+remaining\))?", re.I)
_NMAP_PHASE = re.compile(r"^(.*?)\s+Timing:\s*About", re.I)


def _parse_nmap_progress(line: str) -> dict | None:
    """Parse a single nmap stats line into {percent, [remaining], [phase]}.
    Returns None for any line that isn't a progress update."""
    m = _NMAP_PCT.search(line)
    if not m:
        return None
    out: dict = {"percent": float(m.group(1))}
    if m.group(2):
        out["remaining"] = m.group(2)
    pm = _NMAP_PHASE.search(line.strip())
    if pm and pm.group(1).strip():
        out["phase"] = pm.group(1).strip()
    return out


def _format_progress(tool: str, pr: dict) -> str:
    s = f"{tool}: {pr['percent']:.0f}% done"
    if pr.get("remaining"):
        s += f", ~{pr['remaining']} remaining"
    if pr.get("phase"):
        s += f" ({pr['phase']})"
    return s


def _run_streaming(cmd: list[str], timeout: int, on_line) -> tuple[int, str, str]:
    """Run `cmd` with live output: each line of stdout/stderr is accumulated AND
    passed to `on_line` as it arrives (so a parser can surface progress in real
    time). Returns the same (rc, stdout, stderr) shape as a buffered run; rc=124
    on timeout. Two reader threads avoid the classic pipe-buffer deadlock."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    out_lines: list[str] = []
    err_lines: list[str] = []

    def _reader(stream, sink):
        try:
            for line in stream:
                sink.append(line)
                try:
                    on_line(line.rstrip("\n"))
                except Exception:  # noqa: BLE001 — a parser bug must not kill the scan
                    pass
        finally:
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass

    t_out = threading.Thread(target=_reader, args=(proc.stdout, out_lines), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, err_lines), daemon=True)
    t_out.start()
    t_err.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        t_out.join(timeout=2)
        t_err.join(timeout=2)
        return 124, "".join(out_lines), "timeout"
    t_out.join(timeout=2)
    t_err.join(timeout=2)
    return proc.returncode, "".join(out_lines), "".join(err_lines)


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
            # Keep the event log 'warm' so the web dashboard can tell a slow-but-
            # alive tool (a long nmap) from a dead/killed run that stops writing.
            _log_event("exec_heartbeat", tool=self.label, waited=int(waited))

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()


def run(cmd: list[str], timeout: int = 300, capture: bool = True,
        progress: bool = False) -> tuple[int, str, str]:
    """Run a command. Returns (returncode, stdout, stderr).
    Never raises on non-zero exit; returns the captured output instead.

    With `progress=True` the call is streamed instead of buffered: nmap stats
    lines (emitted by --stats-every) are parsed live and surfaced as real
    percentage updates + 'exec_progress' events, replacing the blind heartbeat.
    Output is still fully accumulated and returned unchanged, so callers see no
    difference. Requires `capture` (the default).

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
    # Emit a live 'exec_start' so the web dashboard can show what's running now.
    _log_event("exec_start", tool=cmd[0], cmd=" ".join(cmd))
    start = time.time()
    rc = None
    use_stream = progress and capture
    # Heartbeat only for calls we expect could be long — and not when streaming,
    # which surfaces real progress instead.
    hb = None if use_stream else (_Heartbeat(cmd[0], interval=30.0) if timeout >= 60 else None)
    try:
        if use_stream:
            tool = cmd[0]

            def _on_line(line: str):
                pr = _parse_nmap_progress(line)
                if pr:
                    info(f"  {_format_progress(tool, pr)}")
                    _log_event("exec_progress", tool=tool, **pr)

            rc, out, errout = _run_streaming(cmd, timeout, _on_line)
            dur = time.time() - start
            if rc == 124:
                warn(f"timed out after {timeout}s: {tool}")
            elif dur > 1:
                info(f"  -> finished in {dur:.1f}s (rc={rc})")
            return rc, out, errout
        if hb:
            hb.__enter__()
        proc = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        dur = time.time() - start
        rc = proc.returncode
        if dur > 1:
            info(f"  -> finished in {dur:.1f}s (rc={proc.returncode})")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        err(f"tool not found: {cmd[0]}")
        rc = 127
        return 127, "", "tool-not-found"
    except subprocess.TimeoutExpired:
        warn(f"timed out after {timeout}s: {cmd[0]}")
        rc = 124
        return 124, "", "timeout"
    finally:
        if hb:
            hb.__exit__()
        _log_event("exec_end", tool=cmd[0], rc=rc, dur=round(time.time() - start, 1))


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
