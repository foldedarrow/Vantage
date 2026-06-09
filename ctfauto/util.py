"""Shared utilities: logging, command execution, output formatting."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ANSI colors (no dependency on external libs)
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREY = "\033[90m"


def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    print(f"{C.GREY}[{stamp()}]{C.RESET} {C.BLUE}[*]{C.RESET} {msg}")


def good(msg: str) -> None:
    print(f"{C.GREY}[{stamp()}]{C.RESET} {C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.GREY}[{stamp()}]{C.RESET} {C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.GREY}[{stamp()}]{C.RESET} {C.RED}[-]{C.RESET} {msg}", file=sys.stderr)


def banner(text: str) -> None:
    bar = "=" * (len(text) + 4)
    print(f"\n{C.BOLD}{C.CYAN}{bar}\n  {text}\n{bar}{C.RESET}")


def run(cmd: list[str], timeout: int = 300, capture: bool = True) -> tuple[int, str, str]:
    """Run a command. Returns (returncode, stdout, stderr).
    Never raises on non-zero exit; returns the captured output instead."""
    info(f"exec: {C.GREY}{' '.join(cmd)}{C.RESET}")
    start = time.time()
    try:
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
