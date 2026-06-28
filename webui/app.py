"""vantage web dashboard — a READ-ONLY viewer over the loot/ output directory.

It runs NO scans and changes nothing on disk. It reads the artifacts vantage
already writes (report_*.json / .md, events_*.ndjson, index_*.md) and renders
them: a target overview with the ranked priority leads, the full report as HTML,
and the run's event timeline.

Run it:
    pip install -r webui/requirements.txt
    VANTAGE_LOOT=/path/to/loot python webui/app.py      # or just `python webui/app.py`

Then open http://127.0.0.1:5000. Point it at a loot dir with $VANTAGE_LOOT or
--loot; it defaults to ./loot.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time

from flask import Flask, abort, render_template, jsonify, request, redirect, url_for
import markdown as md

# Make the vantage package importable so we reuse its canonical lead-ranking
# instead of duplicating it here (single source of truth).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from vantage.modules.report import _priority_leads  # noqa: E402
from types import SimpleNamespace  # noqa: E402

app = Flask(__name__)

_RUN_PY = os.path.join(_REPO_ROOT, "run.py")
# slug -> Popen for scans launched from the GUI (so we can stop them).
_procs: dict = {}

# A loot slug is the filesystem-safe target token (target with '/' -> '_'); it is
# validated against this charset AND must resolve inside the loot dir (no traversal).
_SLUG_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

_MD_EXTENSIONS = ["tables", "fenced_code", "toc", "sane_lists"]

# A scan whose event log hasn't been written to in this many seconds is treated as
# dead/stopped, not live. A genuinely-running scan emits exec_start/exec_end and a
# 30s heartbeat during long tools, so a live log is never quiet this long; a
# Ctrl-C'd run stops writing and goes stale within the window.
LIVE_STALE_SECONDS = 90


def loot_dir() -> str:
    return app.config.get("LOOT_DIR") or os.environ.get("VANTAGE_LOOT") \
        or os.environ.get("CTFAUTO_LOOT") or os.path.join(os.getcwd(), "loot")


def _safe_path(*parts: str) -> str:
    """Join under loot_dir and refuse anything that escapes it (path traversal)."""
    root = os.path.realpath(loot_dir())
    full = os.path.realpath(os.path.join(root, *parts))
    if full != root and not full.startswith(root + os.sep):
        abort(404)
    return full


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# --- discovery ---------------------------------------------------------------
def list_targets() -> list[dict]:
    """One row per report_<slug>.json found in the loot dir."""
    root = loot_dir()
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        if not (name.startswith("report_") and name.endswith(".json")):
            continue
        slug = name[len("report_"):-len(".json")]
        data = _load_report_json(slug)
        if data is None:
            continue
        out.append(_summarize(slug, data))
    return out


def list_sweeps() -> list[dict]:
    root = loot_dir()
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        if name.startswith("index_") and name.endswith(".md"):
            out.append({"slug": name[len("index_"):-len(".md")], "file": name})
    return out


def _load_report_json(slug: str) -> dict | None:
    if not _SLUG_RE.match(slug):
        return None
    path = _safe_path(f"report_{slug}.json")
    raw = _read(path)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _leads(data: dict) -> list[str]:
    """Reuse vantage's canonical ranking by reconstructing the minimal shapes it
    reads (host.nse_cves, enum.findings[.tags/.service_port/.summary],
    exploits.candidates[.high_confidence/.msf_module/.port/.title/.category])."""
    host = SimpleNamespace(nse_cves=(data.get("host", {}) or {}).get("nse_cves", []) or [])
    enum = SimpleNamespace(findings=[
        SimpleNamespace(tags=f.get("tags") or {}, service_port=f.get("service_port", 0),
                        summary=f.get("summary", ""))
        for f in data.get("enumeration", [])])
    exploits = SimpleNamespace(candidates=[
        SimpleNamespace(high_confidence=c.get("high_confidence", False),
                        msf_module=c.get("msf_module", ""), port=c.get("port", 0),
                        title=c.get("title", ""), category=c.get("category", ""))
        for c in data.get("exploit_candidates", [])])
    return _priority_leads(host, enum, exploits)


def _summarize(slug: str, data: dict) -> dict:
    host = data.get("host", {}) or {}
    services = (host.get("services") or []) + (host.get("udp_services") or [])
    leads = _leads(data)
    return {
        "slug": slug,
        "target": data.get("target", slug),
        "klass": data.get("classification", ""),
        "profile": data.get("profile", ""),
        "generated": data.get("generated", ""),
        "n_services": len(services),
        "n_findings": len(data.get("enumeration", [])),
        "n_candidates": len(data.get("exploit_candidates", [])),
        "leads": leads,
        "top_leads": [_md_inline(b) for b in leads[:3]],
    }


def _md_inline(text: str) -> str:
    """Render a single markdown bullet's inline formatting (**bold**, `code`)."""
    html = md.markdown(text, extensions=_MD_EXTENSIONS)
    # strip the wrapping <p> markdown adds around a single line
    return re.sub(r"^<p>(.*)</p>\s*$", r"\1", html, flags=re.S)


def load_events(slug: str) -> list[dict]:
    if not _SLUG_RE.match(slug):
        return []
    raw = _read(_safe_path(f"events_{slug}.ndjson"))
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def _events_age(slug: str) -> float | None:
    """Seconds since the event log was last written, or None if it's missing."""
    if not _SLUG_RE.match(slug):
        return None
    try:
        return max(0.0, time.time() - os.path.getmtime(_safe_path(f"events_{slug}.ndjson")))
    except OSError:
        return None


def _scan_status(events: list[dict], age: float | None = None) -> dict:
    """Derive status from the event stream + how recently it was written.
    A scan is LIVE only if it hasn't finished AND its log is still being written
    (age under the stale threshold). A Ctrl-C'd/killed run stops writing, so it
    goes stale and is reported as stopped — not live."""
    done = any(e.get("event") in ("run_done", "run_abort", "sweep_done") for e in events)
    active, last_start, phase, last_progress = 0, None, "", None
    for e in events:
        ev = e.get("event", "")
        if ev == "exec_start":
            active += 1
            last_start = e
            last_progress = None        # new tool — reset any prior progress
        elif ev == "exec_progress":
            last_progress = e           # live nmap percentage for the running tool
        elif ev == "exec_end":
            active = max(0, active - 1)
            last_progress = None
        elif ev.endswith("_done") or ev.endswith("_start"):
            phase = ev
    stale = age is not None and age > LIVE_STALE_SECONDS
    live = (not done) and (not stale)
    running = live and active > 0
    current = None
    if running and last_start:
        current = {"tool": last_start.get("tool", ""), "cmd": last_start.get("cmd", ""),
                   "ts": last_start.get("ts", "")}
        if last_progress:
            current["progress"] = {"percent": last_progress.get("percent"),
                                   "remaining": last_progress.get("remaining"),
                                   "phase": last_progress.get("phase")}
    return {"live": live, "running": running, "done": done, "stale": stale,
            "current": current, "phase": phase, "n_events": len(events),
            "age": None if age is None else round(age)}


def _list_inprogress() -> list[dict]:
    """All scans with an event log that hasn't reached a terminal event, each with
    age-aware status so the caller can split genuinely-live from stopped/stale."""
    root = loot_dir()
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        if not (name.startswith("events_") and name.endswith(".ndjson")):
            continue
        slug = name[len("events_"):-len(".ndjson")]
        events = load_events(slug)
        if not events:
            continue
        status = _scan_status(events, _events_age(slug))
        if status["done"]:
            continue            # finished -> shown under Targets
        out.append({"slug": slug, "status": status,
                    "last": events[-1].get("event", "")})
    return out


def list_live() -> list[dict]:
    """Only the genuinely-running scans (log still being written)."""
    return [s for s in _list_inprogress() if s["status"]["live"]]


def list_stopped() -> list[dict]:
    """Started-but-stopped scans (e.g. Ctrl-C'd) — incomplete and no longer live."""
    return [s for s in _list_inprogress() if not s["status"]["live"]]


# --- routes ------------------------------------------------------------------
@app.context_processor
def _inject_nav():
    """Expose the loot dir + live-scan count to every template so the nav bar
    can render its path chip and the 'Ongoing' badge on any page."""
    try:
        return {"loot": loot_dir(), "nav_live_count": len(list_live())}
    except Exception:  # noqa: BLE001 — the nav must never break a page render
        return {"loot": "", "nav_live_count": 0}


@app.route("/")
def index():
    return render_template("index.html", targets=list_targets(),
                           sweeps=list_sweeps(), live=list_live(),
                           stopped=list_stopped(), nav="dashboard")


@app.route("/reports")
def reports():
    return render_template("reports.html", targets=list_targets(), nav="reports")


@app.route("/ongoing")
def ongoing():
    return render_template("ongoing.html", live=list_live(), nav="ongoing")


@app.route("/previous")
def previous():
    return render_template("previous.html", stopped=list_stopped(), nav="previous")


@app.route("/sweeps")
def sweeps():
    return render_template("sweeps.html", sweeps=list_sweeps(), nav="sweeps")


def _proc_alive(slug: str) -> bool:
    p = _procs.get(slug)
    return bool(p and p.poll() is None)


@app.route("/live/<slug>")
def live(slug: str):
    if not _SLUG_RE.match(slug):
        abort(404)
    events = load_events(slug)
    # A scan we just launched may not have written its log yet — don't 404 it.
    if not events and not _proc_alive(slug):
        abort(404)
    return render_template("live.html", slug=slug, events=events,
                           status=_scan_status(events, _events_age(slug)),
                           can_stop=_proc_alive(slug))


@app.route("/report/<slug>")
def report(slug: str):
    data = _load_report_json(slug)
    if data is None:
        abort(404)
    md_html = md.markdown(_read(_safe_path(f"report_{slug}.md")),
                          extensions=_MD_EXTENSIONS)
    return render_template("report.html", meta=_summarize(slug, data),
                           leads=[_md_inline(b) for b in _leads(data)],
                           report_html=md_html, events=load_events(slug))


@app.route("/sweep/<slug>")
def sweep(slug: str):
    if not _SLUG_RE.match(slug):
        abort(404)
    body = _read(_safe_path(f"index_{slug}.md"))
    if not body:
        abort(404)
    return render_template("sweep.html", slug=slug,
                           sweep_html=md.markdown(body, extensions=_MD_EXTENSIONS))


@app.route("/api/events/<slug>")
def api_events(slug: str):
    """JSON event feed the live view polls: the full event list plus derived
    status (running / current command / done)."""
    events = load_events(slug)
    return jsonify({"events": events, "can_stop": _proc_alive(slug),
                    "status": _scan_status(events, _events_age(slug))})


# --- launching scans from the GUI (localhost only) --------------------------
# The form maps 1:1 onto run.py flags. We build an ARGV (never a shell string) and
# invoke the real CLI, so its authorization gate / scope file / external-refusal
# still apply. Booleans -> presence flags; valued fields are validated.
_BOOL_FLAGS = {
    "aggressive": "--aggressive", "cloud": "--cloud", "allow_cloud": "--allow-cloud",
    "no_udp": "--no-udp", "no_nse_vuln": "--no-nse-vuln", "resume": "--resume",
    "connect": "--connect", "no_fragment": "--no-fragment", "add_hosts": "--add-hosts",
}
# (form field, flag, kind) — kind validates the value.
_VALUE_FIELDS = [
    ("max_time", "--max-time", "int"), ("parallelism", "--parallelism", "int"),
    ("max_rate", "--max-rate", "int"), ("source_port", "--source-port", "int"),
    ("scan_delay", "--scan-delay", "token"), ("decoys", "--decoys", "token"),
    ("hostname", "--hostname", "token"), ("cloud_name", "--cloud-name", "token"),
    ("scope_file", "--scope-file", "path"),
]
_TOKEN_RE = re.compile(r"^[A-Za-z0-9.\-_:,/ ]+$")   # no shell metacharacters


def _is_localhost() -> bool:
    return (request.remote_addr or "") in ("127.0.0.1", "::1", "localhost")


def _valid_target(t: str) -> bool:
    t = t.strip()
    if not t or len(t) > 255:
        return False
    try:
        ipaddress.ip_network(t, strict=False)   # IP or CIDR
        return True
    except ValueError:
        pass
    return bool(re.match(r"^[A-Za-z0-9.\-]+$", t))   # hostname


def _build_argv(form) -> tuple[list, str]:
    """Build the run.py argv from the submitted form. Raises ValueError on bad input."""
    target = (form.get("target") or "").strip()
    if not _valid_target(target):
        raise ValueError("Enter a valid IP, hostname, or CIDR.")
    argv = [sys.executable, _RUN_PY, target, "--out-dir", loot_dir()]

    profile = form.get("profile", "auto")
    if profile == "stealth":
        argv.append("--stealth")
    elif profile in ("lab", "gentle"):
        argv += ["--profile", profile]

    # The GUI can't answer the interactive prompt, so 'authorized' -> --yes. The
    # checkbox is required (enforced client- and server-side).
    if not form.get("authorized"):
        raise ValueError("You must confirm you're authorized to test this target.")
    argv.append("--yes")
    if form.get("allow_external"):
        argv.append("--allow-external")

    for field, flag in _BOOL_FLAGS.items():
        if form.get(field):
            argv.append(flag)

    for field, flag, kind in _VALUE_FIELDS:
        v = (form.get(field) or "").strip()
        if not v:
            continue
        if kind == "int":
            if not v.isdigit():
                raise ValueError(f"{field.replace('_', ' ')} must be a number.")
            argv += [flag, v]
        elif kind == "token":
            if not _TOKEN_RE.match(v):
                raise ValueError(f"Invalid characters in {field.replace('_', ' ')}.")
            argv += [flag, v]
        elif kind == "path":
            argv += [flag, v]
    return argv, target


def _spawn_scan(argv: list, slug: str) -> None:
    log_path = os.path.join(loot_dir(), f"webrun_{slug}.log")
    os.makedirs(loot_dir(), exist_ok=True)
    logf = open(log_path, "ab")
    # start_new_session so we can signal the whole tool tree (nmap children) on stop.
    p = subprocess.Popen(argv, cwd=_REPO_ROOT, stdout=logf, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    _procs[slug] = p


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if not _is_localhost():
        abort(403)
    if request.method == "POST":
        try:
            argv, target = _build_argv(request.form)
        except ValueError as e:
            return render_template("scan.html", error=str(e), form=request.form,
                                   is_root=_is_root(), loot=loot_dir()), 400
        slug = target.replace("/", "_")
        _spawn_scan(argv, slug)
        return redirect(url_for("live", slug=slug))
    return render_template("scan.html", error=None, form={}, is_root=_is_root(),
                           loot=loot_dir())


@app.route("/scan/<slug>/stop", methods=["POST"])
def scan_stop(slug: str):
    if not _is_localhost():
        abort(403)
    if not _SLUG_RE.match(slug):
        abort(404)
    p = _procs.get(slug)
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGINT)   # Ctrl-C the whole group
        except (ProcessLookupError, PermissionError, OSError):
            pass
    return redirect(url_for("live", slug=slug))


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def main(argv=None):
    p = argparse.ArgumentParser(description="vantage read-only web dashboard")
    p.add_argument("--loot", default="", help="Path to the loot dir (else $VANTAGE_LOOT or ./loot)")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: localhost only)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)
    if args.loot:
        app.config["LOOT_DIR"] = args.loot
    print(f"[vantage-webui] serving loot from: {loot_dir()}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
