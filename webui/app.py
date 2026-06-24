"""ctfauto web dashboard — a READ-ONLY viewer over the loot/ output directory.

It runs NO scans and changes nothing on disk. It reads the artifacts ctfauto
already writes (report_*.json / .md, events_*.ndjson, index_*.md) and renders
them: a target overview with the ranked priority leads, the full report as HTML,
and the run's event timeline.

Run it:
    pip install -r webui/requirements.txt
    CTFAUTO_LOOT=/path/to/loot python webui/app.py      # or just `python webui/app.py`

Then open http://127.0.0.1:5000. Point it at a loot dir with $CTFAUTO_LOOT or
--loot; it defaults to ./loot.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

from flask import Flask, abort, render_template, jsonify
import markdown as md

# Make the ctfauto package importable so we reuse its canonical lead-ranking
# instead of duplicating it here (single source of truth).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from ctfauto.modules.report import _priority_leads  # noqa: E402
from types import SimpleNamespace  # noqa: E402

app = Flask(__name__)

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
    return app.config.get("LOOT_DIR") or os.environ.get("CTFAUTO_LOOT") or \
        os.path.join(os.getcwd(), "loot")


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
    """Reuse ctfauto's canonical ranking by reconstructing the minimal shapes it
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
    active, last_start, phase = 0, None, ""
    for e in events:
        ev = e.get("event", "")
        if ev == "exec_start":
            active += 1
            last_start = e
        elif ev == "exec_end":
            active = max(0, active - 1)
        elif ev.endswith("_done") or ev.endswith("_start"):
            phase = ev
    stale = age is not None and age > LIVE_STALE_SECONDS
    live = (not done) and (not stale)
    running = live and active > 0
    current = None
    if running and last_start:
        current = {"tool": last_start.get("tool", ""), "cmd": last_start.get("cmd", ""),
                   "ts": last_start.get("ts", "")}
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
@app.route("/")
def index():
    return render_template("index.html", targets=list_targets(),
                           sweeps=list_sweeps(), live=list_live(),
                           stopped=list_stopped(), loot=loot_dir())


@app.route("/live/<slug>")
def live(slug: str):
    if not _SLUG_RE.match(slug):
        abort(404)
    events = load_events(slug)
    if not events:
        abort(404)
    return render_template("live.html", slug=slug, events=events,
                           status=_scan_status(events, _events_age(slug)))


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
    return jsonify({"events": events, "status": _scan_status(events, _events_age(slug))})


def main(argv=None):
    p = argparse.ArgumentParser(description="ctfauto read-only web dashboard")
    p.add_argument("--loot", default="", help="Path to the loot dir (else $CTFAUTO_LOOT or ./loot)")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: localhost only)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)
    if args.loot:
        app.config["LOOT_DIR"] = args.loot
    print(f"[ctfauto-webui] serving loot from: {loot_dir()}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
