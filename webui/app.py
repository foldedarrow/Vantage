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


# --- routes ------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", targets=list_targets(),
                           sweeps=list_sweeps(), loot=loot_dir())


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
    """JSON event feed (a frontend could poll this for a live view)."""
    return jsonify(load_events(slug))


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
