"""Optional local-LLM advisory pass (read-only, single-shot).

This borrows METATRON's best idea — let a model turn raw findings into a
prioritized, explained narrative — while dropping the parts that conflict with
vantage's design:

  * ADVISORY ONLY. The model receives the findings and is asked to explain and
    triage them. There is NO [TOOL:]/[SEARCH:] dispatch loop back to a shell
    (METATRON's run_tool_by_command lets the model emit arbitrary argv to nmap/
    nikto). The model here cannot cause vantage to run anything, so vantage's
    "fires nothing" guarantee is preserved.
  * LOCAL + soft dependency. It talks to Ollama on localhost via stdlib urllib
    (no `requests`). If Ollama isn't running, the pass is skipped with a hint —
    exactly how vantage treats any missing tool.
  * SECRET-REDACTED input. The findings summary is run through the report's
    redactor before it leaves the process.
  * STRUCTURED input, not raw dumps. The model is fed vantage's already-ranked
    leads + service/candidate summary, not megabytes of raw tool output — so no
    second "compress with the LLM" round-trip is needed.

Off by default. Enable with --ai. Model via --ai-model or $VANTAGE_AI_MODEL
(default 'llama3.1'); endpoint via $VANTAGE_OLLAMA_URL (default localhost:11434).
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from ..config import RunConfig
from ..modules.recon import HostResult
from ..modules.enumerate import EnumResult
from ..modules.exploit import ExploitResult
from ..util import info, good, warn, warn_once, budget_remaining

_OLLAMA_URL = os.environ.get("VANTAGE_OLLAMA_URL", "http://127.0.0.1:11434")
_DEFAULT_MODEL = os.environ.get("VANTAGE_AI_MODEL", "llama3.1")

_SYSTEM = """You are a read-only security analyst helping write an AUTHORIZED \
reconnaissance report. Another tool already collected the structured findings \
below. Your job is ONLY to analyze and explain them:

- Prioritize the findings by exploitability and impact.
- For each significant one, give the risk in 1-2 sentences and a concrete \
remediation.
- Call out relationships between findings (e.g. an exposed .git plus a CMS).
- Finish with an overall rating on its own line: RISK_LEVEL: CRITICAL|HIGH|MEDIUM|LOW

Hard rules:
- You did NOT and CANNOT run any tools, commands, scans, or exploits. Never \
claim to have tested, accessed, or exploited anything.
- Do not invent CVEs, versions, services, or hosts that are not in the data.
- If evidence is weak or inconclusive, say so and rate it low.
- Plain prose and short lists. No tool-call tags, no markdown headers."""


def _build_summary(cfg: RunConfig, host: HostResult, enum: EnumResult,
                   exploits: ExploitResult) -> str:
    """Compact, model-friendly digest of the findings. Reuses the report's own
    lead ranking so the model triages from the same signal the report shows."""
    from .report import _priority_leads  # local import avoids a cycle

    L = [f"TARGET: {cfg.hostname or cfg.target}  (classification: "
         f"{getattr(cfg, 'klass', '?')})"]
    if host.os_guess:
        L.append(f"OS GUESS: {host.os_guess}")

    svcs = host.services + getattr(host, "udp_services", [])
    if svcs:
        L.append("OPEN SERVICES:")
        for s in svcs:
            L.append(f"  - {s.port}/{s.proto} {s.name} {s.banner}".rstrip())

    cves = getattr(host, "nse_cves", []) or []
    if cves:
        L.append("NSE-FLAGGED CVEs: " + ", ".join(cves))

    leads = _priority_leads(host, enum, exploits)
    if leads:
        L.append("RANKED LEADS (highest signal first):")
        for b in leads[:15]:
            L.append("  - " + re.sub(r"\*+", "", b))

    cands = getattr(exploits, "candidates", [])
    if cands:
        L.append("EXPLOIT CANDIDATES (identified, NOT run):")
        for c in cands[:25]:
            L.append(f"  - :{c.port} {c.title} [{c.category}]")

    return "\n".join(L)


def _post_chat(model: str, messages: list, timeout: int) -> str:
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2, "top_p": 0.9},
    }).encode()
    req = urllib.request.Request(
        _OLLAMA_URL.rstrip("/") + "/api/chat",
        data=payload, headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return (data.get("message") or {}).get("content", "").strip()


def advise(cfg: RunConfig, host: HostResult, enum: EnumResult,
           exploits: ExploitResult, timeout: int = 600) -> str:
    """Run the advisory pass. Returns the model's analysis as Markdown text, or ""
    if there's nothing to analyze, the budget is spent, or Ollama is unreachable.
    Never raises — analysis must not break a run."""
    from .report import _redact  # the same redactor the Markdown report uses

    summary = _build_summary(cfg, host, enum, exploits)
    if not summary.strip() or "OPEN SERVICES" not in summary:
        info("AI analysis skipped: no findings to analyze.")
        return ""

    rem = budget_remaining()
    if rem is not None:
        if rem <= 5:
            warn("time budget nearly spent — skipping AI analysis.")
            return ""
        timeout = min(timeout, int(rem) or 1)

    model = getattr(cfg, "ai_model", "") or _DEFAULT_MODEL
    info(f"AI analysis via Ollama model '{model}' at {_OLLAMA_URL} (advisory only)…")
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": _redact(summary)},
    ]
    try:
        out = _post_chat(model, messages, timeout)
    except urllib.error.URLError as e:
        warn_once("ai-ollama",
                  f"Ollama not reachable at {_OLLAMA_URL} ({e}). Start it "
                  "(`ollama serve`) and `ollama pull` a model, or omit --ai.")
        return ""
    except (OSError, ValueError) as e:
        warn_once("ai-ollama", f"AI analysis failed: {e}")
        return ""

    if not out:
        warn("AI analysis returned an empty response.")
        return ""
    good("AI analysis complete (advisory).")
    return out
