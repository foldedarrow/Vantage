"""Structured handoff export: turn Vantage's findings into a Pentesting Task
Tree (PTT) that a downstream agent (e.g. PentestGPT) can consume.

This is a *reshape* of data Vantage already collected — it runs no tools and
adds no analysis of its own. The deterministic, tool-observed tree is the core;
the optional `--ai` advisory narrative is attached separately and clearly tagged
as model-generated so a consumer never confuses the two.

Design invariants (these mirror Vantage's whole reason for existing):

  * VANTAGE STILL FIRES NOTHING. This module writes a file and returns. It must
    never invoke, spawn, or hand control to the downstream agent — the operator
    runs that separately, against the artifact, as a deliberate next step.
  * `source` IS PROVENANCE, NEVER A RESULT. Every task records where the
    candidate came from (curated signature, NSE CVE, searchsploit…), never that
    anything was attempted. The report-only guarantee lives in the data, not
    just the prose.
  * REDACTED ON THE WAY OUT. Free-text and credential-bearing tags are run
    through the report's redactor before they leave the process, exactly as the
    Markdown report and the `--ai` input already are.
  * SCOPE TRAVELS WITH IT. The `authorization` block carries the target's
    classification and scope verdict so a scope-aware consumer can refuse
    out-of-scope follow-up — Vantage's guard doesn't evaporate at the boundary.

Schema id: ``vantage.ptt/v1``.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime

from ..config import RunConfig, load_scope, target_in_scope
from ..modules.recon import HostResult, is_domain_controller, ad_domain
from ..modules.enumerate import EnumResult
from ..modules.exploit import ExploitResult
from ..util import good
from . import report as _report

SCHEMA = "vantage.ptt/v1"

# Confidence label per priority rank (see report._priority_leads tiers).
_RANK_CONFIDENCE = {0: "critical", 1: "high", 2: "high", 3: "medium", 4: "medium"}

# Tag keys whose values may carry a credential and must be masked before export.
_SENSITIVE_TAGS = ("confirmed_cred",)


def _candidate_rank(c) -> int:
    """Map an ExploitCandidate to the same priority tier report._priority_leads
    uses (lower = higher priority), so task ordering matches the human report."""
    cat = getattr(c, "category", "")
    if cat == "shell":
        return 0
    if cat == "ad":
        return 4 if getattr(c, "needs_cred", False) else 1
    if getattr(c, "high_confidence", False) and getattr(c, "msf_module", ""):
        return 1
    if cat == "creds":
        return 4
    return 3


def _safe_tags(tags: dict) -> dict:
    """Copy enum-finding tags, masking any credential-bearing value. Never
    mutates the caller's dict."""
    if not tags:
        return {}
    out = dict(tags)
    for k in _SENSITIVE_TAGS:
        if k in out and isinstance(out[k], str):
            out[k] = _report._mask_cred_list(out[k])
    return out


def _task_from_candidate(c) -> dict:
    """One ExploitCandidate -> one PTT task node. `status` is always 'todo':
    Vantage observed the candidate, it did not act on it."""
    rank = _candidate_rank(c)
    # stable id: a digest of (port, action, title) so the same finding yields the
    # same id across runs — Python's hash() is per-process salted and would not.
    slug = hashlib.sha1(f"{c.port}|{c.web_action or c.category}|{c.title}".encode()).hexdigest()[:8]
    return {
        "id": f"task:{c.port}/{(c.web_action or c.category or 'svc')}:{slug}",
        "title": c.title,
        "status": "todo",                       # never 'done' — Vantage runs nothing
        "rank": rank,
        "priority": _RANK_CONFIDENCE.get(rank, "medium"),
        "confidence": "high" if getattr(c, "high_confidence", False) else "normal",
        "category": getattr(c, "category", "service"),
        "technique": c.technique,
        "needs_cred": getattr(c, "needs_cred", False),
        "msf_module": getattr(c, "msf_module", ""),
        "suggested_command": c.command,         # a suggestion to a human/agent, not a run
        "web_target": getattr(c, "web_target", ""),
        # provenance only — where the candidate came from, never an outcome.
        "source": "vantage:recon-derived",
        "evidence": _report._redact(c.result.strip()) if getattr(c, "result", "") else "",
    }


def _evidence_from_finding(f) -> dict:
    """One EnumFinding -> one evidence node (tool-observed fact)."""
    return {
        "tool": f.tool,
        "summary": f.summary,
        "detail": _report._redact(f.detail.strip()) if f.detail else "",
        "tags": _safe_tags(f.tags),
    }


def build_ptt(cfg: RunConfig, host: HostResult, enum: EnumResult,
              exploits: ExploitResult, analysis: str = "") -> dict:
    """Assemble the Pentesting Task Tree from already-collected results.

    Tree shape: host -> service(port) -> {evidence[], tasks[]}. Candidates and
    findings that don't map to a discovered service port hang off the host node.
    """
    # --- authorization block: scope verdict travels with the handoff ----------
    scope = load_scope(cfg.scope_file)
    in_scope = target_in_scope(cfg.target, scope) if scope else None
    authorization = {
        "target": cfg.target,
        "hostname": cfg.hostname,
        "classification": getattr(cfg, "klass", ""),
        "profile": cfg.profile.name,
        "aggressive": cfg.aggressive,
        "in_scope": in_scope,                    # None = no scope file configured
        "scope_enforced": bool(scope),
        "allow_external": getattr(cfg, "allow_external", False),
    }

    # --- service nodes, keyed by port so evidence/tasks slot in ---------------
    nodes: dict[int, dict] = {}
    for s in list(host.services) + list(getattr(host, "udp_services", [])):
        nodes[s.port] = {
            "id": f"svc:{s.port}/{s.proto}",
            "kind": "service",
            "port": s.port,
            "proto": s.proto,
            "facts": {
                "name": s.name,
                "product": getattr(s, "product", ""),
                "version": getattr(s, "version", ""),
                "banner": s.banner,
            },
            "evidence": [],
            "tasks": [],
        }

    host_evidence: list[dict] = []
    host_tasks: list[dict] = []

    for f in enum.findings:
        node = nodes.get(f.service_port)
        (node["evidence"] if node else host_evidence).append(_evidence_from_finding(f))

    for c in exploits.candidates:
        node = nodes.get(c.port)
        (node["tasks"] if node else host_tasks).append(_task_from_candidate(c))

    # tasks within a node sorted by priority rank (highest signal first)
    for node in nodes.values():
        node["tasks"].sort(key=lambda t: t["rank"])
    host_tasks.sort(key=lambda t: t["rank"])

    # known CVEs flagged by NSE, annotated with CVSS where seen
    scores = getattr(host, "nse_cve_scores", {}) or {}
    known_cves = [{"cve": cve, "cvss": scores.get(cve)}
                  for cve in (getattr(host, "nse_cves", []) or [])]

    tree = {
        "id": f"host:{cfg.target}",
        "kind": "host",
        "facts": {
            "ip": host.ip,
            "hostname": host.hostname or cfg.hostname,
            "os_guess": host.os_guess,
            "domain_controller": is_domain_controller(host),
            "ad_domain": ad_domain(host) or "",
        },
        "known_cves": known_cves,
        "services": [nodes[p] for p in sorted(nodes)],
        "evidence": host_evidence,
        "tasks": host_tasks,
    }

    ptt = {
        "schema": SCHEMA,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "generator": "vantage",
        "authorization": authorization,
        # the already-ranked, human-readable worklist, reused verbatim so the
        # consumer inherits Vantage's ordering without re-deriving it.
        "priority_leads": _report._priority_leads(host, enum, exploits),
        "tree": tree,
    }

    # optional, clearly fenced model output — advisory only, never executable.
    if analysis:
        ptt["ai_advisory"] = {
            "generated_by": f"ollama:{cfg.ai_model or os.environ.get('VANTAGE_AI_MODEL', 'llama3.1')}",
            "advisory_only": True,
            "narrative": _report._redact(analysis),
        }

    return ptt


def write_handoff(cfg: RunConfig, host: HostResult, enum: EnumResult,
                  exploits: ExploitResult, analysis: str = "") -> str:
    """Build and write the PTT handoff JSON. Returns the path written ('' on a
    write failure that even the fallback couldn't recover)."""
    ptt = build_ptt(cfg, host, enum, exploits, analysis)
    safe_t = cfg.target.replace("/", "_")
    path = os.path.join(cfg.out_dir, f"handoff_{safe_t}.json")
    path = _report._safe_write(path, json.dumps(ptt, indent=2), "PTT handoff")
    if path:
        good(f"handoff written: {path}  (schema {SCHEMA})")
    return path
