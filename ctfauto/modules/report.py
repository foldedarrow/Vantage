"""Reporting: write structured JSON + a readable Markdown report per target."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime

from ..config import RunConfig
from ..modules.recon import HostResult
from ..modules.enumerate import EnumResult
from ..modules.exploit import ExploitResult
from ..util import good


def write_reports(cfg: RunConfig, host: HostResult,
                  enum: EnumResult, exploits: ExploitResult,
                  postex=None) -> tuple[str, str]:
    os.makedirs(cfg.out_dir, exist_ok=True)
    safe_t = cfg.target.replace("/", "_")
    json_path = os.path.join(cfg.out_dir, f"report_{safe_t}.json")
    md_path = os.path.join(cfg.out_dir, f"report_{safe_t}.md")

    data = {
        "target": cfg.target,
        "hostname": cfg.hostname,
        "profile": cfg.profile.name,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "aggressive": cfg.aggressive,
        "host": asdict(host),
        "enumeration": [asdict(f) for f in enum.findings],
        "exploits": [asdict(c) for c in exploits.candidates],
        "postexploit": (asdict(postex) if postex else {}),
    }
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    with open(md_path, "w") as f:
        f.write(_render_md(cfg, host, enum, exploits, postex))

    good(f"report written: {md_path}")
    good(f"json written:   {json_path}")
    return md_path, json_path


def _render_md(cfg, host, enum, exploits, postex=None) -> str:
    L = []
    L.append(f"# ctfauto report — {cfg.target}\n")
    L.append(f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}")
    if cfg.hostname:
        L.append(f"- **Hostname:** {cfg.hostname}")
    L.append(f"- **Classification:** {getattr(cfg, 'klass', '?')}")
    L.append(f"- **Profile:** {cfg.profile.name}")
    L.append(f"- **Aggressive:** {cfg.aggressive}")
    if host.os_guess:
        L.append(f"- **OS guess:** {host.os_guess}")
    L.append("")
    # Captured flags float to the very top — the headline result on HTB.
    flags = list(getattr(postex, "flags", []) or [])
    if flags:
        L.append("> 🚩 **Flags captured:** " + ", ".join(f"`{f}`" for f in flags))
        L.append("")
    L.append("> ⚠️ _Loot under the output dir (`gitloot/`, `sqlmap/`, raw scans) may "
             "contain credentials or PII. Handle accordingly._")
    L.append("")

    L.append("## Open services\n")
    all_svcs = host.services + getattr(host, "udp_services", [])
    if all_svcs:
        L.append("| Port | Proto | Service | Version |")
        L.append("|---|---|---|---|")
        for s in all_svcs:
            L.append(f"| {s.port} | {s.proto} | {s.name} | {s.banner or '—'} |")
    else:
        L.append("_No open services found._")
    L.append("")

    nse = getattr(host, "nse_vuln_hits", [])
    if nse:
        L.append("## NSE vuln-script findings\n")
        L.append("```\n" + "\n".join(nse) + "\n```\n")

    L.append("## Enumeration findings\n")
    if enum.findings:
        for fnd in enum.findings:
            L.append(f"### :{fnd.service_port} — {fnd.tool}: {fnd.summary}")
            if fnd.detail:
                L.append("```\n" + fnd.detail.strip() + "\n```")
            L.append("")
    else:
        L.append("_No enumeration findings._\n")

    L.append("## Exploit candidates\n")
    if exploits.candidates:
        # Surface confirmed wins first.
        wins = [c for c in exploits.candidates if c.session_opened]
        if wins:
            L.append("> **Confirmed access / valid findings:**")
            for c in wins:
                L.append(f"> - :{c.port} {c.title} — {c.result.splitlines()[0]}")
            L.append("")
        for c in exploits.candidates:
            tag = "✅ SAFE" if c.safe else "⚠️ MANUAL/AGGRESSIVE"
            cat = f" _[{c.category}]_" if getattr(c, "category", "") else ""
            win = " 🎯" if c.session_opened else ""
            L.append(f"### :{c.port} — {c.title}  ({tag}){cat}{win}")
            L.append(f"{c.technique}\n")
            if c.msf_module:
                L.append(f"- **Metasploit:** `{c.msf_module}`")
            if c.command:
                L.append(f"- **Command:**\n```\n{c.command}\n```")
            if c.auto_ran:
                L.append(f"- **Auto-run result:**\n```\n{c.result.strip()}\n```")
            elif c.result:
                L.append(f"- **Details:**\n```\n{c.result.strip()}\n```")
            L.append("")
    else:
        L.append("_No exploit candidates identified._\n")

    has_postex = postex and (postex.notes or getattr(postex, "privesc_output", None)
                             or getattr(postex, "proof", None)
                             or getattr(postex, "privesc_leads", None))
    if has_postex:
        L.append("## Post-exploitation\n")
        leads = getattr(postex, "privesc_leads", []) or []
        if leads:
            L.append("**Privilege-escalation leads:**\n")
            for lead in leads:
                L.append(f"- {lead}")
            L.append("")
        proof = getattr(postex, "proof", {}) or {}
        if proof:
            L.append("**Confirmed access (proof):**\n")
            for k, v in proof.items():
                L.append(f"\n### {k} — proof\n```\n{v.strip()[:3000]}\n```")
            L.append("")
        if postex.notes:
            L.append("**Notes:**\n")
            for n in postex.notes:
                L.append(f"- {n}")
            L.append("")
        for k, v in (getattr(postex, "privesc_output", {}) or {}).items():
            L.append(f"\n### {k} — enum output\n```\n{v.strip()[:3000]}\n```")
        L.append("")

    L.append("---")
    L.append("_Generated by ctfauto. Use only against systems you own or are "
             "explicitly authorized to test._")
    return "\n".join(L) + "\n"
