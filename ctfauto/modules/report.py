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

import re as _re

# Patterns for obvious secrets to mask in the *Markdown* report only. The raw,
# unredacted data is still written to the gitignored JSON / loot files (#31).
_REDACTORS = [
    # private key blocks
    (_re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                 _re.S), "[REDACTED PRIVATE KEY]"),
    # AWS access key IDs / secret access keys
    (_re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY ID]"),
    (_re.compile(r"(?i)\baws_secret_access_key\b\s*[=:]\s*\S+"),
     "aws_secret_access_key = [REDACTED]"),
    # key: value style secrets (password/passwd/pwd/secret/token/api_key)
    (_re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b"
                 r"\s*[=:]\s*('?\"?)([^\s'\"]{3,})\2"),
     r"\1=[REDACTED]"),
    # hydra/ctfauto success lines: 'login: x password: y'
    (_re.compile(r"(?i)(login:\s*\S+\s+password:\s*)(\S+)"), r"\1[REDACTED]"),
    # ctfauto's own 'VALID [DEFAULT ]CREDS: user:pass, user2:pass2' lines — mask
    # the password half of each pair. Anchored on the CREDS: prefix so we don't
    # touch unrelated 'host:port' / 'Server: Apache' text elsewhere.
    (_re.compile(r"(?im)((?:VALID(?:\s+DEFAULT)?\s+CREDS|CREDS):\s*)(.+)$"),
     lambda m: m.group(1) + _mask_cred_list(m.group(2))),
]


def _mask_cred_list(s: str) -> str:
    """Given 'root:root, admin:secret (manager)', mask each password half."""
    parts = []
    for chunk in s.split(","):
        c = chunk.strip()
        if ":" in c:
            user, _, rest = c.partition(":")
            # keep any trailing parenthetical note (e.g. '(manager)')
            tail = ""
            if "(" in rest:
                rest, _, paren = rest.partition("(")
                tail = " (" + paren
            parts.append(f"{user}:[REDACTED]{tail}".rstrip())
        else:
            parts.append(c)
    return ", ".join(parts)


def _redact(text: str) -> str:
    """Mask obvious secrets for the human-readable Markdown. Raw data lives in
    the JSON/loot files. Never raises — redaction must not break reporting."""
    if not text:
        return text
    out = text
    for rx, repl in _REDACTORS:
        try:
            out = rx.sub(repl, out)
        except Exception:  # noqa: BLE001 — redaction must never break reporting
            continue
    return out


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

    # Cloud misconfiguration findings (if the cloud phase ran) — surfaced up top.
    cloud_finds = [f for f in enum.findings if f.tags.get("cloud")]
    if cloud_finds:
        hot = [f for f in cloud_finds
               if f.tags.get("cloud_state") in ("listable", "writable", "readable", "takeover")]
        L.append("## Cloud exposure (unauthenticated)\n")
        if hot:
            L.append("> ☁️ **Public cloud misconfigurations found** — these are "
                     "anonymously accessible:")
            for f in hot:
                sev = f.tags.get("severity", "info")
                L.append(f"> - **{f.tags['cloud'].upper()}** {f.summary}  _[{sev}]_")
            L.append("")
        L.append("| Provider | Resource | State | Severity |")
        L.append("|---|---|---|---|")
        for f in cloud_finds:
            prov = f.tags.get("cloud", "?")
            state = f.tags.get("cloud_state", "?")
            sev = f.tags.get("severity", "info")
            res = f.summary.split(":")[0]
            L.append(f"| {prov} | {res} | {state} | {sev} |")
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

    nse_by_port = getattr(host, "nse_by_port", None)
    nse = getattr(host, "nse_vuln_hits", [])
    if nse_by_port:
        L.append("## NSE vuln-script findings\n")
        cves = getattr(host, "nse_cves", []) or []
        if cves:
            L.append(f"**CVEs flagged:** {', '.join(cves)}\n")
        for port in sorted(nse_by_port,
                           key=lambda p: int(p) if p.isdigit() else 1 << 30):
            lines = nse_by_port[port]
            L.append(f"### :{port} — {len(lines)} line(s)")
            L.append("```\n" + "\n".join(lines) + "\n```")
        L.append("")
    elif nse:
        L.append("## NSE vuln-script findings\n")
        L.append("```\n" + "\n".join(nse) + "\n```\n")

    L.append("## Enumeration findings\n")
    if enum.findings:
        for fnd in enum.findings:
            L.append(f"### :{fnd.service_port} — {fnd.tool}: {fnd.summary}")
            if fnd.detail:
                L.append("```\n" + _redact(fnd.detail.strip()) + "\n```")
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
                first = _redact(c.result.splitlines()[0]) if c.result else ""
                L.append(f"> - :{c.port} {c.title} — {first}")
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
                L.append(f"- **Auto-run result:**\n```\n{_redact(c.result.strip())}\n```")
            elif c.result:
                L.append(f"- **Details:**\n```\n{_redact(c.result.strip())}\n```")
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
                L.append(f"\n### {k} — proof\n```\n{_redact(v.strip()[:3000])}\n```")
            L.append("")
        if postex.notes:
            L.append("**Notes:**\n")
            for n in postex.notes:
                L.append(f"- {n}")
            L.append("")
        for k, v in (getattr(postex, "privesc_output", {}) or {}).items():
            L.append(f"\n### {k} — enum output\n```\n{_redact(v.strip()[:3000])}\n```")
        L.append("")

    L.append("---")
    L.append("_Generated by ctfauto. Use only against systems you own or are "
             "explicitly authorized to test._")
    return "\n".join(L) + "\n"
