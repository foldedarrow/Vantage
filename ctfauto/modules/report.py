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
                  enum: EnumResult, exploits: ExploitResult) -> tuple[str, str]:
    os.makedirs(cfg.out_dir, exist_ok=True)
    safe_t = cfg.target.replace("/", "_")
    json_path = os.path.join(cfg.out_dir, f"report_{safe_t}.json")
    md_path = os.path.join(cfg.out_dir, f"report_{safe_t}.md")

    data = {
        "target": cfg.target,
        "hostname": cfg.hostname,
        "classification": getattr(cfg, "klass", ""),
        "profile": cfg.profile.name,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "aggressive": cfg.aggressive,
        "host": asdict(host),
        "enumeration": [asdict(f) for f in enum.findings],
        "exploit_candidates": [asdict(c) for c in exploits.candidates],
    }
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    with open(md_path, "w") as f:
        f.write(_render_md(cfg, host, enum, exploits))

    good(f"report written: {md_path}")
    good(f"json written:   {json_path}")
    return md_path, json_path


def write_sweep_index(out_dir: str, range_target: str, rows: list[dict]) -> str:
    """Write an index report for a CIDR sweep, linking each per-host report.
    `rows` items: {ip, services, candidates, report (md path or '')}."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"index_{range_target.replace('/', '_')}.md")
    L = [f"# ctfauto sweep — {range_target}\n",
         f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}",
         f"- **Live hosts:** {len(rows)}", "",
         "| Host | Services | Exploit candidates | Report |",
         "|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: r.get("candidates", 0), reverse=True):
        rep = os.path.basename(r["report"]) if r.get("report") else ""
        link = f"[{rep}]({rep})" if rep else "—"
        L.append(f"| {r['ip']} | {r.get('services', 0)} | {r.get('candidates', 0)} | {link} |")
    L.append("")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    good(f"sweep index written: {path}")
    return path


def _priority_leads(host, enum, exploits) -> list[str]:
    """Rank the findings into a 'try these first' worklist. Highest-signal items
    first: known RCE → anonymous/unauth access → version-matched CVEs → default
    creds. Returns formatted markdown bullets (most important first)."""
    tiers: list[tuple[int, str]] = []  # (rank, bullet); lower rank = higher priority

    # 0. An open, unauthenticated shell (bind/backdoor shell) — instant access with
    #    no exploit to run. The single highest-signal lead; ranks above known RCE.
    for c in getattr(exploits, "candidates", []):
        if getattr(c, "category", "") == "shell":
            tiers.append((0, f"**Instant root** · :{c.port} — {c.title} "
                             "(connect directly, no exploit)"))

    # 1. High-confidence exploit leads (curated/NSE-bridged RCE).
    for c in getattr(exploits, "candidates", []):
        if c.high_confidence and c.msf_module:
            tiers.append((1, f"**RCE** · :{c.port} — {c.title}  (`{c.msf_module}`)"))

    # 2. Anonymous / unauthenticated access surfaced during enumeration.
    for f in getattr(enum, "findings", []):
        t = f.tags or {}
        if t.get("anon_ftp"):
            tiers.append((2, f"**Anon access** · :{f.service_port} — anonymous FTP login allowed"))
        if t.get("smb_share"):
            tiers.append((2, f"**Anon access** · :{f.service_port} — readable SMB share "
                             f"`{t['smb_share']}` (null session)"))
        if t.get("snmp_community"):
            tiers.append((2, f"**Anon access** · :{f.service_port} — SNMP readable with "
                             f"community `{t['snmp_community']}`"))
        if t.get("path") == ".git/HEAD":
            tiers.append((2, f"**Source leak** · :{f.service_port} — exposed `.git` directory"))
        if t.get("cloud_state") in ("listable", "writable", "readable"):
            tiers.append((2, f"**Cloud exposure** · {t.get('cloud','?').upper()} "
                             f"{f.summary} ({t['cloud_state']})"))
        if t.get("unauth_redis"):
            tiers.append((1, f"**Unauth service** · :{f.service_port} — Redis open with no auth"))
        if t.get("unauth_es"):
            tiers.append((1, f"**Unauth service** · :{f.service_port} — Elasticsearch open with no auth"))
        if t.get("unauth_docker"):
            tiers.append((1, f"**Unauth service** · :{f.service_port} — Docker Engine API "
                             "exposed (host takeover)"))
        if t.get("anon_ldap"):
            tiers.append((2, f"**Anon access** · :{f.service_port} — anonymous LDAP bind"))
        if t.get("nfs_world"):
            tiers.append((2, f"**Anon access** · :{f.service_port} — world-readable NFS "
                             "export(s) (mountable by anyone)"))
        if t.get("web_panel"):
            tiers.append((2, f"**Mgmt panel** · :{f.service_port} — {f.summary}"))

    # 3. NSE-flagged CVEs — rank by CVSS. Only the serious ones (>=7.0) and
    #    confirmed-VULNERABLE unscored hits become leads; low/medium vulners noise
    #    stays in the NSE section, not the worklist.
    scores = getattr(host, "nse_cve_scores", {}) or {}
    for cve in getattr(host, "nse_cves", []) or []:
        score = scores.get(cve)
        if score is None:
            tiers.append((3, f"**Known CVE** · {cve} — NSE-flagged VULNERABLE; verify"))
        elif score >= 7.0:
            tiers.append((3, f"**Known CVE** · {cve} (CVSS {score}) — NSE-flagged; verify"))

    # 4. Default-credential checks worth trying.
    for c in getattr(exploits, "candidates", []):
        if c.category == "creds":
            tiers.append((4, f"**Default creds** · :{c.port} — {c.title}"))

    if not tiers:
        return []
    tiers.sort(key=lambda x: x[0])
    # de-dupe while preserving order
    seen, ordered = set(), []
    for _, bullet in tiers:
        if bullet not in seen:
            seen.add(bullet)
            ordered.append(bullet)
    return ordered


def _render_md(cfg, host, enum, exploits) -> str:
    L = []
    L.append(f"# ctfauto recon report — {cfg.target}\n")
    L.append(f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}")
    if cfg.hostname:
        L.append(f"- **Hostname:** {cfg.hostname}")
    L.append(f"- **Classification:** {getattr(cfg, 'klass', '?')}")
    L.append(f"- **Profile:** {cfg.profile.name}")
    L.append(f"- **Aggressive:** {cfg.aggressive}")
    if host.os_guess:
        L.append(f"- **OS guess:** {host.os_guess}")
    L.append("")
    L.append("> ℹ️ _This is a recon & enumeration report. ctfauto does not exploit "
             "anything — the exploit candidates below are informational and intended "
             "as a starting point for manual, authorized testing._")
    L.append("")
    L.append("> ⚠️ _Loot under the output dir (raw scans, dumps) may contain "
             "credentials or PII. Handle accordingly._")
    L.append("")

    # Priority leads — a ranked 'try these first' worklist distilled from all phases.
    leads = _priority_leads(host, enum, exploits)
    if leads:
        L.append("## Priority leads\n")
        L.append("_Ranked highest-signal first. These are candidates for manual, "
                 "authorized follow-up — ctfauto did not act on them._\n")
        for i, bullet in enumerate(leads, 1):
            L.append(f"{i}. {bullet}")
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
            scores = getattr(host, "nse_cve_scores", {}) or {}
            # already CVSS-ranked in recon; annotate with the score where known.
            labelled = [f"{c} ({scores[c]})" if c in scores else c for c in cves]
            L.append(f"**CVEs flagged (CVSS-ranked):** {', '.join(labelled)}\n")
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

    L.append("## Exploit candidates (informational — not run)\n")
    if exploits.candidates:
        L.append("_ctfauto identified the following candidate exploits / known CVEs "
                 "from the recon data. It did **not** attempt any of them. Use these "
                 "as leads for manual, authorized testing._\n")
        for c in exploits.candidates:
            tag = "high-confidence lead" if c.high_confidence else "lead — verify manually"
            cat = f" _[{c.category}]_" if getattr(c, "category", "") else ""
            L.append(f"### :{c.port} — {c.title}  ({tag}){cat}")
            L.append(f"{c.technique}\n")
            if c.msf_module:
                L.append(f"- **Metasploit module:** `{c.msf_module}`")
            if c.command:
                L.append(f"- **Suggested command:**\n```\n{c.command}\n```")
            if c.result:
                L.append(f"- **Details:**\n```\n{_redact(c.result.strip())}\n```")
            L.append("")
    else:
        L.append("_No exploit candidates identified._\n")

    L.append("---")
    L.append("_Generated by ctfauto — a recon & enumeration tool. It does not exploit "
             "anything. Use only against systems you own or are explicitly authorized "
             "to test._")
    return "\n".join(L) + "\n"
