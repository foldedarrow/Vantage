"""Enumeration module: per-service deep enumeration dispatched from recon results.

Each service is enumerated by an isolated handler; handlers are run concurrently
(profile.parallelism) since they're independent network operations.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from ..config import RunConfig
from ..modules.recon import HostResult, Service
from ..util import good, info, run, warn, parallel_map


@dataclass
class EnumFinding:
    service_port: int
    tool: str
    summary: str
    detail: str = ""
    # tags carry structured hints for later phases (e.g. {"cms": "wordpress"})
    tags: dict = field(default_factory=dict)


@dataclass
class EnumResult:
    findings: list[EnumFinding] = field(default_factory=list)

    def add(self, f: EnumFinding) -> None:
        self.findings.append(f)
        good(f"[{f.tool}] :{f.service_port} {f.summary}")

    def extend(self, fs: list[EnumFinding]) -> None:
        for f in fs:
            self.add(f)

    def tag_values(self, key: str) -> list:
        return [f.tags[key] for f in self.findings if key in f.tags]


def _have(cfg: RunConfig, tool: str, quiet: bool = False) -> bool:
    if cfg.discovered_tools.get(tool):
        return True
    if not quiet:
        warn(f"{tool} not installed — skipping that enumeration step.")
    return False


def _host_label(cfg: RunConfig) -> str:
    return cfg.hostname or cfg.target


def scheme_is_tls(svc: Service) -> bool:
    return svc.port in (443, 8443) or "https" in svc.name.lower() or "ssl" in svc.name.lower()


def _enum_tls(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    if _have(cfg, "sslscan", quiet=True):
        rc, ss, _ = run(["sslscan", "--no-colour", f"{cfg.target}:{svc.port}"], timeout=90)
        flags = [l for l in ss.splitlines()
                 if any(k in l.lower() for k in ("heartbleed", "vulnerable", "sslv2", "sslv3",
                                                 "tlsv1.0", "weak", "expired"))]
        if flags:
            out.append(EnumFinding(svc.port, "sslscan", f"{len(flags)} TLS issue line(s)",
                                   "\n".join(flags)[:2000]))


def enumerate_host(cfg: RunConfig, host: HostResult) -> EnumResult:
    res = EnumResult()

    def handle(svc: Service) -> list[EnumFinding]:
        local: list[EnumFinding] = []
        name = svc.name.lower()
        if name in ("http", "https", "http-alt", "http-proxy") or svc.port in (80, 443, 8080, 8000, 8443):
            _enum_http(cfg, svc, local)
            if scheme_is_tls(svc):
                _enum_tls(cfg, svc, local)
        elif name == "ftp" or svc.port == 21:
            _enum_ftp(cfg, svc, local)
        elif name in ("microsoft-ds", "netbios-ssn", "smb") or svc.port in (139, 445):
            _enum_smb(cfg, svc, local)
        elif name == "snmp" or svc.port == 161:
            _enum_snmp(cfg, svc, local)
        elif name == "ssh" or svc.port == 22:
            local.append(EnumFinding(svc.port, "recon", f"SSH: {svc.banner or 'version unknown'}"))
        elif name in ("mysql", "ms-sql-s", "postgresql", "mongodb", "redis") or \
                svc.port in (3306, 1433, 5432, 27017, 6379):
            local.append(EnumFinding(svc.port, "recon", f"DB/cache exposed: {svc.name} {svc.banner}",
                                     tags={"db": svc.name}))
        return local

    # Run handlers concurrently; each returns its own findings, merged after.
    batches = parallel_map(handle, host.all_services, workers=cfg.profile.parallelism)
    for batch in batches:
        res.extend(batch)

    # Surface NSE vuln hits from recon as enumeration findings too.
    for hit in host.nse_vuln_hits:
        res.add(EnumFinding(0, "nmap-nse", "vuln-script finding", hit))
    return res


# --- HTTP --------------------------------------------------------------------
def _enum_http(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    scheme = "https" if svc.port in (443, 8443) else "http"
    label = _host_label(cfg)
    base = f"{scheme}://{label}:{svc.port}"

    # 1. Fingerprint stack
    cms = ""
    if _have(cfg, "whatweb"):
        rc, ww, _ = run(["whatweb", "--color=never", base], timeout=120)
        if ww.strip():
            out.append(EnumFinding(svc.port, "whatweb", "fingerprint captured", ww.strip()[:2000]))
            low = ww.lower()
            for c in ("wordpress", "drupal", "joomla"):
                if c in low:
                    cms = c
                    break

    # 2. Quick-win files: robots.txt, .git/, common backups
    if _have(cfg, "curl", quiet=True):
        for path in ("robots.txt", ".git/HEAD", "sitemap.xml", "backup.zip", ".env", "config.php.bak"):
            rc, body, _ = run(["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
                               "-w", "%{http_code}", f"{base}/{path}"], timeout=15)
            code = body.strip()
            if code in ("200", "301", "302"):
                out.append(EnumFinding(svc.port, "http-quickwin",
                                       f"/{path} -> HTTP {code}",
                                       tags={"path": path}))

    # 3. Nikto
    if _have(cfg, "nikto"):
        rc, nk, _ = run(["nikto", "-host", base, "-maxtime", "120s", "-nointeractive"], timeout=200)
        hits = [l for l in nk.splitlines() if l.strip().startswith("+")]
        if hits:
            out.append(EnumFinding(svc.port, "nikto", f"{len(hits)} item(s)", "\n".join(hits)))

    # 4. Directory busting (initial pass)
    found_dirs: list[str] = []
    if _have(cfg, "gobuster"):
        wl = cfg.wordlist_dirs or "/usr/share/wordlists/dirb/common.txt"
        if os.path.exists(wl):
            rc, gb, _ = run(["gobuster", "dir", "-u", base, "-w", wl, "-q",
                             "-t", str(cfg.profile.http_threads), "--no-error"], timeout=300)
            found_dirs = [l.strip() for l in gb.splitlines() if l.strip()]
            if found_dirs:
                out.append(EnumFinding(svc.port, "gobuster", f"{len(found_dirs)} path(s)",
                                       "\n".join(found_dirs)))
        else:
            warn(f"wordlist not found: {wl} (set --wordlist-dirs)")

    # 5. vhost discovery (only meaningful when we have a hostname/.htb)
    if cfg.hostname and _have(cfg, "ffuf", quiet=True):
        vwl = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if os.path.exists(vwl):
            rc, vf, _ = run(["ffuf", "-u", f"{scheme}://{cfg.target}:{svc.port}/",
                             "-H", f"Host: FUZZ.{cfg.hostname}", "-w", vwl,
                             "-mc", "200,301,302,403", "-s"], timeout=180)
            subs = [l.strip() for l in vf.splitlines() if l.strip()]
            if subs:
                out.append(EnumFinding(svc.port, "ffuf-vhost", f"{len(subs)} vhost(s)",
                                       "\n".join(subs)))

    # 5b. Parameterized-URL discovery — feed the web-exploit stage real targets.
    #     Crawl the homepage + any found dirs for links containing query strings.
    if _have(cfg, "curl", quiet=True):
        param_urls = _discover_param_urls(cfg, base, found_dirs)
        for u in param_urls:
            out.append(EnumFinding(svc.port, "param-url", f"parameterized URL: {u}",
                                   tags={"param_url": u}))

    # 6. CMS-specific scanners — emit tag so exploit phase can branch
    if cms:
        out.append(EnumFinding(svc.port, "cms", f"CMS detected: {cms}", tags={"cms": cms, "url": base}))
        if cms == "wordpress" and _have(cfg, "wpscan"):
            rc, ws, _ = run(["wpscan", "--url", base, "--no-banner", "--random-user-agent",
                             "--enumerate", "vp,u", "--format", "cli-no-color"], timeout=300)
            if ws.strip():
                out.append(EnumFinding(svc.port, "wpscan", "WordPress scan", ws.strip()[-3000:]))
        elif cms in ("drupal", "joomla") and _have(cfg, "droopescan"):
            rc, ds, _ = run(["droopescan", "scan", cms, "-u", base], timeout=240)
            if ds.strip():
                out.append(EnumFinding(svc.port, "droopescan", f"{cms} scan", ds.strip()[-3000:]))


def _discover_param_urls(cfg: RunConfig, base: str, found_dirs: list[str]) -> list[str]:
    """Light crawl: fetch base + found dirs, regex out href/src/action targets
    that carry a query string (?x=y). These become sqlmap/LFI candidates.
    Bounded to keep it non-aggressive."""
    seen: set[str] = set()
    pages = [base]
    # found_dirs lines from gobuster look like '/page.php (Status: 200) ...'
    for line in found_dirs[:20]:
        path = line.split()[0] if line.split() else ""
        if path.startswith("/"):
            pages.append(base + path)
    href_re = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I)
    for page in pages[:8]:
        rc, body, _ = run(["curl", "-sk", "--max-time", "10", page], timeout=15)
        if rc != 0 or not body:
            continue
        for m in href_re.findall(body):
            if "?" in m and "=" in m.split("?", 1)[1]:
                url = m if m.startswith("http") else base + ("" if m.startswith("/") else "/") + m
                # strip the value, keep param skeleton, dedupe by path+param-name
                key = url.split("=")[0]
                if key not in seen:
                    seen.add(key)
                    seen.add(url)
    # return concrete URLs (those with both ? and =)
    return [u for u in seen if "?" in u and "=" in u][:15]


# --- FTP ---------------------------------------------------------------------
def _enum_ftp(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    if _have(cfg, "curl", quiet=True):
        rc, body, _ = run(["curl", "-s", "--max-time", "15",
                           f"ftp://anonymous:anonymous@{cfg.target}:{svc.port}/"], timeout=30)
        if rc == 0:
            out.append(EnumFinding(svc.port, "ftp", "ANONYMOUS LOGIN ALLOWED",
                                   body.strip()[:1000] or "(empty listing)",
                                   tags={"anon_ftp": True}))
    out.append(EnumFinding(svc.port, "recon", f"FTP banner: {svc.banner or 'unknown'}"))


# --- SMB ---------------------------------------------------------------------
def _enum_smb(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    if _have(cfg, "enum4linux"):
        rc, e4, _ = run(["enum4linux", "-a", cfg.target], timeout=240)
        if e4.strip():
            interesting = [l for l in e4.splitlines()
                           if any(k in l for k in ("Sharename", "Mapping:", "Server", "OS=", "user:"))]
            out.append(EnumFinding(svc.port, "enum4linux", "SMB enumeration captured",
                                   "\n".join(interesting) or e4[:2000]))
    shares: list[str] = []
    if _have(cfg, "smbclient"):
        rc, sc, _ = run(["smbclient", "-N", "-L", f"//{cfg.target}/"], timeout=60)
        if sc.strip():
            out.append(EnumFinding(svc.port, "smbclient", "share listing (null session)", sc.strip()[:2000]))
            for line in sc.splitlines():
                m = re.match(r"\s+(\S+)\s+Disk", line)
                if m and m.group(1) not in ("IPC$",):
                    shares.append(m.group(1))
    # Try to list contents of each readable share via null session
    for share in shares[:8]:
        rc, ls, _ = run(["smbclient", "-N", f"//{cfg.target}/{share}", "-c", "ls"], timeout=45)
        if rc == 0 and ls.strip():
            out.append(EnumFinding(svc.port, "smbclient", f"share '{share}' readable (null session)",
                                   ls.strip()[:1500], tags={"smb_share": share}))


# --- SNMP --------------------------------------------------------------------
def _enum_snmp(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    community = ""
    if _have(cfg, "onesixtyone"):
        rc, o, _ = run(["onesixtyone", cfg.target, "public", "private", "community"], timeout=60)
        if "public" in o.lower() or "[" in o:
            community = "public"
            out.append(EnumFinding(svc.port, "onesixtyone", "SNMP community string found",
                                   o.strip()[:800], tags={"snmp_community": "public"}))
    if (community or True) and _have(cfg, "snmpwalk"):
        rc, sw, _ = run(["snmpwalk", "-v2c", "-c", "public", "-t", "5", cfg.target], timeout=120)
        if rc == 0 and sw.strip():
            out.append(EnumFinding(svc.port, "snmpwalk", "SNMP tree readable with 'public'",
                                   sw.strip()[:2500], tags={"snmp_community": "public"}))
    elif _have(cfg, "snmp-check", quiet=True):
        rc, sc, _ = run(["snmp-check", cfg.target], timeout=120)
        if rc == 0 and sc.strip():
            out.append(EnumFinding(svc.port, "snmp-check", "SNMP details", sc.strip()[:2500]))
