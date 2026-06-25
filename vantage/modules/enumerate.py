"""Enumeration module: per-service deep enumeration dispatched from recon results.

Each service is enumerated by an isolated handler; handlers are run concurrently
(profile.parallelism) since they're independent network operations.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from dataclasses import asdict

from ..config import RunConfig
from ..modules.recon import HostResult, Service, ad_domain
from ..util import good, info, run, warn, warn_once, parallel_map, load_state, save_state
from .. import wordlists


# WinRM/WS-Management, RPC-over-HTTP and the bare Windows HTTPAPI listener all
# answer on "http" ports that nmap labels 'http', but they are NOT web apps —
# running whatweb/nikto/dir-brute/sqlmap against them produces pure noise
# ("missing security headers" on a DC) and, worse, tees up sqlmap at WinRM. Keep
# them out of the HTTP path; they get their own lightweight recon notes instead.
_NON_WEB_HTTP_PORTS = {5985, 5986, 47001, 593, 9389}

# A tiny curated set of AD accounts to try when no username wordlist is resolved.
# Enough to catch the classic AS-REP-roastable service accounts on a lab DC
# without the volume of a full SecLists run.
_COMMON_AD_USERS = [
    "administrator", "admin", "guest", "krbtgt", "ldap", "svc-ldap", "svc_ldap",
    "svc-admin", "svc_admin", "service", "sql", "sqlservice", "svc-sql",
    "backup", "web", "webadmin", "helpdesk", "support", "test", "dev",
    "j.doe", "jdoe", "john", "jane", "mike", "sarah", "david", "robert",
]


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


# A common browser UA used in --stealth so requests don't carry the obvious
# 'curl/8.x' / 'WhatWeb' signatures a WAF/IDS flags immediately.
_STEALTH_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def _ua_args(cfg: RunConfig) -> list[str]:
    """curl -A <browser UA> when in stealth mode, else nothing."""
    return ["-A", _STEALTH_UA] if getattr(cfg, "stealth", False) else []


def _have(cfg: RunConfig, tool: str, quiet: bool = False) -> bool:
    if cfg.discovered_tools.get(tool):
        return True
    if not quiet:
        # warn only once per tool across the whole run, not per service (#18)
        warn_once(f"missing:{tool}", f"{tool} not installed — skipping steps that use it.")
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


def _enum_to_state(res: EnumResult) -> list[dict]:
    return [asdict(f) for f in res.findings]


def _enum_from_state(d: dict) -> EnumResult | None:
    """Rebuild an EnumResult from cached state. Returns None if absent/invalid."""
    rows = (d or {}).get("enum")
    if rows is None:
        return None
    try:
        res = EnumResult()
        for r in rows:
            res.findings.append(EnumFinding(
                service_port=r.get("service_port", 0),
                tool=r.get("tool", ""),
                summary=r.get("summary", ""),
                detail=r.get("detail", ""),
                tags=r.get("tags", {}) or {},
            ))
        return res
    except (TypeError, ValueError, AttributeError):
        return None


def enumerate_host(cfg: RunConfig, host: HostResult) -> EnumResult:
    """Enumerate all services. With --resume, reuse cached enum findings if a
    previous run persisted them (issue #13 — enum half was previously unwired)."""
    if cfg.resume:
        cached = _enum_from_state(load_state(cfg.out_dir, cfg.target))
        if cached is not None and cached.findings:
            good(f"--resume: reusing cached enumeration "
                 f"({len(cached.findings)} finding(s)) from previous run")
            return cached
        info("--resume: no usable cached enumeration; enumerating fresh.")

    res = _enumerate_host_fresh(cfg, host)

    # Persist enum into the same state file as recon (merge, don't clobber #13).
    try:
        state = load_state(cfg.out_dir, cfg.target)
        state["enum"] = _enum_to_state(res)
        save_state(cfg.out_dir, cfg.target, state)
    except OSError:
        pass
    return res


def _enumerate_host_fresh(cfg: RunConfig, host: HostResult) -> EnumResult:
    res = EnumResult()

    # Detect the AD realm once, up front, from nmap's LDAP/Kerberos banners. The
    # per-service handlers run concurrently, so the Kerberos handler can't wait on
    # the LDAP one — both read this shared, pre-computed value instead.
    domain = ad_domain(host)

    def handle(svc: Service) -> list[EnumFinding]:
        local: list[EnumFinding] = []
        name = svc.name.lower()
        # Windows infra ports (WinRM/WSMan, RPC-over-HTTP, HTTPAPI, ADWS) answer on
        # 'http' but are not web apps — route them away from the HTTP enumeration.
        is_web = ((name in ("http", "https", "http-alt", "http-proxy")
                   or svc.port in (80, 443, 8080, 8000, 8443))
                  and svc.port not in _NON_WEB_HTTP_PORTS
                  and name not in ("wsman", "mc-nmf", "ncacn_http"))
        if name == "kerberos-sec" or svc.port == 88:
            _enum_kerberos(cfg, svc, local, domain)
        elif is_web:
            _enum_http(cfg, svc, local)
            if scheme_is_tls(svc):
                _enum_tls(cfg, svc, local)
        elif name == "ftp" or svc.port == 21:
            _enum_ftp(cfg, svc, local)
        elif name in ("microsoft-ds", "netbios-ssn", "smb") or svc.port in (139, 445):
            # 139 and 445 are the same Samba instance — enumerate it once (prefer
            # 445) so the report doesn't carry duplicate share listings.
            open_ports = {x.port for x in host.all_services}
            if not (svc.port == 139 and 445 in open_ports):
                _enum_smb(cfg, svc, local)
        elif name in ("nfs", "nfs_acl", "mountd") or svc.port == 2049:
            # NFS registers on several RPC ports (2049 + a dynamic mountd port)
            # over both TCP and UDP. showmount -e queries the portmapper and returns
            # all exports regardless of which one we hit, so enumerate ONCE — on the
            # canonical NFS service (lowest port, TCP preferred) — to avoid the
            # duplicate findings/leads a per-port run produced.
            nfs_svcs = [x for x in host.all_services
                        if x.name.lower() in ("nfs", "nfs_acl", "mountd") or x.port == 2049]
            canonical = min(nfs_svcs,
                            key=lambda x: (x.port, 0 if x.proto == "tcp" else 1))
            if svc is canonical:
                _enum_nfs(cfg, svc, local)
        elif name == "snmp" or svc.port == 161:
            _enum_snmp(cfg, svc, local)
        elif name == "ssh" or svc.port == 22:
            local.append(EnumFinding(svc.port, "recon", f"SSH: {svc.banner or 'version unknown'}"))
        elif name in ("ldap", "ldaps") or svc.port in (389, 636, 3268, 3269):
            # 389 (LDAP), 636 (LDAPS), 3268/3269 (Global Catalog) are the same
            # directory — enumerate ONCE on the canonical port (prefer plain 389)
            # so the report doesn't carry duplicate anonymous-bind leads.
            ldap_ports = [x.port for x in host.all_services
                          if x.name.lower() in ("ldap", "ldaps")
                          or x.port in (389, 636, 3268, 3269)]
            if svc.port == _canonical_ldap_port(ldap_ports):
                _enum_ldap(cfg, svc, local, domain)
        elif svc.port == 2375 or (svc.port == 2376 and "docker" in name):
            _enum_docker_api(cfg, svc, local)
        elif name in ("elasticsearch",) or svc.port == 9200 or "elasticsearch" in svc.banner.lower():
            _enum_elasticsearch(cfg, svc, local)
        elif name in ("ms-wbt-server", "rdp") or svc.port == 3389:
            local.append(EnumFinding(svc.port, "recon", f"RDP exposed: {svc.banner or 'service up'} "
                                     "— check NLA / CredSSP (CVE-2019-0708 BlueKeep on legacy)"))
        elif name in ("wsman",) or svc.port in (5985, 5986):
            local.append(EnumFinding(svc.port, "recon", f"WinRM exposed: {svc.banner or 'service up'} "
                                     "— try evil-winrm / nxc winrm once you have valid creds"))
        elif svc.port == 47001:
            local.append(EnumFinding(svc.port, "recon",
                                     "Windows HTTPAPI / WS-Management companion listener "
                                     "(not a web app) — WinRM lives on :5985"))
        elif name == "mc-nmf" or svc.port == 9389:
            local.append(EnumFinding(svc.port, "recon",
                                     "AD Web Services (ADWS) — drives the PowerShell AD "
                                     "module / SOAPHound; queryable with valid creds"))
        elif name in ("mysql", "ms-sql-s", "postgresql", "mongodb", "redis") or \
                svc.port in (3306, 1433, 5432, 27017, 6379):
            _enum_dbcache(cfg, svc, local)
        return local

    # Run handlers concurrently; each returns its own findings, merged after.
    batches = parallel_map(handle, host.all_services, workers=cfg.profile.parallelism)
    for batch in batches:
        res.extend(batch)

    # NSE vuln hits are NOT bridged into enum findings: the report renders them in
    # its own dedicated "NSE vuln-script findings" section (grouped per port with a
    # CVSS-ranked CVE summary). Bridging them here duplicated every line in the
    # report. host.nse_by_port / nse_cves carry the data straight to the report.
    return res


# --- HTTP --------------------------------------------------------------------
def _parse_whatweb_server(ww: str) -> tuple[str, str]:
    """Extract (product, version) for the web server from whatweb output, e.g.
    'HTTPServer[lighttpd/1.4.76]' -> ('lighttpd','1.4.76'). Returns ('','') if the
    server isn't disclosed (some 403s hide it)."""
    m = re.search(r"HTTPServer\[([^\]]+)\]", ww)
    token = m.group(1) if m else ""
    if not token:
        for srv in ("Apache", "nginx", "lighttpd", "Microsoft-IIS", "openresty", "Jetty"):
            m2 = re.search(rf"\b{srv}\[([^\]]+)\]", ww)
            if m2:
                token = f"{srv}/{m2.group(1)}"
                break
    if not token:
        return "", ""
    token = token.split("(")[0].strip()      # drop '(Ubuntu)' etc.
    if "/" in token:
        prod, _, ver = token.partition("/")
        return prod.strip(), ver.strip()
    return token.strip(), ""


# Known web apps → (app name, sensitive?, follow-up hint). Matched against whatweb
# output (titles/headers/plugins), lowercased. 'sensitive' apps are management/admin
# surfaces worth promoting to a priority lead.
_WEB_APP_SIGNATURES = [
    ("title[pi-hole", "Pi-hole admin", True,
     "Admin UI at /admin — check the web password; `searchsploit pi-hole` for app CVEs."),
    ("title[grafana", "Grafana", True,
     "Login at /login (default admin:admin); check version against CVE-2021-43798 (path traversal)."),
    ("x-jenkins[", "Jenkins", True,
     "Script console at /script = RCE if unauthenticated; enumerate /asynchPeople, check version CVEs."),
    ("phpmyadmin", "phpMyAdmin", True,
     "At /phpmyadmin — try DB default creds; `searchsploit phpmyadmin` for version RCEs."),
    ("title[gitea", "Gitea", True, "Check for open registration and version CVEs."),
    ("title[proxmox virtual environment", "Proxmox VE", True, "Login at :8006; check known CVEs."),
    ("title[pfsense", "pfSense", True, "Default admin:pfsense; check firmware CVEs."),
    ("title[portainer", "Portainer", True, "Initial-admin race / weak creds; manages Docker."),
    ("kibana", "Kibana", True, "Check version against known prototype-pollution/RCE CVEs."),
    ("title[adminer", "Adminer", True, "DB admin at this path; try default DB creds; SSRF CVEs."),
]


def _identify_web_app(ww: str) -> tuple[str, bool, str] | None:
    """Return (app, sensitive, hint) for the first known web app matched in the
    whatweb output, else None."""
    low = ww.lower()
    for sig, name, sensitive, hint in _WEB_APP_SIGNATURES:
        if sig in low:
            return name, sensitive, hint
    return None


# nikto's most actionable lines, pulled out of the 30-item blob into their own
# leads. A confirmed default account (e.g. Tomcat Manager tomcat:tomcat = WAR-deploy
# RCE) is the single highest-signal thing nikto finds and shouldn't be buried.
_NIKTO_DEFAULT_ACCT = re.compile(
    r"(/\S*?):\s*Default account found for '([^']+)' at "
    r"\(ID '([^']*)', PW '([^']*)'\)", re.I)
# Sensitive admin/data surfaces nikto reports by path → promote to a panel lead.
_NIKTO_PANELS = [
    ("/phpmyadmin", "phpMyAdmin",
     "DB admin panel — try DB default creds (root:<blank>); `searchsploit phpmyadmin`."),
    ("/admin/login.jsp", "Tomcat admin console",
     "Tomcat Server Administration login — try default Tomcat creds."),
]


def _nikto_findings(port: int, hits: list[str]) -> list[EnumFinding]:
    """Extract high-signal leads (confirmed default creds, admin panels) from
    nikto's '+' lines so they surface as priority leads, not buried in the blob."""
    out: list[EnumFinding] = []
    seen_panels: set[str] = set()
    for line in hits:
        m = _NIKTO_DEFAULT_ACCT.search(line)
        if m:
            path, app, user, pw = m.group(1), m.group(2), m.group(3), m.group(4)
            cred = f"{user}:{pw}" if (user or pw) else "(blank)"
            out.append(EnumFinding(
                port, "nikto", f"CONFIRMED default creds {cred} for {app} at {path}",
                line.strip(),
                tags={"confirmed_cred": cred, "cred_app": app, "cred_path": path}))
        low = line.lower()
        for needle, name, hint in _NIKTO_PANELS:
            if needle in low and name not in seen_panels:
                seen_panels.add(name)
                out.append(EnumFinding(
                    port, "nikto", f"{name} exposed", f"{hint}\n{line.strip()}",
                    tags={"web_panel": True, "panel": name}))
    return out


def _enum_http(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    scheme = "https" if svc.port in (443, 8443) else "http"
    label = _host_label(cfg)
    base = f"{scheme}://{label}:{svc.port}"

    # 1. Fingerprint stack
    cms = ""
    if _have(cfg, "whatweb"):
        ww_cmd = ["whatweb", "--color=never"]
        if cfg.stealth:
            ww_cmd += ["--user-agent", _STEALTH_UA, "--max-threads", "1"]
        rc, ww, _ = run(ww_cmd + [base], timeout=120)
        if ww.strip():
            # Pull the real server product+version (nmap often mislabels web ports —
            # e.g. 'webdav' for a lighttpd box); these tags let the exploit phase
            # query Exploit-DB on the actual software instead of nmap's guess (#2).
            prod, ver = _parse_whatweb_server(ww)
            wtags = {"http_product": prod, "http_version": ver} if prod else {}
            summary = "fingerprint captured" + (f": {prod} {ver}".rstrip() if prod else "")
            out.append(EnumFinding(svc.port, "whatweb", summary, ww.strip()[:2000], tags=wtags))
            # Known-app fingerprint → the actual attack surface (admin panel, default
            # creds, app CVEs) instead of just a stack list (#3).
            app = _identify_web_app(ww)
            if app:
                name, sensitive, hint = app
                atags = {"app": name, "app_url": base}
                if sensitive:
                    atags["web_panel"] = True
                out.append(EnumFinding(svc.port, "web-app", f"{name} detected", hint, tags=atags))
            low = ww.lower()
            for c in ("wordpress", "drupal", "joomla"):
                if c in low:
                    cms = c
                    break

    # 2. Quick-win files: robots.txt, .git/, common backups
    if _have(cfg, "curl", quiet=True):
        # Soft-404 baseline: request a path that cannot exist. If the server still
        # answers 200/redirect for it, it serves a custom success page for missing
        # content, so a 200 on a real quick-win path is meaningless — suppress those
        # to avoid flooding the report with false hits.
        rc, base_code, _ = run(["curl", "-sk", *_ua_args(cfg), "--max-time", "10",
                                "-o", "/dev/null", "-w", "%{http_code}",
                                f"{base}/vantage-nonexistent-{svc.port}.html"], timeout=15)
        soft404 = base_code.strip() in ("200", "301", "302")
        if soft404:
            info(f"{base} soft-404s (success on a missing path); skipping quick-win path checks")
        else:
            for path in ("robots.txt", ".git/HEAD", "sitemap.xml", "backup.zip", ".env", "config.php.bak"):
                rc, body, _ = run(["curl", "-sk", *_ua_args(cfg), "--max-time", "10",
                                   "-o", "/dev/null", "-w", "%{http_code}",
                                   f"{base}/{path}"], timeout=15)
                code = body.strip()
                if code in ("200", "301", "302"):
                    out.append(EnumFinding(svc.port, "http-quickwin",
                                           f"/{path} -> HTTP {code}",
                                           tags={"path": path}))

    # 2b. API / Swagger surface discovery (read-only GETs of well-known endpoints).
    #     An exposed schema/Swagger UI maps the whole API attack surface. We must
    #     check the STATUS CODE, not just the body: Apache/Tomcat 404 pages echo the
    #     requested path back ("/swagger-ui.html was not found on this server"), so a
    #     body-only substring match flags a plain 404 as an exposed Swagger UI — a
    #     false positive that fired on Metasploitable's :80 and :8180. Require 200.
    if _have(cfg, "curl", quiet=True):
        for path in ("swagger.json", "openapi.json", "api-docs", "v2/api-docs",
                     "swagger-ui.html", "graphql", "api", "actuator", "actuator/env"):
            rc, body, _ = run(["curl", "-sk", *_ua_args(cfg), "--max-time", "10",
                               "-w", "\n__VANTAGE_HTTP__%{http_code}",
                               f"{base}/{path}"], timeout=15)
            # The status code is appended after the body by curl's -w; split it off.
            code = ""
            if "__VANTAGE_HTTP__" in body:
                body, _, code = body.rpartition("__VANTAGE_HTTP__")
                code = code.strip()
            # Only a genuine 200 is an exposed schema. 404/401/403 (including error
            # pages that reflect the requested path) are not — skip them.
            if code != "200":
                continue
            low = body.lower()
            if any(k in low for k in ('"swagger"', '"openapi"', '"paths"',
                                      "swagger-ui", '"__schema"', '"_links"', '"activeprofiles"')):
                out.append(EnumFinding(svc.port, "api-discovery",
                                       f"/{path} -> API schema/endpoint exposed",
                                       body.strip()[:1200], tags={"api_path": path}))

    # 3. Nikto — loud; only when the profile allows it (off on gentle/HTB, #14)
    if cfg.profile.enable_nikto and _have(cfg, "nikto"):
        rc, nk, _ = run(["nikto", "-host", base, "-maxtime", "120s", "-nointeractive"], timeout=200)
        hits = [l for l in nk.splitlines() if l.strip().startswith("+")]
        if hits:
            out.append(EnumFinding(svc.port, "nikto", f"{len(hits)} item(s)", "\n".join(hits)))
            # Pull confirmed default creds / admin panels out into their own leads.
            out.extend(_nikto_findings(svc.port, hits))
    elif not cfg.profile.enable_nikto:
        info(f"nikto skipped on {cfg.profile.name} profile (noisy)")

    # 4. Directory busting (initial pass). Prefer feroxbuster (recursion) if
    #    present, else gobuster. Gated by profile.enable_dirbust.
    found_dirs: list[str] = []
    if cfg.profile.enable_dirbust:
        wl = wordlists.directory_wordlist(cfg, cfg.wordlist_dirs)
        if not wl:
            warn_once("no-dir-wordlist",
                      "no directory wordlist found (set --wordlist-dirs); dir-busting skipped.")
        elif _have(cfg, "feroxbuster", quiet=True):
            rc, fx, _ = run(["feroxbuster", "-u", base, "-w", wl, "-q", "-d", "2",
                             "-t", str(cfg.profile.http_threads), "--silent",
                             "-x", "php,txt,html"], timeout=400)
            found_dirs = [l.strip() for l in fx.splitlines() if l.strip().startswith("http")]
            if found_dirs:
                out.append(EnumFinding(svc.port, "feroxbuster", f"{len(found_dirs)} path(s)",
                                       "\n".join(found_dirs[:200])))
        elif _have(cfg, "gobuster"):
            rc, gb, _ = run(["gobuster", "dir", "-u", base, "-w", wl, "-q",
                             "-t", str(cfg.profile.http_threads), "--no-error"], timeout=300)
            found_dirs = [l.strip() for l in gb.splitlines() if l.strip()]
            if found_dirs:
                out.append(EnumFinding(svc.port, "gobuster", f"{len(found_dirs)} path(s)",
                                       "\n".join(found_dirs)))

    # 5. vhost discovery (only meaningful when we have a hostname/.htb).
    #    Wordlist resolved via the SecLists resolver (with fallbacks) so it works
    #    regardless of how SecLists was installed — was a hardcoded path (#27).
    if cfg.hostname and _have(cfg, "ffuf", quiet=True):
        vwl = wordlists.vhost_wordlist(cfg)
        if vwl:
            rc, vf, _ = run(["ffuf", "-u", f"{scheme}://{cfg.target}:{svc.port}/",
                             "-H", f"Host: FUZZ.{cfg.hostname}", "-w", vwl,
                             "-mc", "200,301,302,403", "-s"], timeout=180)
            subs = [l.strip() for l in vf.splitlines() if l.strip()]
            if subs:
                out.append(EnumFinding(svc.port, "ffuf-vhost", f"{len(subs)} vhost(s)",
                                       "\n".join(subs)))
        else:
            warn_once("no-vhost-wordlist",
                      "no vhost/subdomain wordlist found (install SecLists or set "
                      "--seclists-dir); vhost discovery skipped.")

    # 5b. Parameterized-URL discovery — feed the web-exploit stage real targets.
    #     Crawl the homepage + any found dirs for links carrying query strings.
    #     Only when the profile permits active web (so we don't tee up sqlmap/LFI
    #     against HTB shared infra). arjun augments this if installed (#23).
    if cfg.profile.enable_active_web and _have(cfg, "curl", quiet=True):
        param_urls = _discover_param_urls(cfg, base, found_dirs)
        if _have(cfg, "arjun", quiet=True):
            param_urls = list(dict.fromkeys(param_urls + _arjun_params(cfg, base)))
        param_urls = [u for u in param_urls if _is_testable_param_url(u)]
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


def _arjun_params(cfg: RunConfig, base: str) -> list[str]:
    """Use arjun to discover hidden GET parameters, returned as base?param=1 URLs
    so the sqlmap/LFI stage can test them. Best-effort; empty on any failure."""
    import json as _json
    out_file = os.path.join(cfg.out_dir, "arjun.json")
    cmd = ["arjun", "-u", base, "-m", "GET", "-oJ", out_file, "-q"]
    # Feed arjun the SecLists parameter wordlist when we have it (bigger surface).
    pwl = wordlists.param_wordlist(cfg)
    if pwl:
        cmd += ["-w", pwl]
    rc, _, _ = run(cmd, timeout=180)
    urls: list[str] = []
    try:
        with open(out_file) as f:
            data = _json.load(f)
        # arjun JSON: { "<url>": { "params": [...], ... }, ... }
        for url, info_d in data.items():
            for p in info_d.get("params", []):
                urls.append(f"{url}{'&' if '?' in url else '?'}{p}=1")
    except (OSError, ValueError, AttributeError):
        pass
    return urls


# Static assets are never injectable; their `?v=`/`?_=` cache-busters just flood
# the report with sqlmap/LFI candidates (a Pi-hole/AdminLTE scan produced ~60).
_STATIC_EXTS = (".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif",
                ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
                ".otf", ".mp4", ".webm", ".pdf", ".zip")
_CACHEBUSTER_PARAMS = {"v", "ver", "version", "_", "t", "ts", "cache", "cb", "rev", "r", "d"}


def _is_testable_param_url(u: str) -> bool:
    """Keep a parameterized URL only if it's worth testing. Drops static assets
    (.css/.js/fonts/images) and URLs whose parameters are ALL cache-busters
    (?v=, ?_=) — neither is injectable, and they dominate modern web UIs."""
    import urllib.parse as _up
    parsed = _up.urlparse(u)
    if any(parsed.path.lower().endswith(ext) for ext in _STATIC_EXTS):
        return False
    names = [k.lower() for k, _ in _up.parse_qsl(parsed.query)]
    if not names:
        return False
    return not all(n in _CACHEBUSTER_PARAMS for n in names)


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
    # In-scope hosts: the target IP and any resolved hostname. We must NOT tee up
    # sqlmap/LFI against an EXTERNAL host linked from the page (e.g. Tomcat's docs
    # link to issues.apache.org) — that would send active attack traffic
    # off-target. Absolute links to other hosts are dropped.
    import urllib.parse as _up
    in_scope = {cfg.target.lower()}
    if cfg.hostname:
        in_scope.add(cfg.hostname.lower())

    def _same_host(u: str) -> bool:
        host = _up.urlparse(u).hostname
        return (host or "").lower() in in_scope

    href_re = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I)
    for page in pages[:8]:
        rc, body, _ = run(["curl", "-sk", "--max-time", "10", page], timeout=15)
        if rc != 0 or not body:
            continue
        for m in href_re.findall(body):
            if "?" in m and "=" in m.split("?", 1)[1]:
                if m.startswith("http"):
                    # absolute URL: keep only if it points back at the target host
                    if not _same_host(m):
                        continue
                    url = m
                elif m.startswith("//"):
                    continue  # protocol-relative to another host — skip
                else:
                    url = base + ("" if m.startswith("/") else "/") + m
                # strip the value, keep param skeleton, dedupe by path+param-name
                key = url.split("=")[0]
                if key not in seen:
                    seen.add(key)
                    seen.add(url)
    # return concrete URLs (both ? and =), minus static assets / cache-buster-only
    return [u for u in seen
            if "?" in u and "=" in u and _is_testable_param_url(u)][:15]


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
    # Modern null-session AD enumeration via netexec/nxc: users, password policy,
    # and (lab/aggressive only) RID cycling. enum4linux-ng is preferred over the
    # legacy enum4linux, which is largely defanged on hardened 2022 DCs.
    _enum_smb_nxc(cfg, svc, out)
    e4tool = _have_any(cfg, "enum4linux-ng", "enum4linux")
    if e4tool:
        rc, e4, _ = run([e4tool, "-a", cfg.target], timeout=240)
        if e4.strip():
            interesting = [l for l in e4.splitlines()
                           if any(k in l for k in ("Sharename", "Mapping:", "Server",
                                                   "OS=", "user:", "Password Policy",
                                                   "Domain Sid"))]
            out.append(EnumFinding(svc.port, e4tool, "SMB enumeration captured",
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


def _enum_smb_nxc(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    """Null/guest-session SMB enumeration with netexec (nxc) — the modern path for
    pulling the domain user list, password policy and SID off a DC. RID cycling is
    higher-volume, so it's gated to lab/aggressive. Read-only; no auth attempted."""
    tool = _have_any(cfg, "nxc", "netexec")
    if not tool:
        return
    base = [tool, "smb", cfg.target, "-u", "", "-p", ""]
    # password policy + user list (low volume, run everywhere)
    rc, pol, _ = run(base + ["--pass-pol"], timeout=90)
    if "Minimum password length" in pol or "Password Complexity" in pol:
        lines = [l for l in pol.splitlines()
                 if any(k in l for k in ("password", "Lockout", "Complexity",
                                         "Minimum", "Maximum"))]
        out.append(EnumFinding(svc.port, tool, "domain password policy (null session)",
                               "\n".join(lines)[:1500] or pol[:1500],
                               tags={"pass_pol": True}))
    rc, usr, _ = run(base + ["--users"], timeout=120)
    users = sorted({m.group(1) for m in
                    re.finditer(r"^\S+\s+\S+\s+\d+\s+(?:smb\s+)?([^\s]+)\\([^\s]+)", usr, re.M)})
    # nxc prints '<ip> <port> <host> <DOMAIN\user> ...'; a simpler grab on the
    # '-Username-' column also works across versions.
    if not users:
        users = sorted({m.group(1) for m in re.finditer(r"\\([A-Za-z0-9._-]+)\s", usr)})
    if users:
        out.append(EnumFinding(svc.port, tool,
                               f"{len(users)} domain user(s) via null session",
                               "\n".join(users)[:1500],
                               tags={"ad_users": len(users)}))
    if _ad_active_ok(cfg):
        rc, rid, _ = run(base + ["--rid-brute"], timeout=180)
        rid_users = sorted({m.group(1) for m in
                            re.finditer(r"\\([A-Za-z0-9._-]+)\s+\(SidTypeUser\)", rid)})
        if rid_users and len(rid_users) > len(users):
            out.append(EnumFinding(svc.port, tool,
                                   f"{len(rid_users)} user(s) via RID cycling (null session)",
                                   "\n".join(rid_users)[:1500],
                                   tags={"ad_users": len(rid_users)}))


# --- NFS ----------------------------------------------------------------------
def _enum_nfs(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    """List NFS exports via `showmount -e` (queries the portmapper). A share
    exported to everyone ('*') is a direct file-read / privesc path on lab boxes —
    mount it and read or plant files. Read-only; we don't mount anything."""
    if not _have(cfg, "showmount", quiet=True):
        return
    rc, mounts, _ = run(["showmount", "-e", cfg.target], timeout=45)
    lines = [l.strip() for l in mounts.splitlines()
             if l.strip() and not l.lower().startswith("export list")]
    if not lines:
        return
    world = any("*" in l or "everyone" in l.lower() for l in lines)
    out.append(EnumFinding(
        svc.port, "showmount",
        f"{len(lines)} NFS export(s)" + (" — world-readable (*)" if world else ""),
        "\n".join(lines)[:1500],
        tags={"nfs_exports": True, "nfs_world": world}))


# --- SNMP --------------------------------------------------------------------
_SNMP_COMMUNITIES = ["public", "private", "community"]


def _parse_onesixtyone_community(out: str) -> str:
    """onesixtyone prints e.g. '10.0.0.5 [public] Hardware: ...'. Return the
    first community string found inside [brackets], or '' if none."""
    m = re.search(r"\[([^\]]+)\]", out)
    return m.group(1).strip() if m else ""


def _enum_snmp(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    community = ""
    if _have(cfg, "onesixtyone"):
        # onesixtyone takes ONE positional community; extra positionals are parsed
        # as additional HOSTS, so passing the list inline would probe bogus hosts
        # named 'private'/'community' and only test 'public'. Feed the strings via
        # a community file (-c) so all of them are actually tried against the target.
        comm_file = os.path.join(cfg.out_dir, "snmp_communities.txt")
        try:
            with open(comm_file, "w") as f:
                f.write("\n".join(_SNMP_COMMUNITIES) + "\n")
            rc, o, _ = run(["onesixtyone", "-c", comm_file, cfg.target], timeout=60)
        except OSError:
            # fall back to a single-community probe if we can't write the file
            rc, o, _ = run(["onesixtyone", cfg.target, _SNMP_COMMUNITIES[0]], timeout=60)
        found = _parse_onesixtyone_community(o)
        if found:
            community = found  # use the ACTUAL string, not a hardcoded 'public' (#8)
            out.append(EnumFinding(svc.port, "onesixtyone",
                                   f"SNMP community string found: {community}",
                                   o.strip()[:800], tags={"snmp_community": community}))

    # snmpwalk with whichever community we found (default to 'public' as a probe
    # if onesixtyone didn't run/return). The 'or True' dead-guard is gone (#8).
    walk_comm = community or "public"
    if _have(cfg, "snmpwalk"):
        rc, sw, _ = run(["snmpwalk", "-v2c", "-c", walk_comm, "-t", "5", cfg.target], timeout=120)
        if rc == 0 and sw.strip():
            out.append(EnumFinding(svc.port, "snmpwalk",
                                   f"SNMP tree readable with '{walk_comm}'",
                                   sw.strip()[:2500], tags={"snmp_community": walk_comm}))
    elif _have(cfg, "snmp-check", quiet=True):
        # Now genuinely reachable when snmpwalk is absent (was dead code, #8).
        rc, sc, _ = run(["snmp-check", cfg.target], timeout=120)
        if rc == 0 and sc.strip():
            out.append(EnumFinding(svc.port, "snmp-check", "SNMP details", sc.strip()[:2500]))


# --- DB / cache --------------------------------------------------------------
def _enum_dbcache(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    """Record the exposed datastore, then probe the unauthenticated ones (Redis,
    Elasticsearch) read-only. These are classic 'open by default' wins on labs."""
    out.append(EnumFinding(svc.port, "recon", f"DB/cache exposed: {svc.name} {svc.banner}",
                           tags={"db": svc.name}))
    name = svc.name.lower()
    if name == "redis" or svc.port == 6379:
        _probe_redis(cfg, svc, out)


def _probe_redis(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    """Unauthenticated Redis check via a raw socket (no redis-cli needed). Sends
    PING; a +PONG means no auth is required → read/write access to the keyspace."""
    import socket
    try:
        with socket.create_connection((cfg.target, svc.port), timeout=8) as s:
            s.sendall(b"PING\r\n")
            resp = s.recv(256).decode("utf-8", "ignore")
            if "PONG" in resp:
                s.sendall(b"INFO server\r\n")
                info_resp = s.recv(4096).decode("utf-8", "ignore")
                ver = next((l.split(":", 1)[1].strip() for l in info_resp.splitlines()
                            if l.startswith("redis_version:")), "?")
                out.append(EnumFinding(svc.port, "redis",
                                       f"UNAUTHENTICATED Redis access (no auth) — v{ver}",
                                       info_resp[:1500], tags={"unauth_redis": True}))
            elif "NOAUTH" in resp:
                out.append(EnumFinding(svc.port, "redis",
                                       "Redis requires authentication (NOAUTH)", resp[:200]))
    except OSError:
        pass


def _enum_elasticsearch(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    """Unauthenticated Elasticsearch over HTTP — read-only checks for the cluster
    banner and index listing (often exposes whole datasets on labs)."""
    if not _have(cfg, "curl", quiet=True):
        return
    base = f"http://{cfg.target}:{svc.port}"
    rc, root, _ = run(["curl", "-sk", "--max-time", "10", f"{base}/"], timeout=15)
    if '"cluster_name"' in root or '"lucene_version"' in root:
        rc, idx, _ = run(["curl", "-sk", "--max-time", "10", f"{base}/_cat/indices?v"], timeout=15)
        out.append(EnumFinding(svc.port, "elasticsearch",
                               "UNAUTHENTICATED Elasticsearch access",
                               (root + "\n\n" + idx)[:1800], tags={"unauth_es": True}))


# --- Active Directory: shared helpers ----------------------------------------
def _canonical_ldap_port(ports: list[int]) -> int:
    """The single LDAP port to enumerate when several are open. Prefer plain 389,
    then the Global Catalog 3268, then the TLS variants — all expose the same
    directory, so we only hit one."""
    for p in (389, 3268, 636, 3269):
        if p in ports:
            return p
    return min(ports) if ports else 389


def _ad_active_ok(cfg: RunConfig) -> bool:
    """Higher-volume AD enumeration (RID cycling, kerbrute over a full wordlist) is
    fine on lab/aggressive but too noisy for the gentle/HTB or stealth profile —
    those get only the low-volume probes (root DSE, AS-REP on a small seed list)."""
    if getattr(cfg, "stealth", False):
        return False
    return cfg.aggressive or cfg.profile.name.startswith("lab")


def _ad_userlist(cfg: RunConfig) -> str:
    """Path to a username list for Kerberos enumeration. Only --aggressive pulls
    the full SecLists username wordlist — feeding thousands of names to GetNPUsers
    / krb5-enum-users one AS-REQ at a time overruns the per-tool timeout and the
    run silently produces nothing. The default (incl. plain lab) uses the small
    built-in seed of common AD/service accounts: fast and catches the usual wins."""
    if cfg.aggressive:
        wl = wordlists.username_wordlist(cfg, cfg.wordlist_users)
        if wl:
            return wl
    seed = os.path.join(cfg.out_dir, "ad_users_seed.txt")
    try:
        with open(seed, "w") as f:
            f.write("\n".join(_COMMON_AD_USERS) + "\n")
        return seed
    except OSError:
        return ""


# --- LDAP --------------------------------------------------------------------
def _ldap_naming_context(contexts: list[str]) -> str:
    """Pull the domain naming context (DC=lab,DC=local) from root-DSE lines,
    preferring defaultNamingContext over the schema/config contexts."""
    default = ""
    first = ""
    for line in contexts:
        low = line.lower()
        val = line.split(":", 1)[1].strip() if ":" in line else ""
        if not val:
            continue
        if low.startswith("defaultnamingcontext:"):
            default = val
        elif low.startswith("namingcontexts:") and "dc=" in low and "cn=" not in low:
            first = first or val
    return default or first


def _domain_from_naming_context(nc: str) -> str:
    """'DC=lab,DC=local' -> 'lab.local'. Returns '' if no DC= components."""
    parts = [p.split("=", 1)[1] for p in nc.split(",")
             if p.strip().lower().startswith("dc=") and "=" in p]
    return ".".join(parts).lower() if parts else ""


def _enum_ldap(cfg: RunConfig, svc: Service, out: list[EnumFinding],
               domain: str = "") -> None:
    """Anonymous LDAP bind: read the root DSE for naming contexts (domain layout),
    then — if the bind is anonymous-readable — attempt a subtree dump for users
    and password-bearing description fields. Anonymous read is a common AD/LDAP
    misconfiguration; the description field frequently holds plaintext passwords."""
    if not _have(cfg, "ldapsearch", quiet=True):
        return
    scheme = "ldaps" if svc.port in (636, 3269) else "ldap"
    url = f"{scheme}://{cfg.target}:{svc.port}"
    rc, ls, _ = run(["ldapsearch", "-x", "-H", url,
                     "-s", "base", "-b", "", "namingContexts", "defaultNamingContext"],
                    timeout=45)
    contexts = [l for l in ls.splitlines() if l.lower().startswith("namingcontexts:")
                or l.lower().startswith("defaultnamingcontext:")]
    if not contexts:
        return
    nc = _ldap_naming_context(contexts)
    dom = _domain_from_naming_context(nc) or domain
    tags = {"anon_ldap": True}
    if dom:
        tags["ad_domain"] = dom
    out.append(EnumFinding(svc.port, "ldapsearch",
                           "anonymous LDAP bind — root DSE readable"
                           + (f" (domain {dom})" if dom else ""),
                           "\n".join(contexts)[:1500], tags=tags))
    if not nc:
        return
    # Anonymous subtree read is usually denied on hardened AD (only the root DSE
    # is anon-readable) — but when it IS allowed it leaks the whole user list and
    # any passwords stashed in description fields. Best-effort; quiet on failure.
    rc, dump, _ = run(["ldapsearch", "-x", "-H", url, "-b", nc, "-s", "sub",
                       "(&(objectClass=user)(objectCategory=person))",
                       "sAMAccountName", "userPrincipalName", "description"],
                      timeout=90)
    users = [l.split(":", 1)[1].strip() for l in dump.splitlines()
             if l.lower().startswith("samaccountname:")]
    descs = [l for l in dump.splitlines() if l.lower().startswith("description:")]
    if users:
        out.append(EnumFinding(svc.port, "ldapsearch",
                               f"anonymous LDAP allows user enumeration — {len(users)} account(s)",
                               "\n".join(users)[:1500],
                               tags={"ldap_users": len(users), "ad_domain": dom}))
    secret_descs = [d for d in descs
                    if re.search(r"pass|pwd|secret|cred", d, re.I)]
    if secret_descs:
        out.append(EnumFinding(svc.port, "ldapsearch",
                               "password-like value in LDAP description field(s) "
                               "(readable anonymously)",
                               "\n".join(secret_descs)[:1500],
                               tags={"ldap_secret": True}))


# --- Kerberos ----------------------------------------------------------------
def _have_any(cfg: RunConfig, *tools: str) -> str:
    """Return the first of `tools` that is installed, or '' if none are."""
    for t in tools:
        if cfg.discovered_tools.get(t):
            return t
    return ""


def _enum_kerberos(cfg: RunConfig, svc: Service, out: list[EnumFinding],
                   domain: str) -> None:
    """Credential-less Kerberos enumeration on a DC (port 88):
      - kerbrute / krb5-enum-users: validate usernames (no creds needed).
      - GetNPUsers (AS-REP roasting): accounts with pre-auth disabled yield a
        crackable hash with NO credentials — the classic DC first-blood.
    All read-only enumeration; vantage never cracks or uses the hashes."""
    if not domain:
        out.append(EnumFinding(svc.port, "recon",
                               "Kerberos (88) — Active Directory DC; realm not "
                               "auto-detected. Re-run with --hostname <fqdn> or read "
                               "it from the LDAP root DSE to enable user/AS-REP enum."))
        return
    out.append(EnumFinding(svc.port, "recon",
                           f"Kerberos (88) — Active Directory DC for realm {domain}",
                           tags={"ad_domain": domain, "ad_dc": True}))
    userlist = _ad_userlist(cfg)
    # --aggressive uses the full username wordlist (thousands of AS-REQs), so give
    # the Kerberos tools a much larger budget; the default seed run stays snappy.
    kt = 600 if cfg.aggressive else 180

    # 1. Username validation. kerbrute is fastest/quietest; fall back to the always
    #    -present nmap krb5-enum-users script.
    valid_users: list[str] = []
    if userlist and _have(cfg, "kerbrute", quiet=True) and _ad_active_ok(cfg):
        rc, kb, _ = run(["kerbrute", "userenum", "--dc", cfg.target, "-d", domain,
                         userlist, "-o", "/dev/stdout"], timeout=kt)
        valid_users = sorted({m.group(1) for m in
                              re.finditer(r"VALID USERNAME:\s+([^@\s]+)@", kb)})
        if valid_users:
            out.append(EnumFinding(svc.port, "kerbrute",
                                   f"{len(valid_users)} valid AD username(s) via Kerberos",
                                   "\n".join(valid_users)[:1500],
                                   tags={"ad_users": len(valid_users), "ad_domain": domain}))
    elif userlist and _have(cfg, "nmap", quiet=True):
        rc, nse, _ = run(["nmap", "-p", "88", "--script", "krb5-enum-users",
                          "--script-args",
                          f"krb5-enum-users.realm={domain},userdb={userlist}",
                          cfg.target], timeout=kt)
        valid_users = sorted({m.group(1) for m in
                              re.finditer(r"^\|\s+([^@\s]+)@", nse, re.M)})
        if valid_users:
            out.append(EnumFinding(svc.port, "krb5-enum-users",
                                   f"{len(valid_users)} valid AD username(s) via Kerberos",
                                   "\n".join(valid_users)[:1500],
                                   tags={"ad_users": len(valid_users), "ad_domain": domain}))

    # 2. AS-REP roasting (no creds). Prefer impacket's GetNPUsers; feed it the
    #    validated users if we found any, else the seed/wordlist.
    getnp = _have_any(cfg, "impacket-GetNPUsers", "GetNPUsers.py", "GetNPUsers")
    if getnp and userlist:
        roast_file = userlist
        if valid_users:
            roast_file = os.path.join(cfg.out_dir, "ad_valid_users.txt")
            try:
                with open(roast_file, "w") as f:
                    f.write("\n".join(valid_users) + "\n")
            except OSError:
                roast_file = userlist
        rc, npo, _ = run([getnp, f"{domain}/", "-dc-ip", cfg.target, "-no-pass",
                          "-usersfile", roast_file, "-format", "hashcat"], timeout=kt)
        hashes = [l.strip() for l in npo.splitlines() if l.startswith("$krb5asrep$")]
        if hashes:
            out.append(EnumFinding(svc.port, "GetNPUsers",
                                   f"AS-REP roastable account(s): {len(hashes)} — "
                                   "crackable offline with NO credentials",
                                   "\n".join(hashes)[:2000],
                                   tags={"asrep_roast": True, "ad_domain": domain}))
    elif not getnp:
        out.append(EnumFinding(svc.port, "recon",
                               "AS-REP roast not run (impacket GetNPUsers absent). "
                               f"Try: GetNPUsers {domain}/ -dc-ip {cfg.target} -no-pass "
                               "-usersfile users.txt -format hashcat"))


# --- Docker API --------------------------------------------------------------
def _enum_docker_api(cfg: RunConfig, svc: Service, out: list[EnumFinding]) -> None:
    """Unauthenticated Docker Engine API (2375) = full host compromise (run a
    privileged container, mount /). Read-only check of /version here."""
    if not _have(cfg, "curl", quiet=True):
        return
    rc, ver, _ = run(["curl", "-sk", "--max-time", "10",
                      f"http://{cfg.target}:{svc.port}/version"], timeout=15)
    if '"ApiVersion"' in ver or '"Version"' in ver:
        out.append(EnumFinding(svc.port, "docker-api",
                               "UNAUTHENTICATED Docker Engine API — host takeover risk",
                               ver[:1200], tags={"unauth_docker": True}))
