"""Recon module: nmap host discovery + service/version detection with XML parsing."""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict

from ..config import RunConfig
from ..util import good, info, run, warn, load_state, save_state


@dataclass
class Service:
    port: int
    proto: str
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    state: str = "open"

    @property
    def banner(self) -> str:
        return " ".join(p for p in [self.product, self.version, self.extrainfo] if p).strip()


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)
    udp_services: list[Service] = field(default_factory=list)
    nse_vuln_hits: list[str] = field(default_factory=list)  # flat parsed lines (compat)
    nse_by_port: dict = field(default_factory=dict)         # port(str) -> [lines]
    nse_cves: list[str] = field(default_factory=list)       # unique CVE IDs, CVSS-desc
    nse_cve_scores: dict = field(default_factory=dict)      # CVE id -> CVSS float (if seen)

    @property
    def all_services(self) -> list[Service]:
        return self.services + self.udp_services


def _xml_path(cfg: RunConfig) -> str:
    return os.path.join(cfg.out_dir, f"nmap_{cfg.target.replace('/', '_')}.xml")


def is_cidr(target: str) -> bool:
    """A CIDR/range target (e.g. 10.0.0.0/24) vs a single host."""
    return "/" in target


def _discovery_perf_flags(cfg: RunConfig) -> list[str]:
    """Host-discovery + performance flags.

    `-Pn` (skip ping) for a SINGLE host: firewalled HTB/external boxes commonly
    drop ICMP, so without it nmap marks them 'down' and we get an empty report —
    the target is already authorized, so discovery only risks a false negative.
    For a CIDR we deliberately KEEP discovery so dead hosts are pruned from the
    sweep. `--max-retries 2` stops slow-filtered ports stalling the run; lab gets
    `--min-rate 1000` for speed (omitted on gentle/HTB to stay polite)."""
    if getattr(cfg, "stealth", False):
        return _stealth_nmap_flags(cfg)
    flags = ["--max-retries", "2"]
    if not is_cidr(cfg.target):
        flags.insert(0, "-Pn")
    if cfg.profile.nmap_timing == "-T4":  # lab profile
        flags += ["--min-rate", "1000"]
    return flags


def _stealth_nmap_flags(cfg: RunConfig) -> list[str]:
    """Evasion flags for AUTHORIZED detection testing. Low-and-slow + signature
    reduction so you can measure whether the SOC/IDS catches it:
      -f               fragment packets (defeat naive signature matching)
      --max-rate       hard cap on packets/sec (default 50 — well under most thresholds)
      --scan-delay     space probes out in time (default 250ms)
      --max-retries 1  fewer retransmits = fewer packets
      --randomize-hosts shuffle target order on a sweep
      --source-port    optional: appear to come from 53/80/443 to slip naive ACLs
      -D               optional: hide the real source among decoys
    All of these need root (raw packets); ctfauto already runs under sudo."""
    flags: list[str] = ["--max-retries", "1", "--randomize-hosts"]
    if not is_cidr(cfg.target):
        flags.insert(0, "-Pn")
    if not getattr(cfg, "no_fragment", False):
        flags.append("-f")
    flags += ["--max-rate", str(cfg.max_rate or 50)]
    flags += ["--scan-delay", cfg.scan_delay or "250ms"]
    if cfg.source_port:
        flags += ["--source-port", str(cfg.source_port)]
    if cfg.decoys:
        flags += ["-D", cfg.decoys]
    return flags


def detect_htb_hostname(cfg: RunConfig) -> str:
    """Probe :80/:443 for a redirect or TLS cert revealing a *.htb hostname,
    common on HackTheBox. Returns the hostname if found, else ''."""
    if not cfg.discovered_tools.get("curl"):
        return ""
    # 1. HTTP redirect Location header
    rc, out, _ = run(["curl", "-sI", "--max-time", "10", f"http://{cfg.target}/"], timeout=15)
    for line in out.splitlines():
        if line.lower().startswith("location:") and ".htb" in line.lower():
            host = line.split("//", 1)[-1].split("/", 1)[0].strip()
            if host:
                return host
    # 2. TLS cert CN/SAN
    rc, out, _ = run(["curl", "-vk", "--max-time", "10", f"https://{cfg.target}/"], timeout=15)
    import re as _re
    m = _re.search(r"CN=([A-Za-z0-9.\-]+\.htb)", out)
    if m:
        return m.group(1)
    return ""


def add_to_hosts(ip: str, hostname: str) -> bool:
    """Best-effort add 'ip<TAB>hostname' to /etc/hosts (needs root).

    Matches the hostname as an exact whitespace-delimited token (so 'box.htb'
    doesn't spuriously match 'devbox.htb'), and reconciles the IP if an entry
    for this hostname already exists with a different address (#5)."""
    if not hostname:
        return False
    try:
        with open("/etc/hosts") as f:
            lines = f.readlines()
    except OSError as e:
        warn(f"could not read /etc/hosts: {e}")
        return False

    for ln in lines:
        stripped = ln.split("#", 1)[0]
        toks = stripped.split()
        if hostname in toks[1:]:
            if toks and toks[0] == ip:
                return True  # already correct
            warn(f"/etc/hosts already maps '{hostname}' to {toks[0] if toks else '?'}, "
                 f"not {ip}. Leaving it; update manually if the box IP changed.")
            return True
    try:
        with open("/etc/hosts", "a") as f:
            f.write(f"{ip}\t{hostname}\n")
        good(f"added '{ip} {hostname}' to /etc/hosts")
        return True
    except PermissionError:
        warn(f"need root to add '{ip} {hostname}' to /etc/hosts — add it manually.")
        return False


def _host_to_state(host: HostResult) -> dict:
    return {"recon": asdict(host)}


def _host_from_state(d: dict) -> HostResult | None:
    r = (d or {}).get("recon")
    if not r:
        return None
    try:
        host = HostResult(ip=r.get("ip", ""), hostname=r.get("hostname", ""),
                          os_guess=r.get("os_guess", ""),
                          nse_vuln_hits=r.get("nse_vuln_hits", []),
                          nse_by_port=r.get("nse_by_port", {}),
                          nse_cves=r.get("nse_cves", []),
                          nse_cve_scores=r.get("nse_cve_scores", {}))
        host.services = [Service(**s) for s in r.get("services", [])]
        host.udp_services = [Service(**s) for s in r.get("udp_services", [])]
        return host
    except (TypeError, ValueError):
        return None


def _banner_count(host: HostResult) -> int:
    """How many services have a real version banner (not blank/tcpwrapped)."""
    n = 0
    for s in host.services:
        if s.banner.strip() and s.name.lower() != "tcpwrapped":
            n += 1
    return n


def _mostly_tcpwrapped(host: HostResult) -> bool:
    """True when the scan found open ports but most carry no usable service
    info — the 'tcpwrapped'/empty-banner pattern that a connect scan fixes.
    Requires at least a couple of open ports so we don't over-trigger on a
    genuinely tiny target."""
    svcs = host.services
    if len(svcs) < 2:
        return False
    wrapped = sum(1 for s in svcs
                  if s.name.lower() == "tcpwrapped" or not s.banner.strip())
    return wrapped >= max(2, int(0.7 * len(svcs)))


def _rescan_connect(cfg: RunConfig, host: HostResult) -> HostResult | None:
    """Targeted TCP connect re-scan (-sT -sV) of the already-discovered open
    ports. Much faster than re-scanning all 65k ports, and connect scans aren't
    affected by the SYN-mangling that produces tcpwrapped."""
    ports = ",".join(str(s.port) for s in host.services)
    if not ports:
        return None
    xml_out = os.path.join(cfg.out_dir, f"nmap_connect_{cfg.target.replace('/', '_')}.xml")
    cmd = ["nmap", "-sT", "-sV", "--version-intensity", "9",
           cfg.profile.nmap_timing, "-p", ports, "--open",
           "-oX", xml_out, cfg.target]
    rc, _, _ = run(cmd, timeout=900)
    if not os.path.exists(xml_out):
        return None
    return parse_nmap_xml(xml_out)


def scan(cfg: RunConfig) -> HostResult:
    """Run nmap and parse results into a HostResult. With --resume, reuse a
    cached recon result if one exists (issue #13)."""
    if cfg.resume:
        cached = _host_from_state(load_state(cfg.out_dir, cfg.target))
        if cached and cached.services:
            good(f"--resume: reusing cached recon ({len(cached.services)} services) "
                 f"from previous run")
            return cached
        info("--resume: no usable cached recon; scanning fresh.")

    if not cfg.discovered_tools.get("nmap"):
        warn("nmap not found on PATH — cannot run recon. Install nmap.")
        return HostResult(ip=cfg.target)

    xml_out = _xml_path(cfg)
    # Full TCP scan when the profile allows it; top-ports on gentle to reduce
    # noise on shared infra. Keyed off the capability flag, not the name string.
    port_spec = ["-p-"] if cfg.profile.full_tcp else ["--top-ports", "1000"]
    # -sT (connect) when forced; otherwise nmap's default (SYN scan as root).
    scan_type = ["-sT"] if cfg.connect_scan else []
    cmd = [
        "nmap", cfg.profile.nmap_timing,
        *scan_type,
        *_discovery_perf_flags(cfg),
        *cfg.profile.nmap_args.split(),
        *port_spec,
        "-oX", xml_out,
        cfg.target,
    ]
    rc, out, _ = run(cmd, timeout=1800)
    if not os.path.exists(xml_out):
        warn("nmap did not produce an XML file; returning empty result.")
        return HostResult(ip=cfg.target)
    # rc may be non-zero (host-down, partial) but a usable XML can still exist;
    # parse defensively rather than bailing on rc alone.
    host = parse_nmap_xml(xml_out)
    if not host.services and rc != 0:
        warn(f"nmap exited rc={rc} with no parsed services; results may be incomplete.")

    # tcpwrapped fallback: a SYN scan that comes back with mostly 'tcpwrapped'
    # (no banners) is the classic signature of a hypervisor NAT / virtual-NIC
    # mangling half-open connections. A TCP connect scan (-sT) sees through it.
    # Re-scan the discovered ports with -sT -sV and keep whichever result is
    # richer. Skipped if the user already forced -sT.
    if not cfg.connect_scan and _mostly_tcpwrapped(host):
        warn("scan returned mostly 'tcpwrapped' (no service banners) — this usually "
             "means a SYN scan is being interfered with (hypervisor NAT/virtual NIC). "
             "Re-scanning the open ports with a TCP connect scan (-sT)...")
        better = _rescan_connect(cfg, host)
        if better and _banner_count(better) > _banner_count(host):
            good(f"connect-scan recovered {_banner_count(better)} service banner(s) "
                 f"(was {_banner_count(host)}). Using connect-scan results.")
            # preserve any ports the first scan saw but the targeted rescan didn't
            known = {s.port for s in better.services}
            for s in host.services:
                if s.port not in known:
                    better.services.append(s)
            better.services.sort(key=lambda s: s.port)
            host = better
        else:
            warn("connect-scan did not improve results; keeping original scan.")

    # UDP top-ports pass (lab profile, unless --no-udp). UDP is slow, so keep it small.
    if cfg.profile.udp_scan and not cfg.no_udp:
        host.udp_services = _udp_scan(cfg)

    # NSE vuln scripts against the open TCP ports we found.
    if cfg.profile.nse_vuln and not cfg.no_nse_vuln and host.services:
        _nse_vuln_scan(cfg, host)

    # Persist recon so a later --resume can skip the (slow) scan (#13).
    try:
        save_state(cfg.out_dir, cfg.target, _host_to_state(host))
    except OSError:
        pass
    return host


def discover_hosts(cfg: RunConfig) -> list[str]:
    """Ping-sweep a CIDR/range (nmap -sn) and return the live host IPs. We KEEP
    host discovery here (no -Pn) precisely so dead addresses are pruned — a /16
    with -Pn would be 65k hosts. Hosts that block ping are missed; that's the
    accepted trade for a bounded sweep."""
    if not cfg.discovered_tools.get("nmap"):
        warn("nmap not found on PATH — cannot discover hosts.")
        return []
    xml_out = os.path.join(cfg.out_dir, f"nmap_discover_{cfg.target.replace('/', '_')}.xml")
    cmd = ["nmap", "-sn", cfg.profile.nmap_timing, "-oX", xml_out, cfg.target]
    run(cmd, timeout=1800)
    if not os.path.exists(xml_out):
        return []
    return [h.ip for h in parse_nmap_xml_all(xml_out) if h.ip]


def _udp_scan(cfg: RunConfig) -> list[Service]:
    info("UDP top-50 scan (slow; SNMP/DNS/TFTP/etc.)")
    xml_out = os.path.join(cfg.out_dir, f"nmap_udp_{cfg.target.replace('/', '_')}.xml")
    cmd = ["nmap", "-sU", cfg.profile.nmap_timing, "--top-ports", "50",
           "--open", "-oX", xml_out, cfg.target]
    rc, _, _ = run(cmd, timeout=1200)
    if not os.path.exists(xml_out):
        return []
    udp_host = parse_nmap_xml(xml_out)
    for s in udp_host.services:
        s.proto = "udp"
    if udp_host.services:
        good(f"{len(udp_host.services)} open UDP service(s)")
    return udp_host.services


def _nse_vuln_scan(cfg: RunConfig, host: HostResult) -> None:
    """Run NSE vuln scripts and populate host.nse_by_port (grouped per port),
    host.nse_vuln_hits (flat, for back-compat), and host.nse_cves (unique CVE
    IDs). Previously every matched line became its own finding downstream, which
    exploded the report into hundreds of ':0' entries — now they're grouped."""
    import re as _re
    info("NSE vuln scripts (--script vuln + smb-vuln-*)")
    ports = ",".join(str(s.port) for s in host.services)
    out_path = os.path.join(cfg.out_dir, f"nmap_vuln_{cfg.target.replace('/', '_')}.txt")
    # Honour the profile timing (gentle/HTB stays at -T2) — the whole point of the
    # gentle profile is to be quiet on shared infra, and the NSE pass is the loudest
    # step. -sV is dropped: recon already version-detected these ports.
    cmd = ["nmap", cfg.profile.nmap_timing, "-p", ports,
           "--script", "vuln,smb-vuln-*,ssl-enum-ciphers",
           "-oN", out_path, cfg.target]
    rc, out, _ = run(cmd, timeout=1800)

    by_port: dict[str, list[str]] = {}
    flat: list[str] = []
    cves: list[str] = []
    scores: dict[str, float] = {}
    cve_re = _re.compile(r"CVE-\d{4}-\d{4,7}")
    # vulners lines look like 'CVE-2026-35414    8.1    https://...'; capture the score.
    cve_score_re = _re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}(?:\.\d)?)\b")
    cur_port = "?"
    for line in out.splitlines():
        stripped = line.strip()
        if "/tcp" in line and "open" in line:
            cur_port = line.split("/")[0].strip()
        if ("VULNERABLE" in stripped) or (
            stripped.startswith("|") and ("CVE-" in stripped or "State: VULNERABLE" in stripped)):
            clean = stripped.lstrip("| ")
            by_port.setdefault(cur_port, []).append(clean)
            flat.append(f"[:{cur_port}] {clean}")
            for cve in cve_re.findall(stripped):
                if cve not in cves:
                    cves.append(cve)
            for cve, score in cve_score_re.findall(stripped):
                try:
                    scores[cve] = float(score)
                except ValueError:
                    pass

    # Rank CVEs by CVSS (highest first); unscored ones sort last but stay listed.
    cves.sort(key=lambda c: scores.get(c, -1.0), reverse=True)
    host.nse_by_port = by_port
    host.nse_vuln_hits = flat
    host.nse_cves = cves
    host.nse_cve_scores = scores
    if flat:
        n_ports = len(by_port)
        good(f"NSE flagged {len(flat)} vuln line(s) across {n_ports} port(s); "
             f"{len(cves)} unique CVE(s)")
        for port, lines in list(by_port.items())[:8]:
            info(f"  :{port} — {len(lines)} line(s)")


def _parse_host_el(host_el) -> HostResult:
    """Parse a single <host> element into a HostResult."""
    addr = ""
    for a in host_el.findall("address"):
        if a.get("addrtype") in ("ipv4", "ipv6"):
            addr = a.get("addr", "")
            break

    hostname = ""
    hn = host_el.find("hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name", "")

    os_guess = ""
    osmatch = host_el.find("os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name", "")

    result = HostResult(ip=addr, hostname=hostname, os_guess=os_guess)
    for port_el in host_el.findall("ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc_el = port_el.find("service")
        try:
            portid = int(port_el.get("portid"))
        except (TypeError, ValueError):
            continue
        svc = Service(
            port=portid,
            proto=port_el.get("protocol", "tcp"),
            name=(svc_el.get("name", "") if svc_el is not None else ""),
            product=(svc_el.get("product", "") if svc_el is not None else ""),
            version=(svc_el.get("version", "") if svc_el is not None else ""),
            extrainfo=(svc_el.get("extrainfo", "") if svc_el is not None else ""),
        )
        result.services.append(svc)
    return result


def parse_nmap_xml_all(path: str) -> list[HostResult]:
    """Parse EVERY <host> in an nmap XML file (multi-host / CIDR support, #16).
    Defensive against truncated/malformed XML (#15): returns [] on parse error."""
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as e:
        warn(f"could not parse nmap XML ({os.path.basename(path)}): {e}")
        return []
    root = tree.getroot()
    hosts = []
    for host_el in root.findall("host"):
        # Skip hosts nmap marked as down.
        status = host_el.find("status")
        if status is not None and status.get("state") == "down":
            continue
        hosts.append(_parse_host_el(host_el))
    return hosts


def parse_nmap_xml(path: str) -> HostResult:
    """Back-compat single-host parse. Returns the first up host (or empty).
    Robust to malformed XML — never raises (#15)."""
    hosts = parse_nmap_xml_all(path)
    if not hosts:
        return HostResult(ip="")
    result = hosts[0]
    good(f"{len(result.services)} open service(s) on {result.ip or '?'}"
         + (f" ({result.os_guess})" if result.os_guess else ""))
    for s in result.services:
        info(f"  {s.port}/{s.proto}  {s.name:12} {s.banner}")
    if len(hosts) > 1:
        info(f"({len(hosts)} hosts in XML; using first — multi-host sweep handles the rest)")
    return result
