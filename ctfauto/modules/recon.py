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
    nse_vuln_hits: list[str] = field(default_factory=list)  # parsed vuln-script findings

    @property
    def all_services(self) -> list[Service]:
        return self.services + self.udp_services


def _xml_path(cfg: RunConfig) -> str:
    return os.path.join(cfg.out_dir, f"nmap_{cfg.target.replace('/', '_')}.xml")


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
                          nse_vuln_hits=r.get("nse_vuln_hits", []))
        host.services = [Service(**s) for s in r.get("services", [])]
        host.udp_services = [Service(**s) for s in r.get("udp_services", [])]
        return host
    except (TypeError, ValueError):
        return None


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
    cmd = [
        "nmap", cfg.profile.nmap_timing,
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

    # UDP top-ports pass (lab profile, unless --no-udp). UDP is slow, so keep it small.
    if cfg.profile.udp_scan and not cfg.no_udp:
        host.udp_services = _udp_scan(cfg)

    # NSE vuln scripts against the open TCP ports we found.
    if cfg.profile.nse_vuln and not cfg.no_nse_vuln and host.services:
        host.nse_vuln_hits = _nse_vuln_scan(cfg, host)

    # Persist recon so a later --resume can skip the (slow) scan (#13).
    try:
        save_state(cfg.out_dir, cfg.target, _host_to_state(host))
    except OSError:
        pass
    return host


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


def _nse_vuln_scan(cfg: RunConfig, host: HostResult) -> list[str]:
    info("NSE vuln scripts (--script vuln + smb-vuln-*)")
    ports = ",".join(str(s.port) for s in host.services)
    out_path = os.path.join(cfg.out_dir, f"nmap_vuln_{cfg.target.replace('/', '_')}.txt")
    cmd = ["nmap", "-sV", "-p", ports,
           "--script", "vuln,smb-vuln-*,ssl-enum-ciphers",
           "-oN", out_path, cfg.target]
    rc, out, _ = run(cmd, timeout=1800)
    hits: list[str] = []
    cur_port = ""
    for line in out.splitlines():
        stripped = line.strip()
        if "/tcp" in line and "open" in line:
            cur_port = line.split("/")[0].strip()
        # nmap marks confirmed vulns with "VULNERABLE" and CVE refs.
        # Parenthesised explicitly (precedence was correct but fragile to read).
        if ("VULNERABLE" in stripped) or (
            stripped.startswith("|") and ("CVE-" in stripped or "State: VULNERABLE" in stripped)):
            hits.append(f"[:{cur_port or '?'}] {stripped.lstrip('| ')}")
    if hits:
        good(f"NSE flagged {len(hits)} potential vuln line(s)")
        for h in hits[:15]:
            info(f"  {h}")
    return hits


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
