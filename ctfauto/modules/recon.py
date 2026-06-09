"""Recon module: nmap host discovery + service/version detection with XML parsing."""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..config import RunConfig
from ..util import good, info, run, warn


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
    """Best-effort append ip<TAB>hostname to /etc/hosts (needs root)."""
    if not hostname:
        return False
    try:
        with open("/etc/hosts") as f:
            if hostname in f.read():
                return True
        with open("/etc/hosts", "a") as f:
            f.write(f"{ip}\t{hostname}\n")
        return True
    except PermissionError:
        warn(f"need root to add '{ip} {hostname}' to /etc/hosts — add it manually.")
        return False


def scan(cfg: RunConfig) -> HostResult:
    """Run nmap and parse results into a HostResult."""
    if not cfg.discovered_tools.get("nmap"):
        warn("nmap not found on PATH — cannot run recon. Install nmap.")
        return HostResult(ip=cfg.target)

    xml_out = _xml_path(cfg)
    # Full TCP scan on lab; top-ports on gentle to reduce noise on shared infra.
    port_spec = ["-p-"] if cfg.profile.name.startswith("lab") else ["--top-ports", "1000"]
    cmd = [
        "nmap", cfg.profile.nmap_timing,
        *cfg.profile.nmap_args.split(),
        *port_spec,
        "-oX", xml_out,
        cfg.target,
    ]
    rc, out, _ = run(cmd, timeout=1800)
    if rc not in (0,) or not os.path.exists(xml_out):
        warn("nmap did not produce parseable XML; returning empty result.")
        return HostResult(ip=cfg.target)

    host = parse_nmap_xml(xml_out)

    # UDP top-ports pass (lab profile, unless --no-udp). UDP is slow, so keep it small.
    if cfg.profile.udp_scan and not cfg.no_udp:
        host.udp_services = _udp_scan(cfg)

    # NSE vuln scripts against the open TCP ports we found.
    if cfg.profile.nse_vuln and not cfg.no_nse_vuln and host.services:
        host.nse_vuln_hits = _nse_vuln_scan(cfg, host)

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
        # nmap marks confirmed vulns with "VULNERABLE" and CVE refs
        if "VULNERABLE" in stripped or stripped.startswith("|") and (
            "CVE-" in stripped or "State: VULNERABLE" in stripped):
            hits.append(f"[:{cur_port or '?'}] {stripped.lstrip('| ')}")
    if hits:
        good(f"NSE flagged {len(hits)} potential vuln line(s)")
        for h in hits[:15]:
            info(f"  {h}")
    return hits


def parse_nmap_xml(path: str) -> HostResult:
    tree = ET.parse(path)
    root = tree.getroot()
    host_el = root.find("host")
    if host_el is None:
        return HostResult(ip="")

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
        svc = Service(
            port=int(port_el.get("portid")),
            proto=port_el.get("protocol", "tcp"),
            name=(svc_el.get("name", "") if svc_el is not None else ""),
            product=(svc_el.get("product", "") if svc_el is not None else ""),
            version=(svc_el.get("version", "") if svc_el is not None else ""),
            extrainfo=(svc_el.get("extrainfo", "") if svc_el is not None else ""),
        )
        result.services.append(svc)

    good(f"{len(result.services)} open service(s) on {result.ip or '?'}"
         + (f" ({os_guess})" if os_guess else ""))
    for s in result.services:
        info(f"  {s.port}/{s.proto}  {s.name:12} {s.banner}")
    return result
