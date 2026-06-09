"""Configuration, profiles, and the safety/scope guard for ctfauto."""
from __future__ import annotations

import ipaddress
import shutil
from dataclasses import dataclass, field

# RFC1918 + HTB ranges considered "lab-safe" for full automation.
LAB_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# HackTheBox lab VPN handout ranges (10.10.x). These are *shared infra*:
# HTB's rules prohibit aggressive/automated mass scanning. We detect these
# and force the gentle profile unless the user explicitly overrides.
HTB_NETWORKS = [
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("10.10.11.0/24"),
    ipaddress.ip_network("10.129.0.0/16"),
]


@dataclass
class Profile:
    """Scan/enum tuning. 'gentle' is used for HTB; 'lab' for owned VMs."""
    name: str
    nmap_timing: str          # -T2 (gentle) .. -T4 (lab)
    nmap_args: str
    enable_brute: bool        # only with --aggressive
    enable_auto_exploit: bool
    http_threads: int
    max_brute_attempts: int
    udp_scan: bool            # run a UDP top-ports pass
    nse_vuln: bool            # run --script vuln (noisy)
    parallelism: int          # concurrent per-service enumeration workers

    @classmethod
    def gentle(cls) -> "Profile":
        return cls(
            name="gentle (HTB / shared infra)",
            nmap_timing="-T2",
            nmap_args="-sV -sC --open",
            enable_brute=False,
            enable_auto_exploit=False,
            http_threads=10,
            max_brute_attempts=0,
            udp_scan=False,        # UDP scans are slow + noisy on shared infra
            nse_vuln=False,
            parallelism=2,
        )

    @classmethod
    def lab(cls) -> "Profile":
        return cls(
            name="lab (owned VMs)",
            nmap_timing="-T4",
            nmap_args="-sV -sC -O --open",
            enable_brute=False,        # flipped on by --aggressive
            enable_auto_exploit=True,  # safe modules only unless --aggressive
            http_threads=40,
            max_brute_attempts=200,
            udp_scan=True,
            nse_vuln=True,
            parallelism=6,
        )


@dataclass
class RunConfig:
    target: str
    profile: Profile
    aggressive: bool = False
    auto_exploit: bool = False
    identify_only: bool = False
    out_dir: str = "loot"
    wordlist_dirs: str = ""          # gobuster wordlist
    wordlist_users: str = ""
    wordlist_pass: str = ""
    discovered_tools: dict = field(default_factory=dict)
    hostname: str = ""               # resolved/added .htb name, if any
    resume: bool = False             # reuse cached phase state
    no_udp: bool = False             # force-disable UDP even on lab
    no_nse_vuln: bool = False        # force-disable --script vuln
    default_creds: bool = True       # try default credentials (safe, on by default)
    post_exploit: bool = False       # stage privesc enum over opened sessions
    peas_dir: str = ""               # local dir holding linpeas.sh / winPEAS.exe


def classify_target(target: str) -> str:
    """Return 'htb', 'lab', or 'external' for a target IP/host."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # hostname — can't classify by IP, treat as external (most cautious)
        return "external"
    for net in HTB_NETWORKS:
        if ip in net:
            return "htb"
    for net in LAB_NETWORKS:
        if ip in net:
            return "lab"
    return "external"


def detect_tools() -> dict:
    """Map of tool name -> path (or None if missing)."""
    tools = [
        "nmap", "gobuster", "nikto", "hydra", "searchsploit",
        "msfconsole", "msfrpcd", "enum4linux", "smbclient", "whatweb",
        "ffuf", "curl", "wget",
        # new recon/enum tooling
        "onesixtyone", "snmpwalk", "snmp-check", "sslscan",
        "wpscan", "droopescan", "sqlmap", "mount", "showmount",
        "mysql", "git-dumper",
    ]
    return {t: shutil.which(t) for t in tools}
