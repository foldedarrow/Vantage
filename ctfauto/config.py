"""Configuration, profiles, and the safety/scope guard for ctfauto."""
from __future__ import annotations

import ipaddress
import shutil
from dataclasses import dataclass, field

# RFC1918 ranges considered "lab-safe" for full automation (owned VMs).
# NOTE: HTB networks below are carved out of 10/8 and MUST be classified first,
# otherwise a HackTheBox target would fall into 'lab' and get the aggressive
# profile (see classify_target — HTB is checked before LAB).
LAB_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# HackTheBox lab VPN ranges. These are *shared infra*: HTB's rules prohibit
# aggressive/automated mass scanning. We detect these and force the gentle
# profile; --aggressive is ignored for them.
#
# Broadened from the original three /24-ish ranges: HTB machine/lab traffic
# appears across 10.10.0.0/16 (labs, release arena, seasonal) and 10.129.0.0/16
# (the main machine pool). Pro Lab / Enterprise ranges vary per lab — add yours
# to ~/.config/ctfauto/networks.json (key "htb") and it'll be merged in.
HTB_NETWORKS = [
    ipaddress.ip_network("10.10.0.0/16"),    # labs, release arena, starting point, tun handouts
    ipaddress.ip_network("10.129.0.0/16"),   # main active-machine pool
]

# The operator's OWN VPN client IP range (HTB tun0 typically 10.10.14.x/15.x).
# We never want to classify (or scan) our own assigned address as a target.
# This is informational; the real guard is "don't scan yourself" in cli.
OWN_VPN_HINT_NETWORKS = [
    ipaddress.ip_network("10.10.14.0/23"),
    ipaddress.ip_network("10.10.16.0/23"),
]


def _load_user_networks() -> dict:
    """Merge user-supplied network overrides from ~/.config/ctfauto/networks.json.
    Format: {"htb": ["10.13.37.0/24"], "lab": ["192.168.10.0/24"]}.
    Silently ignored if absent or malformed — never blocks a run."""
    import json
    import os
    path = os.path.expanduser("~/.config/ctfauto/networks.json")
    extra = {"htb": [], "lab": []}
    if not os.path.exists(path):
        return extra
    try:
        with open(path) as f:
            data = json.load(f)
        for key in ("htb", "lab"):
            for cidr in data.get(key, []):
                try:
                    extra[key].append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
    except (OSError, ValueError):
        pass
    return extra


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
    # --- enumeration intensity (profile-aware noise control, issue #14) -------
    enable_nikto: bool = True       # nikto is loud; off on gentle/HTB
    enable_dirbust: bool = True     # gobuster/feroxbuster dir brute
    enable_active_web: bool = True  # crawl->sqlmap/LFI active web stage
    full_tcp: bool = True           # -p- vs --top-ports on gentle

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
            enable_nikto=False,    # don't blast shared infra with nikto
            enable_dirbust=True,   # a quiet dir pass is fine
            enable_active_web=False,  # no auto sqlmap/LFI on shared infra
            full_tcp=False,        # top-1000 only
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
            enable_nikto=True,
            enable_dirbust=True,
            enable_active_web=True,
            full_tcp=True,
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
    max_time: int = 0                # global wall-clock budget (s); 0 = unlimited (#17)
    no_udp: bool = False             # force-disable UDP even on lab
    no_nse_vuln: bool = False        # force-disable --script vuln
    default_creds: bool = True       # try default credentials (safe, on by default)
    post_exploit: bool = False       # stage privesc enum over opened sessions
    peas_dir: str = ""               # local dir holding linpeas.sh / winPEAS.exe
    # --- scope / authorization (issues #1, #2, #4) ----------------------------
    klass: str = "external"          # 'htb' | 'lab' | 'external' (set by cli)
    allow_external: bool = False     # explicit opt-in to actively touch an external target
    events_path: str = ""            # NDJSON event log path (issue #25); "" = disabled
    seclists_dir: str = ""           # override SecLists root (else auto-detect / $CTFAUTO_SECLISTS)
    # --- cloud recon (unauthenticated public-misconfig discovery) -------------
    cloud: bool = False              # run the cloud recon phase
    allow_cloud: bool = False        # explicit authorization to enumerate cloud targets
    cloud_name: str = ""             # seed: a keyword (acme) or domain (acme.com)
    cloud_providers: tuple = ("aws",)  # which providers to probe: aws, azure
    cloud_extra_words: str = ""      # comma-separated extra permutation words
    cloud_candidate_cap: int = 200   # max candidate names to probe (politeness bound)


def classify_target(target: str) -> str:
    """Return 'htb', 'lab', or 'external' for a target IP/host.

    HTB is checked BEFORE lab on purpose: HTB ranges are carved out of 10/8,
    so checking lab first would misclassify HTB machines as lab and hand them
    the aggressive profile. User overrides from networks.json are merged in.
    """
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # hostname — we can't safely classify by IP. Most cautious: external.
        # (cli will resolve it and re-classify on the resolved IP where possible.)
        return "external"
    extra = _load_user_networks()
    for net in list(HTB_NETWORKS) + extra["htb"]:
        if ip in net:
            return "htb"
    for net in list(LAB_NETWORKS) + extra["lab"]:
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
        "mysql", "git-dumper", "feroxbuster", "arjun",
        # cloud recon (unauthenticated misconfig discovery)
        "aws", "s3scanner", "cloud_enum",
    ]
    return {t: shutil.which(t) for t in tools}
