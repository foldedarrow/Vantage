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
    http_threads: int
    udp_scan: bool            # run a UDP top-ports pass
    nse_vuln: bool            # run --script vuln (noisy)
    parallelism: int          # concurrent per-service enumeration workers
    # --- enumeration intensity (profile-aware noise control, issue #14) -------
    enable_nikto: bool = True       # nikto is loud; off on gentle/HTB
    enable_dirbust: bool = True     # gobuster/feroxbuster dir brute
    enable_active_web: bool = True  # active web crawl (param-URL discovery)
    full_tcp: bool = True           # -p- vs --top-ports on gentle

    @classmethod
    def gentle(cls) -> "Profile":
        return cls(
            name="gentle (HTB / shared infra)",
            nmap_timing="-T2",
            nmap_args="-sV -sC --open",
            http_threads=10,
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
            http_threads=40,
            udp_scan=True,
            nse_vuln=True,
            parallelism=6,
            enable_nikto=True,
            enable_dirbust=True,
            enable_active_web=True,
            full_tcp=True,
        )

    @classmethod
    def stealth(cls) -> "Profile":
        """Low-and-slow, low-signature recon for AUTHORIZED testing of detection
        capabilities (does the SOC/IDS see it?). Drops the loud stuff: no -O / -sC
        (extra probes), no NSE vuln scripts, no nikto, no dir-brute, no active web —
        those flood IDS/WAF. Pairs with the stealth nmap flags in recon (slow timing,
        fragmentation, rate cap, source-port, optional decoys)."""
        return cls(
            name="stealth (low-and-slow, evasive)",
            nmap_timing="-T1",                          # 'sneaky' timing
            nmap_args="-sV --open --version-intensity 2",  # no -O / -sC (loud)
            http_threads=2,
            udp_scan=False,
            nse_vuln=False,                             # --script vuln is very noisy
            parallelism=1,                              # serialise to flatten the footprint
            enable_nikto=False,
            enable_dirbust=False,                       # dir-brute is an IDS-bait flood
            enable_active_web=False,
            full_tcp=False,                             # top-ports only -> far fewer packets
        )


@dataclass
class RunConfig:
    target: str
    profile: Profile
    aggressive: bool = False
    out_dir: str = "loot"
    wordlist_dirs: str = ""          # gobuster wordlist
    wordlist_users: str = ""
    wordlist_pass: str = ""
    discovered_tools: dict = field(default_factory=dict)
    hostname: str = ""               # resolved/added .htb name, if any
    resume: bool = False             # reuse cached phase state
    max_time: int = 0                # global wall-clock budget (s); 0 = unlimited (#17)
    connect_scan: bool = False       # force nmap -sT connect scan (skip SYN scan)
    no_udp: bool = False             # force-disable UDP even on lab
    # --- stealth / evasion (authorized detection testing) ---------------------
    stealth: bool = False            # low-and-slow, low-signature recon
    scan_delay: str = ""             # nmap --scan-delay (e.g. '500ms'); stealth default if ''
    max_rate: int = 0                # nmap --max-rate pps; stealth default if 0
    source_port: int = 0             # nmap --source-port (e.g. 53/80/443) to slip naive ACLs
    decoys: str = ""                 # nmap -D decoy list (e.g. 'RND:5' or ip1,ip2,ME)
    no_fragment: bool = False        # disable IP fragmentation (-f) in stealth mode
    no_nse_vuln: bool = False        # force-disable --script vuln
    default_creds: bool = True       # flag known default-cred pairs in the report (identify-only)
    # --- scope / authorization (issues #1, #2, #4) ----------------------------
    klass: str = "external"          # 'htb' | 'lab' | 'external' (set by cli)
    lab_nets: tuple = ()             # operator-declared lab CIDRs (--lab-net); beat built-in HTB
    allow_external: bool = False     # explicit opt-in to actively touch an external target
    scope_file: str = ""             # engagement allowlist; when set, target must match
    profile_is_auto: bool = True     # True if --profile auto (gate may prompt for external upgrade)
    events_path: str = ""            # NDJSON event log path (issue #25); "" = disabled
    seclists_dir: str = ""           # override SecLists root (else auto-detect / $CTFAUTO_SECLISTS)
    # --- cloud recon (unauthenticated public-misconfig discovery) -------------
    cloud: bool = False              # run the cloud recon phase
    allow_cloud: bool = False        # explicit authorization to enumerate cloud targets
    cloud_name: str = ""             # seed: a keyword (acme) or domain (acme.com)
    cloud_providers: tuple = ("aws",)  # which providers to probe: aws, azure
    cloud_extra_words: str = ""      # comma-separated extra permutation words
    cloud_candidate_cap: int = 200   # max candidate names to probe (politeness bound)


def load_scope(explicit: str = "") -> list:
    """Load an authorized-target scope list (engagement allowlist).

    Sources, in order: explicit path (--scope-file) → $CTFAUTO_SCOPE →
    ~/.config/ctfauto/scope.txt. One entry per line; '#' comments and blank lines
    ignored. Each entry is a CIDR, single IP, or a hostname (matched literally).
    Returns a list of (kind, value) where kind is 'net' (ip_network) or 'host'
    (lowercased string). An empty list means "no scope file configured" — callers
    treat that as 'scope not enforced', preserving the flag-only behaviour."""
    import os
    path = explicit or os.environ.get("CTFAUTO_SCOPE", "") or \
        os.path.expanduser("~/.config/ctfauto/scope.txt")
    if not path or not os.path.exists(path):
        return []
    entries: list = []
    try:
        with open(path) as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    entries.append(("net", ipaddress.ip_network(line, strict=False)))
                except ValueError:
                    entries.append(("host", line.lower()))
    except OSError:
        return []
    return entries


def target_in_scope(target: str, scope: list) -> bool:
    """True if `target` is covered by the scope list. An empty scope list means
    'not configured' → True (don't block when no scope file is in use)."""
    if not scope:
        return True
    tl = target.strip().lower()
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    for kind, value in scope:
        if kind == "host" and value == tl:
            return True
        if kind == "net" and ip is not None and ip in value:
            return True
    return False


def classify_target(target: str, extra_lab_nets: list | None = None) -> str:
    """Return 'htb', 'lab', or 'external' for a target IP/host.

    Precedence, most-specific operator intent first:
      1. Operator-declared LAB ranges — networks.json "lab" entries and any
         --lab-net values (extra_lab_nets). These WIN over the built-in HTB
         ranges, so you can tell ctfauto "10.10.10.0/24 is my own VM, not HTB"
         and it stops force-gentling your lab box (and honours --aggressive).
      2. HTB ranges (built-in + networks.json "htb") — shared infra; HTB rules
         prohibit aggressive scanning, so these force the gentle profile.
      3. Built-in RFC1918 LAB ranges.
    Anything else is 'external'. Note: HTB ranges are carved out of 10/8, so the
    built-in lab check stays LAST — only an explicit operator declaration (step 1)
    reclassifies an address that also falls inside an HTB range.
    """
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # A CIDR/range? classify by its network address (a sweep target).
        if "/" in target:
            try:
                ip = ipaddress.ip_network(target, strict=False).network_address
            except ValueError:
                return "external"
        else:
            # hostname — we can't safely classify by IP. Most cautious: external.
            # (cli resolves it and re-classifies on the resolved IP where possible.)
            return "external"
    extra = _load_user_networks()
    # 1. operator-declared lab ranges (CLI --lab-net + config) beat built-in HTB.
    cli_lab = []
    for cidr in (extra_lab_nets or []):
        try:
            cli_lab.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    for net in cli_lab + extra["lab"]:
        if ip in net:
            return "lab"
    # 2. HTB shared infra.
    for net in list(HTB_NETWORKS) + extra["htb"]:
        if ip in net:
            return "htb"
    # 3. built-in RFC1918 lab ranges.
    for net in LAB_NETWORKS:
        if ip in net:
            return "lab"
    return "external"


def detect_tools() -> dict:
    """Map of tool name -> path (or None if missing)."""
    tools = [
        "nmap", "gobuster", "nikto", "searchsploit",
        "enum4linux", "smbclient", "whatweb",
        "ffuf", "curl", "wget",
        # recon/enum tooling
        "onesixtyone", "snmpwalk", "snmp-check", "sslscan",
        "ldapsearch",
        "wpscan", "droopescan", "mount", "showmount",
        "feroxbuster", "arjun",
        # exploit-identification helpers (presence drives which leads we surface)
        "sqlmap", "git-dumper", "hydra", "mysql",
        # cloud recon (unauthenticated misconfig discovery)
        "aws", "s3scanner", "cloud_enum",
    ]
    return {t: shutil.which(t) for t in tools}
