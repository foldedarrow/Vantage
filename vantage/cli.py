"""vantage CLI orchestrator."""
from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys

from . import __version__
from .config import (
    Profile, RunConfig, classify_target, detect_tools, OWN_VPN_HINT_NETWORKS,
    load_scope, target_in_scope,
)
from .modules import recon, enumerate as enum_mod, exploit, report
from .util import (
    banner, good, info, warn, err, C, events_init, event,
    start_budget, budget_exceeded,
)


# Install hints for the `--check` doctor (apt package per tool where it differs).
_INSTALL_HINTS = {
    "nmap": "apt install nmap",
    "gobuster": "apt install gobuster",
    "feroxbuster": "apt install feroxbuster",
    "nikto": "apt install nikto",
    "searchsploit": "apt install exploitdb",
    "enum4linux": "apt install enum4linux",
    "smbclient": "apt install smbclient",
    "whatweb": "apt install whatweb",
    "ffuf": "apt install ffuf",
    "onesixtyone": "apt install onesixtyone",
    "snmpwalk": "apt install snmp",
    "snmp-check": "apt install snmp-check",
    "sslscan": "apt install sslscan",
    "ldapsearch": "apt install ldap-utils",
    "wpscan": "gem install wpscan   # or: apt install wpscan",
    "droopescan": "pipx install droopescan",
    "showmount": "apt install nfs-common",
    "arjun": "pipx install arjun",
    # Active Directory enumeration helpers
    "kerbrute": "go install github.com/ropnop/kerbrute@latest   # or grab a release binary",
    "nxc": "pipx install netexec   # provides both nxc and netexec",
    "netexec": "pipx install netexec",
    "enum4linux-ng": "pipx install enum4linux-ng   # or: apt install enum4linux-ng",
    "rpcclient": "apt install samba-common-bin",
    "impacket-GetNPUsers": "pipx install impacket   # AS-REP roasting",
    "impacket-GetUserSPNs": "pipx install impacket   # Kerberoasting (needs creds)",
    "impacket-lookupsid": "pipx install impacket   # RID/SID enumeration",
    "bloodhound-python": "pipx install bloodhound   # AD graph collector",
    "certipy": "pipx install certipy-ad   # AD CS (ESC1-ESC8) auditing",
    "ldapdomaindump": "pipx install ldapdomaindump",
    "sqlmap": "apt install sqlmap",
    "git-dumper": "pipx install git-dumper",
    "hydra": "apt install hydra",
    "mysql": "apt install default-mysql-client   # or: apt install mariadb-client",
    # cloud recon (all optional — module has a stdlib HTTP fallback)
    "aws": "apt install awscli   # or: pipx install awscli",
    "s3scanner": "pipx install s3scanner",
    # cloud_enum is NOT on PyPI — it's a GitHub project; install from the repo.
    "cloud_enum": "pipx install git+https://github.com/initstring/cloud_enum   # not on PyPI",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vantage",
        description="Automated recon & enumeration for owned & authorized targets "
                    "(HTB, Metasploitable, lab VMs). Produces a report — it never "
                    "exploits anything.",
        epilog="Only use against systems you own or are explicitly authorized to test.",
    )
    p.add_argument("target", nargs="?", help="Target IP or hostname")
    p.add_argument("-o", "--out-dir", default="loot", help="Output directory (default: loot/)")
    p.add_argument("--profile", choices=["auto", "lab", "gentle"], default="auto",
                   help="auto = pick based on target IP (HTB->gentle, RFC1918->lab)")
    p.add_argument("--aggressive", action="store_true",
                   help="Enable the loudest, most thorough enumeration (full TCP, "
                        "nikto, NSE vuln scripts, active web crawl). Noisy. Lab only.")
    p.add_argument("--allow-external", action="store_true",
                   help="Explicitly authorize ACTIVE recon of a target outside known "
                        "lab/HTB ranges (a public/unknown IP). Required before vantage "
                        "will scan such a target — you are asserting you have written "
                        "permission. On --profile auto you'll be prompted to choose the "
                        "gentle or full lab profile; pass --profile lab to opt into the "
                        "loud profile directly.")
    p.add_argument("--lab-net", action="append", default=[], metavar="CIDR",
                   help="Declare a CIDR as your OWN lab range (repeatable). Overrides "
                        "the built-in HTB classification for that range, so a box in "
                        "10.10.0.0/16 you actually own (e.g. a local Metasploitable at "
                        "10.10.10.104) is treated as 'lab' — full enumeration, "
                        "--aggressive honoured — instead of being force-gentled as HTB "
                        "shared infra. Persist it instead in ~/.config/vantage/"
                        "networks.json under the \"lab\" key.")
    p.add_argument("--scope-file", default="",
                   help="Path to an engagement scope allowlist (CIDRs/IPs/hostnames, "
                        "one per line, '#' comments). When set, vantage REFUSES any "
                        "target not covered by the list — regardless of other flags. "
                        "Also read from $VANTAGE_SCOPE or ~/.config/vantage/scope.txt.")
    p.add_argument("--check", "--doctor", dest="check", action="store_true",
                   help="Print the tool/dependency matrix and install hints, then exit")
    p.add_argument("--wordlist-dirs", default="", help="gobuster/feroxbuster wordlist path")
    p.add_argument("--wordlist-users", default="", help="hydra users wordlist")
    p.add_argument("--wordlist-pass", default="", help="hydra password wordlist")
    p.add_argument("--seclists-dir", default="",
                   help="SecLists root (else auto-detect common locations / "
                        "$VANTAGE_SECLISTS). e.g. /usr/share/seclists")
    p.add_argument("--no-default-creds", action="store_true",
                   help="Skip flagging known default-credential pairs in the report "
                        "(on by default; this only identifies them, never tries them)")
    p.add_argument("--connect", "-sT", dest="connect_scan", action="store_true",
                   help="Force an nmap TCP connect scan (-sT) instead of the default "
                        "SYN scan. Use this when a SYN scan returns everything as "
                        "'tcpwrapped' (common with some hypervisor NAT/virtual NICs). "
                        "vantage also auto-falls-back to -sT when it detects this.")
    p.add_argument("--no-udp", action="store_true", help="Disable UDP scan even on lab profile")
    p.add_argument("--no-nse-vuln", action="store_true", help="Disable nmap --script vuln")
    p.add_argument("--hostname", default="", help="Force a hostname (e.g. box.htb) for HTTP/vhost enum")
    p.add_argument("--add-hosts", action="store_true",
                   help="Auto-add detected .htb hostname to /etc/hosts (needs root)")
    p.add_argument("--resume", action="store_true", help="Reuse cached recon/enum state if present")
    p.add_argument("-j", "--parallelism", type=int, default=0,
                   help="Override concurrent enumeration workers")
    p.add_argument("--max-time", type=int, default=0,
                   help="Global wall-clock budget in SECONDS for the whole run. "
                        "0 = unlimited. When set, individual tool timeouts are "
                        "clamped to the remaining budget and phases stop early "
                        "once it's spent.")
    p.add_argument("--yes", action="store_true",
                   help="Skip the authorization prompt (lab/HTB only; external still "
                        "requires --allow-external)")
    # --- stealth / evasion (authorized testing of detection capability) -------
    stealth = p.add_argument_group(
        "stealth / evasion (for AUTHORIZED testing of your own detection — does the "
        "SOC/IDS see the scan?). Does NOT bypass the authorization gate.")
    stealth.add_argument("--stealth", action="store_true",
                         help="Low-and-slow, low-signature recon: -T1, fragmented "
                              "packets, rate-capped, and the loud tools (nikto, "
                              "dir-brute, NSE vuln, active web) disabled.")
    stealth.add_argument("--scan-delay", default="",
                         help="nmap --scan-delay between probes (e.g. 500ms, 1s). "
                              "Default 250ms in --stealth.")
    stealth.add_argument("--max-rate", type=int, default=0,
                         help="nmap --max-rate cap in packets/sec. Default 50 in --stealth.")
    stealth.add_argument("--source-port", type=int, default=0,
                         help="nmap --source-port (e.g. 53, 80, 443) to slip past ACLs "
                              "that trust those source ports.")
    stealth.add_argument("--decoys", default="",
                         help="nmap -D decoy list to obscure the real source — e.g. "
                              "'RND:5' (5 random) or 'ip1,ip2,ME'. Authorized testing only.")
    stealth.add_argument("--no-fragment", action="store_true",
                         help="Disable IP fragmentation (-f) in --stealth (some NICs/"
                              "hypervisors mangle fragments).")
    # --- web intel + local-AI advisory (optional report enrichment) -----------
    intel = p.add_argument_group(
        "web intel + AI advisory (optional, opt-in report enrichment). --search is "
        "the ONLY part of vantage that contacts anything other than the target.")
    intel.add_argument("--search", action="store_true",
                       help="Enrich the report with PUBLIC web/CVE context for the "
                            "CVEs and software versions found (keyless DuckDuckGo + "
                            "CIRCL CVE API, stdlib-only). Searches generic identifiers "
                            "only — never the target's IP/hostname. Makes outbound "
                            "requests; off by default.")
    intel.add_argument("--search-cap", type=int, default=12,
                       help="Max outbound search queries per run (default 12).")
    intel.add_argument("--ai", action="store_true",
                       help="Add a read-only AI advisory section: a LOCAL Ollama model "
                            "triages the findings into prioritized risks + remediation. "
                            "Advisory only — the model cannot run any tool (vantage "
                            "still fires nothing). Needs Ollama running locally.")
    intel.add_argument("--ai-model", default="",
                       help="Ollama model for --ai (else $VANTAGE_AI_MODEL, default "
                            "'llama3.1'). Endpoint via $VANTAGE_OLLAMA_URL.")
    # --- cloud recon (unauthenticated public-misconfiguration discovery) ------
    cloud = p.add_argument_group("cloud recon (unauthenticated misconfig discovery)")
    cloud.add_argument("--cloud", action="store_true",
                       help="Run cloud recon: enumerate PUBLIC/exposed S3 buckets & Azure "
                            "blob containers for a target (read-only by default)")
    cloud.add_argument("--allow-cloud", action="store_true",
                       help="Authorize cloud enumeration — you assert you have permission "
                            "to test the named target. Required for --cloud.")
    cloud.add_argument("--cloud-name", default="",
                       help="Seed for name generation: a keyword (acme) or a domain "
                            "(acme.com). Defaults to the positional target.")
    cloud.add_argument("--cloud-providers", default="aws",
                       help="Comma-separated providers to probe: aws,azure (default: aws)")
    cloud.add_argument("--cloud-extra-words", default="",
                       help="Comma-separated extra permutation words (e.g. teamname,project)")
    cloud.add_argument("--cloud-cap", type=int, default=200,
                       help="Max candidate names to probe per provider (default 200)")
    p.add_argument("--version", action="version", version=f"vantage {__version__}")
    return p


# --- doctor / dependency check ----------------------------------------------
def run_doctor(args=None) -> int:
    banner(f"Vantage {__version__} — dependency check")
    tools = detect_tools()
    width = max(len(t) for t in tools)
    missing = []
    for t in sorted(tools):
        path = tools[t]
        if path:
            print(f"  {C.GREEN}✓{C.RESET} {t:<{width}}  {C.GREY}{path}{C.RESET}")
        else:
            missing.append(t)
            hint = _INSTALL_HINTS.get(t, f"install {t}")
            print(f"  {C.RED}✗{C.RESET} {t:<{width}}  {C.YELLOW}{hint}{C.RESET}")
    print()
    if "nmap" not in [t for t, p in tools.items() if p]:
        err("nmap is the one hard requirement and is missing — recon won't run.")
    if missing:
        warn(f"{len(missing)} tool(s) missing; their steps will be skipped.")
    else:
        good("all known tools present.")

    # --- cloud recon tooling (all optional; stdlib HTTP fallback exists) ---
    cloud_tools = ("aws", "s3scanner", "cloud_enum")
    have_cloud = [t for t in cloud_tools if tools.get(t)]
    if have_cloud:
        good(f"cloud recon helpers present: {', '.join(have_cloud)}")
    else:
        info("cloud recon: no helper tools (aws/s3scanner/cloud_enum) — the built-in "
             "anonymous HTTP probing still works. `apt install awscli` improves S3 results.")

    # --- optional enrichment (web intel + local AI advisory) ---
    info("web intel (--search): stdlib-only; needs outbound internet. No tool to "
         "install. Searches generic identifiers only — never the target's address.")
    info("AI advisory (--ai): needs a local Ollama (`ollama serve` + `ollama pull "
         "llama3.1`). Read-only/advisory — the model cannot run any tool.")

    # --- SecLists / wordlist resolution ---
    from . import wordlists
    from .config import RunConfig, Profile
    shim = RunConfig(target="", profile=Profile.gentle(),
                     seclists_dir=(getattr(args, "seclists_dir", "") or ""))
    print()
    banner("Wordlists")
    wl = wordlists.summary(shim)
    root = wl.pop("seclists_root")
    if root == "(not found)":
        warn(f"SecLists not found. Install it (apt install seclists) or point "
             f"--seclists-dir / $VANTAGE_SECLISTS at it. Looked in: "
             f"/usr/share/seclists, /usr/share/SecLists, /opt, ~/.")
    else:
        good(f"SecLists root: {root}")
    wlwidth = max(len(k) for k in wl)
    for name, path in wl.items():
        ok = path != "(none)"
        mark = f"{C.GREEN}✓{C.RESET}" if ok else f"{C.YELLOW}–{C.RESET}"
        colour = C.GREY if ok else C.YELLOW
        print(f"  {mark} {name:<{wlwidth}}  {colour}{path}{C.RESET}")
    return 0


# --- scope / authorization ---------------------------------------------------
def _resolve_and_classify(target: str, lab_nets: list | None = None) -> tuple[str, str]:
    """Return (klass, resolved_ip_or_target). If target is a hostname, try to
    resolve it so we classify on the real IP rather than defaulting to external.
    `lab_nets` are operator-declared --lab-net ranges that override built-in HTB."""
    klass = classify_target(target, lab_nets)
    if klass != "external":
        return klass, target
    # target may be a hostname — try to resolve and re-classify on the IP.
    try:
        ipaddress.ip_address(target)
        return klass, target  # it was already an IP, genuinely external
    except ValueError:
        pass
    try:
        resolved = socket.gethostbyname(target)
        rklass = classify_target(resolved, lab_nets)
        if rklass != "external":
            info(f"{target} resolves to {resolved} ({rklass})")
        return rklass, target  # keep hostname as the target label; klass from IP
    except (OSError, UnicodeError):
        return klass, target


def _is_own_vpn_ip(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    return any(ip in net for net in OWN_VPN_HINT_NETWORKS)


def _prompt_external_profile(cfg: RunConfig) -> None:
    """Ask the operator whether an authorized external target should use the loud
    'lab' profile (full aggressive automation) or stay on 'gentle'. Mutates
    cfg.profile in place. Defaults to gentle on empty/EOF (the safe choice)."""
    print(f"\n{C.YELLOW}This external target is on the GENTLE profile by default "
          f"(quieter recon-led pass).{C.RESET}")
    print("The LAB profile is full-intensity enumeration: -p- -T4, nikto, "
          "dir-busting, NSE vuln scripts, and an active web crawl. It is LOUD and "
          "can crash fragile services — only choose it if your written "
          "authorization covers that level of intrusiveness. (vantage never "
          "exploits anything on either profile.)")
    try:
        ans = input(f"{C.YELLOW}Use the full LAB (loud enumeration) profile for "
                    f"{cfg.target}? [y/N]: {C.RESET}")
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans.strip().lower() in ("y", "yes"):
        cfg.profile = Profile.lab()
        good(f"external target upgraded to LAB profile: {cfg.profile.name}")
    else:
        info(f"keeping GENTLE profile: {cfg.profile.name}")


def authorization_gate(cfg: RunConfig, assume_yes: bool, allow_external: bool) -> bool:
    """Returns True if the run is authorized to proceed to ACTIVE phases.

    Policy:
      - htb / lab: prompt (or --yes) confirms authorization.
      - external : refuse unless --allow-external is explicitly passed; even then,
                   require interactive confirmation OR --yes alongside it.
    """
    klass = cfg.klass
    banner("AUTHORIZATION CHECK")
    print(f"Target:       {C.BOLD}{cfg.target}{C.RESET}  (classified: {klass})")
    print(f"Profile:      {cfg.profile.name}")
    print(f"Mode:         recon + enumeration + report (no exploitation)   "
          f"Aggressive: {cfg.aggressive}")

    if _is_own_vpn_ip(cfg.target):
        err("That looks like YOUR OWN VPN client IP (tun0 handout range), not a target. "
            "Refusing to scan yourself.")
        return False

    # Engagement scope allowlist (if configured) is authoritative: a target not in
    # the list is refused regardless of class or --allow-external. This binds a run
    # to a written scope so a typo'd/out-of-scope target can't be scanned.
    scope = load_scope(cfg.scope_file)
    if scope and not target_in_scope(cfg.target, scope):
        err(f"{cfg.target} is NOT in the configured scope allowlist — refusing. "
            "Add it to the scope file only if it's within your authorized engagement.")
        return False
    if scope:
        good(f"{cfg.target} is within the configured engagement scope.")

    if klass == "htb":
        warn("HackTheBox shared-infra range. HTB rules prohibit aggressive/automated "
             "mass scanning; forcing the gentle profile and ignoring --aggressive.")
    if klass == "external":
        warn("Target is OUTSIDE known lab/HTB ranges (a public or unknown IP).")
        # NOTE: recon + enumeration (nmap, dir brute, whatweb, NSE) sends real,
        # active scan traffic at the target. So any run against an external target
        # requires explicit authorization, even though we never exploit anything.
        if not allow_external:
            err("Refusing to scan an external target without --allow-external. "
                "Recon/enum sends real scan traffic. Re-run with --allow-external "
                "ONLY if you have explicit written authorization.")
            return False
        warn("--allow-external supplied: you are asserting written authorization for "
             "this external target.")

    if assume_yes:
        if klass == "external" and not allow_external:
            return False  # belt-and-suspenders; already handled above
        # With --yes we don't prompt; external stays on whatever profile was set
        # (gentle by default, or lab if the operator passed --profile lab).
        info("--yes supplied; proceeding.")
        return True

    # Authorized external target on --profile auto: let the operator choose the
    # profile instead of silently forcing gentle. Lab = full aggressive automation
    # (loud, can lock accounts / crash services); gentle = quieter recon-led pass.
    if klass == "external" and allow_external and getattr(cfg, "profile_is_auto", True):
        _prompt_external_profile(cfg)

    try:
        prompt = (f"\n{C.YELLOW}Confirm you own or are explicitly authorized to test "
                  f"{cfg.target} [y/N]: {C.RESET}")
        ans = input(prompt)
    except (EOFError, KeyboardInterrupt):
        return False
    return ans.strip().lower() in ("y", "yes")


def _looks_scannable(target: str, cloud_name: str) -> bool:
    """Heuristic: is `target` something we should run the host pipeline against?
    A real IP or a dotted hostname is scannable. A bare keyword (e.g. 'acme'),
    used purely as a cloud seed, is not — that's cloud-only mode."""
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    # dotted name with a TLD-ish tail -> treat as a host worth scanning
    return "." in target


def cloud_authorization_gate(cfg: RunConfig, assume_yes: bool) -> bool:
    """Separate gate for cloud recon. Cloud targets are public provider infra, so
    enumeration requires an explicit --allow-cloud assertion of authorization."""
    banner("CLOUD AUTHORIZATION CHECK")
    seed = cfg.cloud_name or cfg.target
    print(f"Cloud seed:   {C.BOLD}{seed}{C.RESET}")
    print(f"Providers:    {', '.join(cfg.cloud_providers)}")
    print(f"Write-test:   {'ENABLED (--aggressive)' if cfg.aggressive else 'disabled (read-only)'}")
    warn("Cloud recon enumerates PUBLIC cloud resources (S3/Azure) associated with "
         "the seed. Only do this against assets you own or are authorized to test.")
    if not cfg.allow_cloud:
        err("Refusing to run cloud recon without --allow-cloud. Re-run with "
            "--allow-cloud ONLY if you have explicit authorization to enumerate "
            "the named target's cloud assets.")
        return False
    if cfg.aggressive:
        warn("--aggressive: the WRITE test is enabled. It writes ONE marker object "
             "to any world-writable bucket found and tells you to delete it.")
    if assume_yes:
        info("--yes supplied; proceeding with cloud recon.")
        return True
    try:
        ans = input(f"\n{C.YELLOW}Confirm you are authorized to enumerate cloud assets "
                    f"for '{seed}' [y/N]: {C.RESET}")
    except (EOFError, KeyboardInterrupt):
        return False
    return ans.strip().lower() in ("y", "yes")


# --- phase orchestration -----------------------------------------------------
def build_config(args) -> RunConfig:
    lab_nets = tuple(getattr(args, "lab_net", []) or [])
    klass, target = _resolve_and_classify(args.target, list(lab_nets))

    # Profile selection.
    #   --profile gentle/lab : explicit, always honoured (even for external).
    #   --profile auto       : lab->lab, htb->gentle. For external we DEFER the
    #                          choice to the authorization gate, which prompts the
    #                          operator to pick lab vs gentle (was force-gentle).
    if args.stealth:
        # Stealth takes precedence over any profile choice: it's a different goal
        # (minimise signature) and must not be silently widened by --profile lab.
        profile = Profile.stealth()
    elif args.profile == "gentle":
        profile = Profile.gentle()
    elif args.profile == "lab":
        profile = Profile.lab()
    else:  # auto
        if klass == "lab":
            profile = Profile.lab()
        elif klass == "external":
            # placeholder; the gate will upgrade to lab if the operator confirms.
            profile = Profile.gentle()
        else:  # htb
            profile = Profile.gentle()

    if args.parallelism > 0:
        profile.parallelism = args.parallelism

    # --aggressive is lab-only by default, but an explicitly-authorized external
    # target may opt into it (the operator asserts scope via --allow-external).
    aggressive = args.aggressive and not args.stealth and (
        klass == "lab" or (klass == "external" and args.allow_external))

    cfg = RunConfig(
        target=target,
        profile=profile,
        aggressive=aggressive,
        out_dir=args.out_dir,
        wordlist_dirs=args.wordlist_dirs,
        wordlist_users=args.wordlist_users,
        wordlist_pass=args.wordlist_pass,
        discovered_tools=detect_tools(),
        hostname=args.hostname,
        resume=args.resume,
        max_time=args.max_time,
        connect_scan=args.connect_scan,
        no_udp=args.no_udp,
        no_nse_vuln=args.no_nse_vuln,
        stealth=args.stealth,
        scan_delay=args.scan_delay,
        max_rate=args.max_rate,
        source_port=args.source_port,
        decoys=args.decoys,
        no_fragment=args.no_fragment,
        default_creds=not args.no_default_creds,
        search=args.search,
        search_cap=args.search_cap,
        ai=args.ai,
        ai_model=args.ai_model,
        seclists_dir=args.seclists_dir,
        klass=klass,
        lab_nets=lab_nets,
        allow_external=args.allow_external,
        scope_file=args.scope_file,
        cloud=args.cloud,
        allow_cloud=args.allow_cloud,
        cloud_name=args.cloud_name,
        cloud_providers=tuple(p.strip().lower() for p in args.cloud_providers.split(",") if p.strip()),
        cloud_extra_words=args.cloud_extra_words,
        cloud_candidate_cap=args.cloud_cap,
    )

    if lab_nets and klass == "lab":
        info(f"--lab-net: {target} is in an operator-declared lab range — "
             "classified 'lab' (overrides built-in HTB), full enumeration enabled.")
    if args.aggressive and klass == "htb":
        warn("--aggressive ignored: target is HTB shared infra.")
    if args.aggressive and klass == "external" and not args.allow_external:
        warn("--aggressive ignored: external target needs --allow-external too.")
    # remember whether the operator left profile selection on 'auto' so the gate
    # knows it's allowed to prompt for an external profile upgrade. Stealth pins the
    # profile deliberately, so never prompt to widen it to the loud lab profile.
    cfg.profile_is_auto = (args.profile == "auto") and not args.stealth
    return cfg


def run_host_sweep(cfg: RunConfig, args) -> int:
    """CIDR/range sweep: discover live hosts, then run the full per-host pipeline
    for each and write an index linking the per-host reports (#22). The range was
    already authorized once at the gate before we got here."""
    import dataclasses

    banner("HOST DISCOVERY (CIDR sweep)")
    live = recon.discover_hosts(cfg)
    if not live:
        warn("No live hosts found in range; nothing to do.")
        event(cfg, "sweep_done", live=0)
        return 0
    good(f"{len(live)} live host(s): {', '.join(live)}")
    event(cfg, "sweep_hosts", count=len(live), hosts=live)

    rows: list[dict] = []
    for ip in live:
        if budget_exceeded():
            warn("global time budget exhausted — stopping sweep early.")
            break
        banner(f"HOST {ip}")
        hcfg = dataclasses.replace(
            cfg, target=ip, hostname="", klass=classify_target(ip, list(cfg.lab_nets)),
            events_path=os.path.join(cfg.out_dir, f"events_{ip}.ndjson"),
        )
        events_init(hcfg.events_path)
        host = recon.scan(hcfg)
        if not host.all_services:
            info(f"{ip}: no open services")
            rows.append({"ip": ip, "services": 0, "candidates": 0, "report": ""})
            continue
        enum_res = enum_mod.enumerate_host(hcfg, host)
        exp = exploit.identify(hcfg, host, enum_res)
        exp.candidates = exploit.dedupe(exp.candidates)
        md, _ = report.write_reports(hcfg, host, enum_res, exp)
        rows.append({"ip": ip, "services": len(host.all_services),
                     "candidates": len(exp.candidates), "report": md})

    idx = report.write_sweep_index(cfg.out_dir, cfg.target, rows)
    event(cfg, "sweep_done", live=len(live),
          reports=len([r for r in rows if r["report"]]))
    good(f"Sweep complete. Open {idx} for the index.")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.check:
        return run_doctor(args)
    if not args.target:
        err("a target is required (or use --check). See --help.")
        return 2

    cfg = build_config(args)

    # Start the global wall-clock budget (#17). 0 = unlimited.
    start_budget(cfg.max_time)
    if cfg.max_time:
        info(f"global time budget: {cfg.max_time}s for the whole run")

    banner(f"Vantage {__version__}")
    missing = [t for t, path in cfg.discovered_tools.items() if not path]
    if missing:
        warn("Missing tools (steps using them will be skipped): " + ", ".join(missing)
             + f"  — run `vantage --check` for install hints.")
    os.makedirs(cfg.out_dir, exist_ok=True)

    # Initialise the NDJSON event log (issue #25) for this run.
    cfg.events_path = os.path.join(cfg.out_dir,
                                   f"events_{cfg.target.replace('/', '_')}.ndjson")
    events_init(cfg.events_path)
    event(cfg, "run_start", target=cfg.target, klass=cfg.klass,
          profile=cfg.profile.name, mode="recon+enum+report",
          aggressive=cfg.aggressive)

    # Cloud-only mode: --cloud without a need to host-scan. If the seed is a bare
    # keyword (not a scannable host), we skip the host pipeline entirely and just
    # run cloud recon behind its own authorization gate.
    cloud_only = cfg.cloud and not _looks_scannable(cfg.target, cfg.cloud_name)
    if cloud_only:
        if not cloud_authorization_gate(cfg, args.yes):
            err("Cloud authorization not confirmed. Aborting.")
            event(cfg, "run_abort", reason="cloud_authorization_not_confirmed")
            return 1
        from .modules import cloud as cloud_mod
        banner("CLOUD RECON")
        cloud_res = cloud_mod.run_cloud_recon(cfg, enum=None)
        host = recon.HostResult(ip=cfg.target)
        enum_res = enum_mod.EnumResult()
        enum_res.findings.extend(cloud_res.as_enum_findings())
        banner("REPORT")
        md, js = report.write_reports(cfg, host, enum_res, exploit.ExploitResult())
        event(cfg, "run_done", report=md, cloud_findings=len(cloud_res.findings))
        good(f"Done. Open {md} for the readable report.")
        return 0

    if not authorization_gate(cfg, args.yes, args.allow_external):
        err("Authorization not confirmed. Aborting.")
        event(cfg, "run_abort", reason="authorization_not_confirmed")
        return 1

    # CIDR/range target → multi-host sweep instead of the single-host pipeline (#22).
    if recon.is_cidr(cfg.target):
        return run_host_sweep(cfg, args)

    # HTB ergonomics: detect a .htb hostname and optionally add to /etc/hosts.
    if not cfg.hostname and cfg.klass == "htb":
        detected = recon.detect_htb_hostname(cfg)
        if detected:
            cfg.hostname = detected
            good(f"detected hostname: {detected}")
            if args.add_hosts:
                recon.add_to_hosts(cfg.target, detected)

    banner("PHASE 1 — RECON")
    host = recon.scan(cfg)
    event(cfg, "recon_done", services=len(host.all_services),
          os_guess=host.os_guess)
    if not host.all_services:
        warn("No open services; nothing further to do.")
        report.write_reports(cfg, host, enum_mod.EnumResult(), exploit.ExploitResult())
        return 0

    banner("PHASE 2 — ENUMERATION")
    enum_res = enum_mod.enumerate_host(cfg, host)
    event(cfg, "enum_done", findings=len(enum_res.findings))

    banner("PHASE 3 — EXPLOIT IDENTIFICATION (report-only)")
    # vantage is a recon/enumeration tool: it IDENTIFIES candidate exploits and
    # known CVEs for the report, but never fires anything. The candidate list is
    # informational — use it as a starting point for manual, authorized testing.
    exp_res = exploit.identify(cfg, host, enum_res)
    exp_res.candidates = exploit.dedupe(exp_res.candidates)
    event(cfg, "identify_done", candidates=len(exp_res.candidates))

    # Optional cloud recon alongside the host run. Harvests bucket names from the
    # web-enum crawl, then probes them (+ seed permutations) behind its own gate.
    if cfg.cloud:
        from .modules import cloud as cloud_mod
        if cloud_authorization_gate(cfg, args.yes):
            banner("CLOUD RECON")
            cloud_res = cloud_mod.run_cloud_recon(cfg, enum=enum_res)
            enum_res.findings.extend(cloud_res.as_enum_findings())
        else:
            warn("cloud recon skipped: authorization not confirmed.")

    # Optional report enrichment (both opt-in, both degrade to "" on any failure).
    web_intel = ""
    if cfg.search:
        from .modules import search as search_mod
        banner("WEB INTEL (public sources)")
        web_intel = search_mod.enrich_report(cfg, host, exp_res, enum=enum_res)
        event(cfg, "search_done", chars=len(web_intel))

    analysis = ""
    if cfg.ai:
        from .modules import advise as advise_mod
        banner("AI ANALYSIS (advisory — local model)")
        analysis = advise_mod.advise(cfg, host, enum_res, exp_res)
        event(cfg, "ai_done", chars=len(analysis))

    banner("PHASE 4 — REPORT")
    md, js = report.write_reports(cfg, host, enum_res, exp_res,
                                  web_intel=web_intel, analysis=analysis)
    event(cfg, "run_done", report=md)
    good(f"Done. Open {md} for the readable report.")
    if exp_res.candidates:
        good(f"{len(exp_res.candidates)} candidate exploit(s) listed in the report "
             "for manual, authorized follow-up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
