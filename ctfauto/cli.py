"""ctfauto CLI orchestrator."""
from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys

from . import __version__
from .config import (
    Profile, RunConfig, classify_target, detect_tools, OWN_VPN_HINT_NETWORKS,
)
from .modules import recon, enumerate as enum_mod, exploit, report, postexploit
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
    "hydra": "apt install hydra",
    "searchsploit": "apt install exploitdb",
    "msfconsole": "apt install metasploit-framework",
    "msfrpcd": "apt install metasploit-framework",
    "enum4linux": "apt install enum4linux",
    "smbclient": "apt install smbclient",
    "whatweb": "apt install whatweb",
    "ffuf": "apt install ffuf",
    "onesixtyone": "apt install onesixtyone",
    "snmpwalk": "apt install snmp",
    "snmp-check": "apt install snmp-check",
    "sslscan": "apt install sslscan",
    "wpscan": "gem install wpscan   # or: apt install wpscan",
    "droopescan": "pipx install droopescan",
    "sqlmap": "apt install sqlmap",
    "git-dumper": "pipx install git-dumper",
    "mysql": "apt install default-mysql-client",
    "showmount": "apt install nfs-common",
    "arjun": "pipx install arjun",
    # cloud recon (all optional — module has a stdlib HTTP fallback)
    "aws": "apt install awscli   # or: pipx install awscli",
    "s3scanner": "pipx install s3scanner",
    "cloud_enum": "pipx install cloud_enum",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctfauto",
        description="Automated recon/enum/exploit-ID for owned & authorized targets "
                    "(HTB, Metasploitable, lab VMs).",
        epilog="Only use against systems you own or are explicitly authorized to test.",
    )
    p.add_argument("target", nargs="?", help="Target IP or hostname")
    p.add_argument("-o", "--out-dir", default="loot", help="Output directory (default: loot/)")
    p.add_argument("--profile", choices=["auto", "lab", "gentle"], default="auto",
                   help="auto = pick based on target IP (HTB->gentle, RFC1918->lab)")
    p.add_argument("--auto-exploit", action="store_true",
                   help="Fire SAFE (non-destructive) exploit modules automatically")
    p.add_argument("--aggressive", action="store_true",
                   help="Enable brute-force + all matched modules. Noisy. Lab only.")
    p.add_argument("--allow-external", action="store_true",
                   help="Explicitly authorize ACTIVE testing of a target outside known "
                        "lab/HTB ranges (a public/unknown IP). Required before ctfauto "
                        "will scan or exploit such a target — you are asserting you have "
                        "written permission.")
    p.add_argument("--identify-only", action="store_true",
                   help="Recon + enum + list exploits, but never fire anything")
    p.add_argument("--check", "--doctor", dest="check", action="store_true",
                   help="Print the tool/dependency matrix and install hints, then exit")
    p.add_argument("--wordlist-dirs", default="", help="gobuster/feroxbuster wordlist path")
    p.add_argument("--wordlist-users", default="", help="hydra users wordlist")
    p.add_argument("--wordlist-pass", default="", help="hydra password wordlist")
    p.add_argument("--seclists-dir", default="",
                   help="SecLists root (else auto-detect common locations / "
                        "$CTFAUTO_SECLISTS). e.g. /usr/share/seclists")
    p.add_argument("--post-exploit", action="store_true",
                   help="Stage privesc enumeration (linpeas/winPEAS) over opened sessions")
    p.add_argument("--peas-dir", default="", help="Dir holding linpeas.sh / winPEAS (default /usr/share/peass)")
    p.add_argument("--no-default-creds", action="store_true",
                   help="Skip default-credential checks (on by default)")
    p.add_argument("--connect", "-sT", dest="connect_scan", action="store_true",
                   help="Force an nmap TCP connect scan (-sT) instead of the default "
                        "SYN scan. Use this when a SYN scan returns everything as "
                        "'tcpwrapped' (common with some hypervisor NAT/virtual NICs). "
                        "ctfauto also auto-falls-back to -sT when it detects this.")
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
    p.add_argument("--version", action="version", version=f"ctfauto {__version__}")
    return p


# --- doctor / dependency check ----------------------------------------------
def run_doctor(args=None) -> int:
    banner(f"ctfauto {__version__} — dependency check")
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
    try:
        import pymetasploit3  # noqa: F401
        good("pymetasploit3 present (msfrpc post-exploit available)")
    except ImportError:
        warn("pymetasploit3 missing — `pip install pymetasploit3` for msfrpc post-exploit")
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
             f"--seclists-dir / $CTFAUTO_SECLISTS at it. Looked in: "
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
def _resolve_and_classify(target: str) -> tuple[str, str]:
    """Return (klass, resolved_ip_or_target). If target is a hostname, try to
    resolve it so we classify on the real IP rather than defaulting to external."""
    klass = classify_target(target)
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
        rklass = classify_target(resolved)
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
    print(f"Auto-exploit: {cfg.auto_exploit}   Aggressive: {cfg.aggressive}   "
          f"Identify-only: {cfg.identify_only}")

    if _is_own_vpn_ip(cfg.target):
        err("That looks like YOUR OWN VPN client IP (tun0 handout range), not a target. "
            "Refusing to scan yourself.")
        return False

    if klass == "htb":
        warn("HackTheBox shared-infra range. HTB rules prohibit aggressive/automated "
             "mass scanning; forcing the gentle profile and ignoring --aggressive.")
    if klass == "external":
        warn("Target is OUTSIDE known lab/HTB ranges (a public or unknown IP).")
        # NOTE: even --identify-only runs active recon+enum (nmap, dir brute,
        # whatweb) against the target — it only suppresses *exploitation*. So any
        # run against an external target requires explicit authorization.
        if not allow_external:
            err("Refusing to scan an external target without --allow-external. Even "
                "--identify-only sends real scan traffic. Re-run with --allow-external "
                "ONLY if you have explicit written authorization.")
            return False
        warn("--allow-external supplied: you are asserting written authorization for "
             "this external target.")

    if assume_yes:
        if klass == "external" and not allow_external:
            return False  # belt-and-suspenders; already handled above
        info("--yes supplied; proceeding.")
        return True
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
    klass, target = _resolve_and_classify(args.target)

    # Profile selection. External is forced to gentle and cannot auto-exploit
    # unless the user *also* opted into --allow-external (handled at the gate);
    # we still never give external the loud lab profile automatically.
    if args.profile == "gentle":
        profile = Profile.gentle()
    elif args.profile == "lab":
        profile = Profile.lab()
    else:  # auto
        profile = Profile.lab() if klass == "lab" else Profile.gentle()

    if args.parallelism > 0:
        profile.parallelism = args.parallelism

    # --aggressive is lab-only. Never on htb (shared infra) or external.
    aggressive = args.aggressive and klass == "lab"

    cfg = RunConfig(
        target=target,
        profile=profile,
        aggressive=aggressive,
        auto_exploit=args.auto_exploit,
        identify_only=args.identify_only,
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
        default_creds=not args.no_default_creds,
        post_exploit=args.post_exploit,
        peas_dir=args.peas_dir,
        seclists_dir=args.seclists_dir,
        klass=klass,
        allow_external=args.allow_external,
        cloud=args.cloud,
        allow_cloud=args.allow_cloud,
        cloud_name=args.cloud_name,
        cloud_providers=tuple(p.strip().lower() for p in args.cloud_providers.split(",") if p.strip()),
        cloud_extra_words=args.cloud_extra_words,
        cloud_candidate_cap=args.cloud_cap,
    )

    if args.aggressive and klass == "htb":
        warn("--aggressive ignored: target is HTB shared infra.")
    if args.aggressive and klass == "external":
        warn("--aggressive ignored: external targets never get aggressive automation.")
    return cfg


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

    banner(f"ctfauto {__version__}")
    missing = [t for t, path in cfg.discovered_tools.items() if not path]
    if missing:
        warn("Missing tools (steps using them will be skipped): " + ", ".join(missing)
             + f"  — run `ctfauto --check` for install hints.")
    os.makedirs(cfg.out_dir, exist_ok=True)

    # Initialise the NDJSON event log (issue #25) for this run.
    cfg.events_path = os.path.join(cfg.out_dir,
                                   f"events_{cfg.target.replace('/', '_')}.ndjson")
    events_init(cfg.events_path)
    event(cfg, "run_start", target=cfg.target, klass=cfg.klass,
          profile=cfg.profile.name, auto_exploit=cfg.auto_exploit,
          aggressive=cfg.aggressive, identify_only=cfg.identify_only)

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

    banner("PHASE 3 — EXPLOIT IDENTIFICATION")
    exp_res = exploit.identify(cfg, host, enum_res)
    event(cfg, "identify_done", candidates=len(exp_res.candidates))

    banner("PHASE 4 — EXPLOITATION")
    if budget_exceeded():
        warn("time budget exhausted before exploitation — skipping active phases. "
             "Candidate commands are in the report.")
        event(cfg, "budget_exhausted", phase="exploit")
        cfg.identify_only = True  # downgrade to identify-only for the rest
    exploit.auto_exploit(cfg, host, exp_res)
    wins = [c for c in exp_res.candidates if c.session_opened]
    event(cfg, "exploit_done", confirmed=len(wins),
          titles=[c.title for c in wins])

    banner("PHASE 5 — POST-EXPLOITATION")
    postex_res = postexploit.run_postexploit(cfg, host, exp_res)

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

    banner("PHASE 6 — REPORT")
    md, js = report.write_reports(cfg, host, enum_res, exp_res, postex_res)
    event(cfg, "run_done", report=md)
    good(f"Done. Open {md} for the readable report.")
    if wins:
        good(f"{len(wins)} confirmed win(s): " + ", ".join(c.title for c in wins))
    return 0


if __name__ == "__main__":
    sys.exit(main())
