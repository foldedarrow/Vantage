"""ctfauto CLI orchestrator."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import Profile, RunConfig, classify_target, detect_tools
from .modules import recon, enumerate as enum_mod, exploit, report, postexploit
from .util import banner, good, info, warn, err, C


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctfauto",
        description="Automated recon/enum/exploit-ID for owned & authorized targets "
                    "(HTB, Metasploitable, lab VMs).",
        epilog="Only use against systems you own or are explicitly authorized to test.",
    )
    p.add_argument("target", help="Target IP or hostname")
    p.add_argument("-o", "--out-dir", default="loot", help="Output directory (default: loot/)")
    p.add_argument("--profile", choices=["auto", "lab", "gentle"], default="auto",
                   help="auto = pick based on target IP (HTB->gentle, RFC1918->lab)")
    p.add_argument("--auto-exploit", action="store_true",
                   help="Fire SAFE (non-destructive) exploit modules automatically")
    p.add_argument("--aggressive", action="store_true",
                   help="Enable brute-force + all matched modules. Noisy. Lab only.")
    p.add_argument("--identify-only", action="store_true",
                   help="Recon + enum + list exploits, but never fire anything")
    p.add_argument("--wordlist-dirs", default="", help="gobuster wordlist path")
    p.add_argument("--wordlist-users", default="", help="hydra users wordlist")
    p.add_argument("--wordlist-pass", default="", help="hydra password wordlist")
    p.add_argument("--post-exploit", action="store_true",
                   help="Stage privesc enumeration (linpeas/winPEAS) over opened sessions")
    p.add_argument("--peas-dir", default="", help="Dir holding linpeas.sh / winPEAS (default /usr/share/peass)")
    p.add_argument("--no-default-creds", action="store_true",
                   help="Skip default-credential checks (on by default)")
    p.add_argument("--no-udp", action="store_true", help="Disable UDP scan even on lab profile")
    p.add_argument("--no-nse-vuln", action="store_true", help="Disable nmap --script vuln")
    p.add_argument("--hostname", default="", help="Force a hostname (e.g. box.htb) for HTTP/vhost enum")
    p.add_argument("--add-hosts", action="store_true",
                   help="Auto-add detected .htb hostname to /etc/hosts (needs root)")
    p.add_argument("--resume", action="store_true", help="Reuse cached recon/enum state if present")
    p.add_argument("-j", "--parallelism", type=int, default=0,
                   help="Override concurrent enumeration workers")
    p.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    p.add_argument("--version", action="version", version=f"ctfauto {__version__}")
    return p


def authorization_gate(cfg: RunConfig, klass: str, assume_yes: bool) -> bool:
    banner("AUTHORIZATION CHECK")
    print(f"Target:      {C.BOLD}{cfg.target}{C.RESET}  (classified: {klass})")
    print(f"Profile:     {cfg.profile.name}")
    print(f"Auto-exploit:{cfg.auto_exploit}   Aggressive: {cfg.aggressive}   "
          f"Identify-only: {cfg.identify_only}")
    if klass == "htb":
        warn("This looks like a HackTheBox shared-infra range. HTB rules prohibit "
             "aggressive/automated mass scanning. Forcing the gentle profile.")
    if klass == "external":
        warn("Target is NOT in a known lab/HTB range. Make sure you are explicitly "
             "authorized to test it.")
    if assume_yes:
        info("--yes supplied; proceeding.")
        return True
    try:
        ans = input(f"\n{C.YELLOW}Confirm you own or are authorized to test this target [y/N]: {C.RESET}")
    except (EOFError, KeyboardInterrupt):
        return False
    return ans.strip().lower() in ("y", "yes")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    klass = classify_target(args.target)

    if args.profile == "gentle" or (args.profile == "auto" and klass == "htb"):
        profile = Profile.gentle()
    else:
        profile = Profile.lab()

    if args.parallelism > 0:
        profile.parallelism = args.parallelism

    cfg = RunConfig(
        target=args.target,
        profile=profile,
        aggressive=args.aggressive and klass != "htb",  # never aggressive on HTB
        auto_exploit=args.auto_exploit,
        identify_only=args.identify_only,
        out_dir=args.out_dir,
        wordlist_dirs=args.wordlist_dirs,
        wordlist_users=args.wordlist_users,
        wordlist_pass=args.wordlist_pass,
        discovered_tools=detect_tools(),
        hostname=args.hostname,
        resume=args.resume,
        no_udp=args.no_udp,
        no_nse_vuln=args.no_nse_vuln,
        default_creds=not args.no_default_creds,
        post_exploit=args.post_exploit,
        peas_dir=args.peas_dir,
    )
    if args.aggressive and klass == "htb":
        warn("--aggressive ignored: target is HTB shared infra.")

    banner(f"ctfauto {__version__}")
    missing = [t for t, path in cfg.discovered_tools.items() if not path]
    if missing:
        warn("Missing tools (steps using them will be skipped): " + ", ".join(missing))
    os.makedirs(cfg.out_dir, exist_ok=True)

    if not authorization_gate(cfg, klass, args.yes):
        err("Authorization not confirmed. Aborting.")
        return 1

    # HTB ergonomics: detect a .htb hostname and optionally add to /etc/hosts.
    if not cfg.hostname and klass == "htb":
        detected = recon.detect_htb_hostname(cfg)
        if detected:
            cfg.hostname = detected
            good(f"detected hostname: {detected}")
            if args.add_hosts:
                recon.add_to_hosts(cfg.target, detected)

    banner("PHASE 1 — RECON")
    host = recon.scan(cfg)
    if not host.all_services:
        warn("No open services; nothing further to do.")
        report.write_reports(cfg, host, enum_mod.EnumResult(), exploit.ExploitResult())
        return 0

    banner("PHASE 2 — ENUMERATION")
    enum_res = enum_mod.enumerate_host(cfg, host)

    banner("PHASE 3 — EXPLOIT IDENTIFICATION")
    exp_res = exploit.identify(cfg, host, enum_res)

    banner("PHASE 4 — EXPLOITATION")
    exploit.auto_exploit(cfg, host, exp_res)

    banner("PHASE 5 — POST-EXPLOITATION")
    postex_res = postexploit.run_postexploit(cfg, host, exp_res)

    banner("PHASE 6 — REPORT")
    md, js = report.write_reports(cfg, host, enum_res, exp_res, postex_res)
    good(f"Done. Open {md} for the readable report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
