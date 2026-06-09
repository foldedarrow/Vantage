# ctfauto

Automated **recon → enumeration → exploit-identification → (gated) exploitation**
orchestrator for machines you own or are explicitly authorized to test —
HackTheBox boxes over the HTB VPN, Metasploitable 2, and other lab VMs on your
own network.

> ⚠️ **Authorization.** This tool actively scans and attacks targets. Only point
> it at systems you own or have explicit written permission to test. Running it
> against systems you don't control is illegal in most jurisdictions.

## How it's designed (safety model)

The exploitation stage is **gated**, not a free-for-all:

| Behavior | When it runs |
|---|---|
| Recon + enumeration + exploit **identification** | Always (lab/HTB; external needs opt-in) |
| **SAFE** auto-exploit (non-destructive backdoors that just hand you a shell — vsftpd 2.3.4, UnrealIRCd, distccd, Samba usermap) | Lab targets, with `--auto-exploit` |
| Default-credential checks + active web (sqlmap/LFI/CMS, `.git` dump) | Lab targets, with `--auto-exploit` |
| Brute-force (hydra, bounded) + escalated sqlmap | Only with `--aggressive` (lab targets only) |
| Nothing fired, commands printed for you to run | `--identify-only` |

**Target classification drives everything.** Targets are classified `lab`
(RFC1918), `htb` (HackTheBox ranges), or `external` (anything else — a
public/unknown IP):

- **`external` targets are refused by default.** ctfauto won't scan or exploit a
  public/unknown IP — even `--identify-only`, which still sends real scan traffic
  — unless you pass `--allow-external`, asserting written authorization. Even then
  the target gets the cautious gentle profile.
- **HackTheBox is treated specially.** HTB ranges (`10.10.0.0/16`, incl. the
  lab/release arenas and your tun0 handout, plus `10.129.0.0/16`) are auto-forced
  to the **gentle** profile: top-1000 ports, `-T2`, no auto-exploit, no nikto, no
  active web stage, and `--aggressive` is ignored. Add custom ranges (Pro Labs,
  home lab) in `~/.config/ctfauto/networks.json` (`{"htb": [...], "lab": [...]}`).
- ctfauto refuses to scan **your own VPN client IP** (tun0 handout range) as a
  target.

Run `python run.py --check` (or `ctfauto --check`) any time to see which tools are
installed and the exact install command for whatever's missing.

## What it does (phases)

1. **Recon** — nmap TCP (`-p-` on lab), plus an optional **UDP top-50 pass**
   (SNMP/DNS/TFTP) and **NSE vuln scripts** (`--script vuln,smb-vuln-*,ssl-enum-ciphers`)
   with the results parsed into the report.
2. **Enumeration** (per-service, run **concurrently**):
   - HTTP: whatweb fingerprint → CMS detection → `wpscan`/`droopescan`,
     quick-win files (`robots.txt`, `.git/`, backups, `.env`), nikto, gobuster,
     and **vhost discovery** (ffuf) when a hostname is known.
   - SMB: enum4linux + null-session **share listing and per-share `ls`**.
   - TLS: `sslscan` for Heartbleed/weak-cipher/expired-cert flags.
   - SNMP: `onesixtyone` + `snmpwalk` with the `public` community.
3. **Exploit identification** — curated signatures, **default-credential checks**,
   an **active web-exploitation branch**, and structured **Exploit-DB
   correlation** via `searchsploit --json`. The enumeration phase crawls for
   parameterized URLs (`?id=…`) and feeds each one to the web stage.
4. **Exploitation** — dispatched by category:
   - SAFE Metasploit modules + default-cred checks auto-run.
   - **Active web exploitation runs under `--auto-exploit`:** `.git` dumping
     (always safe-auto), **sqlmap** against each discovered parameterized URL,
     **active LFI probing** (path-traversal payloads injected per-parameter,
     responses checked for `/etc/passwd` etc.), and **CMS exploitation**
     (wpscan/droopescan vuln enumeration + version-matched Exploit-DB lookup).
     `--aggressive` escalates sqlmap to `--level=5 --risk=3 --dbs`.
   - Brute-force needs `--aggressive`.
5. **Post-exploitation** (`--post-exploit`) — stages `linpeas`/`winPEAS` over
   opened Metasploit sessions via the **msfrpc API** (pymetasploit3), with a
   manual-recipe fallback.
6. **Report** — Markdown + JSON, confirmed wins surfaced at the top.

## Requirements

Python 3.9+ and standard pentest CLI tools on `PATH` (i.e. run it from Kali).
Missing tools are detected at startup and their steps are skipped — **nmap is
the only hard requirement** for useful output. Tools used if present:
`nmap, gobuster, nikto, whatweb, ffuf, hydra, searchsploit, enum4linux,
smbclient, sslscan, onesixtyone, snmpwalk, wpscan, droopescan, sqlmap, mysql,
git-dumper, msfconsole, msfrpcd, curl`.

Optional Python package for msfrpc-driven post-exploitation:
`pip install pymetasploit3` (and run `msfrpcd -P "$MSFRPC_PASS" -S`).
No other Python packages beyond the standard library.

## Usage

```bash
# Recon + enum + identify exploits, fire nothing (safest):
python run.py 192.168.56.101 --identify-only

# Metasploitable 2 on your lab net — auto-run SAFE modules:
python run.py 192.168.56.101 --auto-exploit

# Go loud on an owned lab VM (brute-force etc.):
python run.py 192.168.56.101 --auto-exploit --aggressive

# A HackTheBox box (auto-forced to gentle; detects .htb hostname):
python run.py 10.10.11.42 --add-hosts

# Full lab run with post-exploit privesc enumeration:
python run.py 192.168.56.101 --auto-exploit --post-exploit --peas-dir ~/peass

# Custom wordlists:
python run.py 10.0.0.5 --auto-exploit \
    --wordlist-dirs /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    --wordlist-pass /usr/share/wordlists/rockyou.txt
```

Useful flags: `--no-udp` / `--no-nse-vuln` (skip the slow passes),
`--no-default-creds` (disable the default-cred checks, which are on by default),
`--hostname box.htb` (force a vhost), `-j N` (concurrency override),
`--yes` (skip the authorization prompt), `-o DIR` (output dir, default `loot/`).

## Output

Per target, written to the output dir:
- `report_<target>.md` — readable report (services, findings, exploit candidates, any auto-run results)
- `report_<target>.json` — same data, machine-readable
- `nmap_<target>.xml` — raw nmap XML

## Layout

```
ctfauto/
  run.py                  # entry point
  ctfauto/
    cli.py                # arg parsing, authorization gate, phase orchestration
    config.py             # profiles, target classification, tool detection
    util.py               # logging + safe command runner
    modules/
      recon.py            # nmap wrapper + XML parsing
      enumerate.py        # per-service enumeration (http/ftp/smb/...)
      exploit.py          # exploit ID + gated auto-exploit
      report.py           # md + json reporting
```

## Extending it

Add a new service handler in `modules/enumerate.py` (dispatch on port/name in
`enumerate_host`), and add exploit signatures in `modules/exploit.py`
(`_signature_candidates`). Each is isolated, so a new service is one function.
