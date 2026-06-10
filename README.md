# ctfauto

Automated **recon → enumeration → exploit-identification → (gated) exploitation
→ post-exploitation → report** orchestrator for machines you own or are
explicitly authorized to test — HackTheBox boxes over the HTB VPN, Metasploitable
2, and other lab VMs on your own network.

> ⚠️ **Authorization.** This tool actively scans and attacks targets. Only point
> it at systems you own or have explicit written permission to test. Running it
> against systems you don't control is illegal in most jurisdictions.

## Quick start

```bash
git clone https://github.com/foldedarrow/AutoPentest.git
cd AutoPentest
sudo ./setup.sh                 # apt/pipx/gem-installs the toolchain (Kali)
sudo python3 run.py --check     # show the tool + wordlist matrix
sudo python3 run.py 192.168.56.101 --auto-exploit   # scan + get shells
```

`run.py` is the entry point; everything runs from Kali with the standard pentest
tools on `PATH`. **nmap is the only hard requirement** — any other missing tool is
detected at startup and its steps are skipped.

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
  — unless you pass `--allow-external`, asserting written authorization. On
  `--profile auto` it then **prompts** you to choose the cautious *gentle* profile
  or the full *lab* profile; pass `--profile lab` or `--aggressive` to opt into
  aggressive automation directly.
- **HackTheBox is treated specially.** HTB ranges (`10.10.0.0/16`, incl. the
  lab/release arenas and your tun0 handout, plus `10.129.0.0/16`) are auto-forced
  to the **gentle** profile: top-1000 ports, `-T2`, no auto-exploit, no nikto, no
  active web stage, and `--aggressive` is ignored. Add custom ranges (Pro Labs,
  home lab) in `~/.config/ctfauto/networks.json` (`{"htb": [...], "lab": [...]}`).
- ctfauto refuses to scan **your own VPN client IP** (tun0 handout range) as a
  target.
- The Markdown report **redacts obvious secrets** (passwords, private keys, AWS
  keys, cracked creds); the raw, unredacted data stays in the gitignored JSON/loot.

Run `python3 run.py --check` (or `ctfauto --check`) any time to see which tools are
installed and the exact install command for whatever's missing.

## What it does (phases)

1. **Recon** — nmap TCP (`-p-` on lab, top-1000 on gentle), an optional **UDP
   top-50 pass** (SNMP/DNS/TFTP), and **NSE vuln scripts**
   (`--script vuln,smb-vuln-*,ssl-enum-ciphers`), grouped per-port in the report.
   - **Connect-scan fallback:** if a SYN scan comes back with everything
     `tcpwrapped` (common when a hypervisor NAT/virtual NIC mangles half-open
     connections), ctfauto automatically re-scans the open ports with a TCP
     connect scan (`-sT -sV`) and keeps the richer result. Force it from the start
     with `--connect` / `-sT`.
2. **Enumeration** (per-service, run **concurrently**):
   - HTTP: whatweb fingerprint → CMS detection → `wpscan`/`droopescan`,
     quick-win files (`robots.txt`, `.git/`, backups, `.env`), nikto, gobuster/
     feroxbuster, **vhost discovery** (ffuf), and **parameterized-URL discovery**
     (crawl + arjun) feeding the web-exploit stage. Discovered URLs are scoped to
     the target host — off-target links are never tested.
   - SMB: enum4linux + null-session **share listing and per-share `ls`**.
   - TLS: `sslscan` for Heartbleed/weak-cipher/expired-cert flags.
   - SNMP: `onesixtyone` + `snmpwalk` using the discovered community string.
3. **Exploit identification** — curated signatures, **default-credential checks**
   (ssh/ftp/mysql/tomcat-manager), an **active web-exploitation branch**, and
   **version-matched Exploit-DB correlation** via `searchsploit --json`. Strong,
   well-known matches (vsftpd, Samba, UnrealIRCd, distcc, ProFTPD) are
   **auto-promoted** into the gated exploit flow. NSE-flagged CVEs are **bridged**
   to the curated exploits, so a known bug still fires even when the service banner
   was empty.
4. **Exploitation** — dispatched by category:
   - SAFE Metasploit modules + default-cred checks auto-run. Modules use explicit
     **bind/interact payloads** (and set `LHOST` automatically) so reverse-payload
     routing can't silently abort the exploit.
   - **Active web exploitation under `--auto-exploit`:** `.git` dumping (always
     safe-auto), **sqlmap** against each discovered parameterized URL, **active LFI
     probing** (path-traversal payloads per-parameter, responses checked for
     `/etc/passwd` etc.), and **CMS exploitation** (wpscan/droopescan +
     version-matched Exploit-DB lookup). `--aggressive` escalates sqlmap to
     `--level=5 --risk=3 --dbs`.
   - Brute-force (bounded hydra) needs `--aggressive`.
5. **Post-exploitation** (`--post-exploit`) — over the **msfrpc API**
   (pymetasploit3): runs a proof recipe per session (`id`, `uname -a`, grabs
   `user.txt`/`root.txt`), then optional `linpeas`/`winPEAS` whose output is parsed
   for actionable privesc leads (SUID GTFOBins, sudo NOPASSWD, writable passwd,
   cron, kernel CVEs). Manual-recipe fallback when msfrpc isn't available.
6. **Report** — Markdown + JSON, confirmed wins (and any captured flags) surfaced
   at the top. An incremental `events_<target>.ndjson` event log is written for
   automation/re-analysis.

## Cloud recon (unauthenticated misconfiguration discovery)

ctfauto can enumerate **publicly-exposed** cloud storage for a target — the cloud
equivalent of the host recon above. It probes only resources the provider has
already made reachable to anonymous requests, and never touches private resources,
credentials, or IAM.

```bash
# Public S3 buckets for a keyword (cloud-only run):
python3 run.py acme --cloud --allow-cloud --cloud-name acme

# From a domain, AWS + Azure, alongside a host scan:
python3 run.py 10.10.11.42 --cloud --allow-cloud \
    --cloud-name acme.com --cloud-providers aws,azure

# Add the (gated) write test — writes one marker object to any world-writable
# bucket and tells you to delete it:
python3 run.py acme --cloud --allow-cloud --cloud-name acme --aggressive
```

- **AWS S3** — exists / anonymously **listable** / **readable** / (under
  `--aggressive`) **writable**. Uses `aws s3 --no-sign-request` when present, with
  an anonymous-HTTP fallback.
- **Azure Blob** — storage-account existence + anonymous **container listing**.
- **Requires `--allow-cloud`** (its own authorization gate), **read-only by
  default**, bounded (candidate cap, default 200) and rate-limited. It does **not**
  do authenticated cloud testing — a deliberate non-goal.

## Requirements

Python 3.9+ and standard pentest CLI tools on `PATH` (run it from Kali). `setup.sh`
installs the toolchain; `--check` shows what's present. Tools used if available:
`nmap, gobuster, feroxbuster, nikto, whatweb, ffuf, arjun, hydra, searchsploit,
enum4linux, smbclient, sslscan, onesixtyone, snmpwalk, wpscan, droopescan, sqlmap,
mysql, git-dumper, msfconsole, msfrpcd, curl` (plus optional cloud helpers
`aws, s3scanner, cloud_enum`).

Optional Python package for msfrpc post-exploitation: `pip install pymetasploit3`
(then run `msfrpcd -P "$MSFRPC_PASS" -S`). No other non-stdlib Python packages.

> **Lab networking tip:** if you run your VMs under a hypervisor (Parallels,
> VMware, VirtualBox), put the Kali VM on **bridged** networking, not NAT/Shared.
> NAT gives Kali a private hypervisor IP the target can't route back to, which
> breaks reverse shells and can make SYN scans return `tcpwrapped`. Bridged puts
> Kali on the real LAN. (ctfauto's `-sT` fallback works around the scan half, but
> bridged is the proper fix.)

## Usage

```bash
# Recon + enum + identify exploits, fire nothing (safest):
python3 run.py 192.168.56.101 --identify-only

# Metasploitable 2 on your lab net — auto-run SAFE modules:
python3 run.py 192.168.56.101 --auto-exploit

# Go loud on an owned lab VM (brute-force etc.):
python3 run.py 192.168.56.101 --auto-exploit --aggressive

# A HackTheBox box (auto-forced to gentle; detects .htb hostname):
python3 run.py 10.10.11.42 --add-hosts

# Full lab run with post-exploit privesc enumeration:
msfrpcd -P ctfauto -S &
python3 run.py 192.168.56.101 --auto-exploit --post-exploit --peas-dir ~/peass

# Force a connect scan (if SYN scans come back tcpwrapped):
python3 run.py 192.168.56.101 --auto-exploit --connect

# Resume a previous run, and cap total wall-clock time:
python3 run.py 192.168.56.101 --auto-exploit --resume --max-time 1200

# Custom wordlists / non-standard SecLists install:
python3 run.py 10.0.0.5 --auto-exploit \
    --wordlist-dirs /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    --wordlist-pass /usr/share/wordlists/rockyou.txt \
    --seclists-dir /opt/SecLists
```

### Flag reference

**Aggression:** `--auto-exploit` (fire SAFE modules — the on-switch),
`--aggressive` (brute-force + escalated/destructive, lab only),
`--identify-only` (never fire), `--no-default-creds`.

**Scope / profile:** `--profile auto|lab|gentle`, `--allow-external` (authorize a
public IP — prompts for profile on `auto`), `--yes` (skip the auth prompt,
lab/HTB only).

**Scanning:** `--connect` / `-sT` (force TCP connect scan), `--no-udp`,
`--no-nse-vuln`, `--max-time <sec>` (global wall-clock budget), `-j N`
(concurrency), `--resume` (reuse cached recon + enum).

**Targeting:** `--hostname box.htb`, `--add-hosts`.

**Wordlists:** `--seclists-dir`, `--wordlist-dirs`, `--wordlist-users`,
`--wordlist-pass` (all auto-resolve from SecLists/rockyou if omitted).

**Post-exploit:** `--post-exploit`, `--peas-dir <dir>`.

**Cloud:** `--cloud`, `--allow-cloud`, `--cloud-name <seed>`,
`--cloud-providers aws,azure`, `--cloud-extra-words`, `--cloud-cap N`.

**Output / misc:** `-o <dir>` (default `loot/`), `--check` / `--doctor`,
`--version`.

### Wordlists & SecLists

ctfauto uses [SecLists](https://github.com/danielmiessler/SecLists) wherever it
helps — directory/file brute-forcing, vhost discovery, LFI payloads, parameter
discovery, and credential brute-force prefer SecLists and fall back to smaller
system lists (dirb, rockyou, metasploit) when it isn't present. It finds SecLists
automatically (`/usr/share/seclists`, `/usr/share/SecLists`, `/opt`, `~/`);
override with `--seclists-dir PATH` or `$CTFAUTO_SECLISTS`. Run `ctfauto --check`
to see the resolved root and which list maps to each purpose.

## Output

Per target, written to the output dir (`loot/` by default):

- `report_<target>.md` — readable report (services, NSE findings, enumeration,
  exploit candidates + auto-run results, post-exploit), secrets redacted, wins/flags up top
- `report_<target>.json` — same data, machine-readable, unredacted
- `events_<target>.ndjson` — incremental event log (phase/finding/exploit events)
- `state_<target>.json` — cached recon + enum for `--resume`
- `nmap_<target>*.xml` / `.txt` — raw scans; `gitloot/`, `sqlmap/` — web artifacts

## Layout

```
ctfauto/
  run.py                  # entry point
  setup.sh                # toolchain installer (Kali)
  ctfauto/
    cli.py                # arg parsing, authorization gate, phase orchestration
    config.py             # profiles, target classification, tool detection
    util.py               # logging, safe command runner, time budget, LHOST helper
    wordlists.py          # SecLists resolver + per-purpose getters
    modules/
      recon.py            # nmap wrapper, XML parsing, connect-scan fallback, NSE
      enumerate.py        # per-service enumeration (http/ftp/smb/snmp/tls/...)
      exploit.py          # exploit ID + gated auto-exploit
      cloud.py            # unauthenticated S3/Azure misconfig recon
      report.py           # md + json reporting (with redaction)
      postexploit.py      # msfrpc proof recipe + privesc-lead parsing
  tests/                  # stdlib unittest suite (no third-party deps)
```

## Tests

```bash
python3 -m unittest discover -s tests
```

Pure-stdlib `unittest`, no dependencies. Covers target classification, the scope
gates, scan/connect-fallback detection, NSE grouping + CVE bridging, dedupe,
detection-string robustness, redaction, the time budget, and the cloud module.

## Extending it

Add a service handler in `modules/enumerate.py` (dispatch on port/name in
`enumerate_host`), and exploit signatures in `modules/exploit.py`
(`_signature_candidates`, or the `_CVE_SIGNATURES` / `_EDB_MSF_PROMOTIONS` maps).
Each is isolated, so a new service or exploit is one function/entry.
