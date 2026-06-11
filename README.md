# ctfauto

Automated **recon → enumeration → exploit-identification → report** tool for
machines you own or are explicitly authorized to test — HackTheBox boxes over the
HTB VPN, Metasploitable 2, and other lab VMs on your own network.

ctfauto is a **recon and enumeration tool**. It maps the target, enumerates every
service it finds, and identifies candidate exploits and known CVEs — then writes a
report. **It never exploits anything.** The exploit candidates in the report are
informational: a starting point for manual, authorized testing.

> ⚠️ **Authorization.** Recon and enumeration send real, active scan traffic at
> the target (nmap, dir brute-forcing, NSE vuln scripts, web crawling). Only point
> ctfauto at systems you own or have explicit written permission to test. Scanning
> systems you don't control is illegal in most jurisdictions.

## Quick start

```bash
git clone https://github.com/foldedarrow/AutoPentest.git
cd AutoPentest
sudo ./setup.sh                 # apt/pipx/gem-installs the toolchain (Kali)
sudo python3 run.py --check     # show the tool + wordlist matrix
sudo python3 run.py 192.168.56.101   # recon + enum + report
```

`run.py` is the entry point; everything runs from Kali with the standard pentest
tools on `PATH`. **nmap is the only hard requirement** — any other missing tool is
detected at startup and its steps are skipped.

## Safety model

ctfauto does not fire exploits, brute-force credentials, run sqlmap/LFI probes, or
test default credentials. Those have all been removed. What remains is active
*reconnaissance*, and the report it produces — so the safety model is about **who
you're allowed to scan**, not about gating an attack.

**Target classification drives everything.** Targets are classified `lab`
(RFC1918), `htb` (HackTheBox ranges), or `external` (anything else — a
public/unknown IP):

- **`external` targets are refused by default.** Recon/enum sends real scan
  traffic, so ctfauto won't touch a public/unknown IP unless you pass
  `--allow-external`, asserting written authorization. On `--profile auto` it then
  **prompts** you to choose the cautious *gentle* profile or the loud *lab*
  profile; pass `--profile lab` to opt into the loud profile directly.
- **HackTheBox is treated specially.** HTB ranges (`10.10.0.0/16`, incl. the
  lab/release arenas and your tun0 handout, plus `10.129.0.0/16`) are auto-forced
  to the **gentle** profile: top-1000 ports, `-T2`, no nikto, no active web stage,
  and `--aggressive` is ignored. Add custom ranges (Pro Labs, home lab) in
  `~/.config/ctfauto/networks.json` (`{"htb": [...], "lab": [...]}`).
- ctfauto refuses to scan **your own VPN client IP** (tun0 handout range) as a
  target.
- The Markdown report **redacts obvious secrets** (passwords, private keys, AWS
  keys); the raw, unredacted data stays in the gitignored JSON/loot.

`--aggressive` (lab targets only) doesn't enable any attack — it turns the
enumeration up to its loudest, most thorough setting (full TCP, nikto, NSE vuln
scripts, active web crawl). Run `python3 run.py --check` any time to see which
tools are installed and the exact install command for whatever's missing.

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
     (crawl + arjun). Discovered URLs are scoped to the target host — off-target
     links are never touched.
   - SMB: enum4linux + null-session **share listing and per-share `ls`**.
   - TLS: `sslscan` for Heartbleed/weak-cipher/expired-cert flags.
   - SNMP: `onesixtyone` + `snmpwalk` using the discovered community string.
3. **Exploit identification (report-only)** — curated service signatures,
   **known default-credential pairs** (flagged, never tried), candidate web
   findings, and **version-matched Exploit-DB correlation** via
   `searchsploit --json`. NSE-flagged CVEs are **bridged** to curated exploits, so
   a known bug is still listed even when the service banner was empty. Everything
   here is informational — ctfauto fires nothing.
4. **Report** — Markdown + JSON. The exploit candidates are clearly marked as
   *not run*, intended as leads for manual follow-up. An incremental
   `events_<target>.ndjson` event log is written for automation/re-analysis.

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
```

- **AWS S3** — exists / anonymously **listable** / **readable**. Uses
  `aws s3 --no-sign-request` when present, with an anonymous-HTTP fallback.
- **Azure Blob** — storage-account existence + anonymous **container listing**.
- **Requires `--allow-cloud`** (its own authorization gate), **read-only**,
  bounded (candidate cap, default 200) and rate-limited. It does **not** do
  authenticated cloud testing — a deliberate non-goal.

## Requirements

Python 3.9+ and standard pentest CLI tools on `PATH` (run it from Kali). `setup.sh`
installs the toolchain; `--check` shows what's present. Tools used if available:
`nmap, gobuster, feroxbuster, nikto, whatweb, ffuf, arjun, searchsploit,
enum4linux, smbclient, sslscan, onesixtyone, snmpwalk, wpscan, droopescan, curl`
(plus optional cloud helpers `aws, s3scanner, cloud_enum`). No non-stdlib Python
packages.

> **Lab networking tip:** if you run your VMs under a hypervisor (Parallels,
> VMware, VirtualBox), put the Kali VM on **bridged** networking, not NAT/Shared.
> NAT gives Kali a private hypervisor IP, which can make SYN scans return
> `tcpwrapped`. (ctfauto's `-sT` fallback works around the scan half, but bridged
> is the proper fix.)

## Usage

```bash
# Recon + enum + report (the only mode):
python3 run.py 192.168.56.101

# Go loud on an owned lab VM (fullest, noisiest enumeration):
python3 run.py 192.168.56.101 --aggressive

# A HackTheBox box (auto-forced to gentle; detects .htb hostname):
python3 run.py 10.10.11.42 --add-hosts

# Force a connect scan (if SYN scans come back tcpwrapped):
python3 run.py 192.168.56.101 --connect

# Resume a previous run, and cap total wall-clock time:
python3 run.py 192.168.56.101 --resume --max-time 1200

# Custom wordlists / non-standard SecLists install:
python3 run.py 10.0.0.5 \
    --wordlist-dirs /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    --seclists-dir /opt/SecLists
```

### Flag reference

**Intensity:** `--aggressive` (loudest, most thorough enumeration — lab only),
`--no-default-creds` (skip flagging known default-cred pairs in the report).

**Scope / profile:** `--profile auto|lab|gentle`, `--allow-external` (authorize a
public IP — prompts for profile on `auto`), `--yes` (skip the auth prompt,
lab/HTB only).

**Scanning:** `--connect` / `-sT` (force TCP connect scan), `--no-udp`,
`--no-nse-vuln`, `--max-time <sec>` (global wall-clock budget), `-j N`
(concurrency), `--resume` (reuse cached recon + enum).

**Targeting:** `--hostname box.htb`, `--add-hosts`.

**Wordlists:** `--seclists-dir`, `--wordlist-dirs`, `--wordlist-users`,
`--wordlist-pass` (all auto-resolve from SecLists/rockyou if omitted).

**Cloud:** `--cloud`, `--allow-cloud`, `--cloud-name <seed>`,
`--cloud-providers aws,azure`, `--cloud-extra-words`, `--cloud-cap N`.

**Output / misc:** `-o <dir>` (default `loot/`), `--check` / `--doctor`,
`--version`.

### Wordlists & SecLists

ctfauto uses [SecLists](https://github.com/danielmiessler/SecLists) wherever it
helps — directory/file brute-forcing, vhost discovery, and parameter discovery
prefer SecLists and fall back to smaller system lists (dirb, rockyou, metasploit)
when it isn't present. It finds SecLists automatically (`/usr/share/seclists`,
`/usr/share/SecLists`, `/opt`, `~/`); override with `--seclists-dir PATH` or
`$CTFAUTO_SECLISTS`. Run `ctfauto --check` to see the resolved root and which list
maps to each purpose.

## Output

Per target, written to the output dir (`loot/` by default):

- `report_<target>.md` — readable report (services, NSE findings, enumeration,
  and informational exploit candidates), secrets redacted
- `report_<target>.json` — same data, machine-readable, unredacted
- `events_<target>.ndjson` — incremental event log (phase/finding events)
- `state_<target>.json` — cached recon + enum for `--resume`
- `nmap_<target>*.xml` / `.txt` — raw scans

## Layout

```
ctfauto/
  run.py                  # entry point
  setup.sh                # toolchain installer (Kali)
  ctfauto/
    cli.py                # arg parsing, authorization gate, phase orchestration
    config.py             # profiles, target classification, tool detection
    util.py               # logging, safe command runner, time budget
    wordlists.py          # SecLists resolver + per-purpose getters
    modules/
      recon.py            # nmap wrapper, XML parsing, connect-scan fallback, NSE
      enumerate.py        # per-service enumeration (http/ftp/smb/snmp/tls/...)
      exploit.py          # exploit identification (report-only — fires nothing)
      cloud.py            # unauthenticated S3/Azure misconfig recon
      report.py           # md + json reporting (with redaction)
  tests/                  # stdlib unittest suite (no third-party deps)
```

## Tests

```bash
python3 -m unittest discover -s tests
```

Pure-stdlib `unittest`, no dependencies. Covers target classification, the scope
gates, scan/connect-fallback detection, NSE grouping + CVE bridging, candidate
dedupe, redaction, the time budget, and the cloud module.

## Extending it

Add a service handler in `modules/enumerate.py` (dispatch on port/name in
`enumerate_host`), and exploit signatures in `modules/exploit.py`
(`_signature_candidates`, or the `_CVE_SIGNATURES` / `_EDB_MSF_PROMOTIONS` maps).
Each is isolated, so a new service or exploit signature is one function/entry.
