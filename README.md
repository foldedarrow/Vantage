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

## Cloud recon (unauthenticated misconfiguration discovery)

ctfauto can enumerate **publicly-exposed** cloud storage for a target — the cloud
equivalent of the host recon above. It is scoped to *misconfiguration discovery*:
it probes only resources the provider has already made reachable to anonymous
requests, and it never touches private resources, credentials, or IAM.

```bash
# Enumerate public S3 buckets for a keyword (cloud-only run):
python run.py acme --cloud --allow-cloud --cloud-name acme

# From a domain, AWS + Azure, alongside a host scan:
python run.py 10.10.11.42 --cloud --allow-cloud \
    --cloud-name acme.com --cloud-providers aws,azure

# Add the (gated) write test — writes one marker object to any world-writable
# bucket and tells you to delete it:
python run.py acme --cloud --allow-cloud --cloud-name acme --aggressive
```

What it checks, per candidate name (generated from the seed keyword/domain, plus
any bucket names harvested from the web-enum crawl):

- **AWS S3** — exists / anonymously **listable** / anonymously **readable** /
  (under `--aggressive`) anonymously **writable**. Uses `aws s3 --no-sign-request`
  when the AWS CLI is present, with a built-in anonymous-HTTP fallback otherwise.
- **Azure Blob** — storage-account existence + anonymous **container listing**.

Safety, same spirit as the rest of the tool:

- **Requires `--allow-cloud`** — an explicit assertion that you're authorized to
  enumerate the named target's cloud assets. There's a separate authorization gate
  for it. (Cloud targets are public provider infrastructure, so the scope question
  is sharper than your lab IPs.)
- **Read-only by default.** The only write action (the world-writable-bucket test)
  is gated behind `--aggressive`, writes a single innocuous marker object, logs it
  loudly, and prints the exact command to delete it.
- Bounded (candidate cap, default 200) and rate-limited to stay polite.
- It does **not** do authenticated cloud testing (IAM enumeration, privesc, using a
  key) — that's a deliberate non-goal of this module.

Optional helpers (`awscli`, `s3scanner`, `cloud_enum`) improve results but aren't
required — `ctfauto --check` shows what's present.

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

# Custom wordlists / point at a non-standard SecLists install:
python run.py 10.0.0.5 --auto-exploit \
    --wordlist-dirs /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    --wordlist-pass /usr/share/wordlists/rockyou.txt \
    --seclists-dir /opt/SecLists
```

### Wordlists & SecLists

ctfauto uses [SecLists](https://github.com/danielmiessler/SecLists) wherever it
helps — directory/file brute-forcing, vhost discovery, LFI payloads, parameter
discovery, and credential brute-force all prefer SecLists wordlists and fall back
to smaller system lists (dirb, rockyou, metasploit) when SecLists isn't present.

It finds SecLists automatically across the common install locations
(`/usr/share/seclists`, `/usr/share/SecLists`, `/opt`, `~/`). Override with
`--seclists-dir PATH` or the `CTFAUTO_SECLISTS` env var. Per-list overrides
(`--wordlist-dirs`, `--wordlist-users`, `--wordlist-pass`) still win. Run
`ctfauto --check` to see the SecLists root and exactly which wordlist resolves for
each purpose.

Useful flags: `--no-udp` / `--no-nse-vuln` (skip the slow passes),
`--no-default-creds` (disable the default-cred checks, which are on by default),
`--hostname box.htb` (force a vhost), `--seclists-dir PATH` (SecLists location),
`-j N` (concurrency override), `--yes` (skip the authorization prompt),
`-o DIR` (output dir, default `loot/`).

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
