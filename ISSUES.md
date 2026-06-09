# ctfauto — issues & improvement backlog

Findings from a full read + runtime verification of the codebase (commit `8142874`).
Each item is written to be individually actionable: **severity · location · what's wrong ·
fix**. Verified items were confirmed by exercising the code, not just reading it.

Severity key: **S1** = safety/scope (can hit the wrong target or violate rules) ·
**S2** = correctness (a documented feature silently doesn't work) ·
**S3** = robustness (crashes / wasted work) · **S4** = capability gap (toward full
automation) · **S5** = polish.

Status key: ✅ verified by running the code · 🔎 verified by static analysis · 💡 design.

---

## S1 — Safety & scope

### #1 — `external` targets still get the full `lab` profile and can be auto-exploited ✅
**Where:** `cli.py` `main()` (profile selection), `config.classify_target`.
**What:** Classification returns `htb` / `lab` / `external`, but only `htb` changes
behavior. An `external` target (anything outside RFC1918/HTB — i.e. a *public* IP)
falls through to `Profile.lab()`: `-p- -T4 -O`, `enable_auto_exploit=True`. The only
consequence of `external` is a printed warning at the gate. Verified: `192.0.2.1`
(public TEST-NET) → classified `external`, profile `lab (owned VMs)`,
auto-exploit-capable. With `--yes --auto-exploit` it would fire sqlmap/MSF/etc. at a
public host.
**Fix:** Make `external` a hard stop by default. Force `gentle`, disable
auto-exploit/aggressive, and require an explicit `--i-have-authorization` (or
`--allow-external`) flag before *any* active phase against an `external` target. The
authorization gate text should change from a warning to a refusal unless that flag is
present.

### #2 — `--yes` skips the only authorization checkpoint entirely ✅
**Where:** `cli.py` `authorization_gate()`.
**What:** `--yes` returns `True` immediately, bypassing the prompt even for `external`
targets. Good for scripting lab runs; dangerous combined with #1.
**Fix:** Allow `--yes` to satisfy the prompt only for `lab`/`htb`. For `external`,
require the dedicated authorization flag from #1 (don't let a generic `--yes` greenlight
a public IP).

### #3 — HTB range list is incomplete; tun0 client range mis-classified as `lab` ✅
**Where:** `config.HTB_NETWORKS`.
**What:** Only `10.10.10/24`, `10.10.11/24`, `10.129/16` are treated as HTB.
Verified: `10.10.14.x` (the **tun0 client-IP** range handed to *you* on the HTB VPN)
classifies as `lab` → full auto profile. Also, HTB machine/lab traffic appears on
ranges beyond these (Pro Labs, Release Arena, Starting Point, seasonal). Treating only
three /24-ish ranges as "HTB" means real HTB targets can land in `lab` and get the
aggressive profile — the exact thing the gentle profile exists to prevent.
**Fix:** Broaden to the documented HTB lab ranges and treat the whole `10.10.0.0/16`
plus `10.129.0.0/16` (and Pro Lab ranges) as HTB-gentle. Exclude the operator's own
tun0 address from "target" classification, or just never classify your own assigned IP
as a target. Make the HTB ranges a config constant the user can edit.

### #4 — Default-credential login attempts run under `--auto-exploit`, not gated as "active" 🔎
**Where:** `exploit.identify` (always adds cred candidates), `auto_exploit` gate.
**What:** Default-cred candidates are `safe=True`, so under `--auto-exploit` they fire
real `hydra`/`mysql` **login attempts** against the target. That's an active
authentication action (can lock accounts on some services) but is documented as merely
"safe, on by default." It's defensible for a lab, but it's not the same risk class as a
`.git` dump.
**Fix:** Keep them on by default for `lab`, but (a) never for `external`, (b) log them
clearly as active logins, and (c) consider a distinct `--default-creds` opt-in
separate from the generic "safe" bucket so the risk is explicit.

### #5 — `add_to_hosts` does a substring match and can corrupt `/etc/hosts` 🔎
**Where:** `recon.add_to_hosts`.
**What:** `if hostname in f.read()` is a naive substring test: `box.htb` matches
`devbox.htb`, so it may skip a needed entry; and it never checks the IP, so a re-run
after the box IP changes appends a duplicate/stale line. No file locking.
**Fix:** Parse lines, match on exact hostname token, and reconcile the IP (update the
line if the IP changed). Append atomically. Optionally back up `/etc/hosts` first.

---

## S2 — Correctness (documented features that silently don't work)

### #6 — Brute-force never actually runs, despite the safety-model table ✅
**Where:** `exploit.auto_exploit`, `_brute_candidates`.
**What:** Brute candidates are `category="brute"`, `safe=False`, **no `msf_module`**.
In `auto_exploit`, under `--aggressive` they pass `runnable`, aren't `creds`, then hit
`if not c.msf_module: continue` and are skipped. Verified: the only `hydra` execution
in the codebase is the *default-cred* path; the brute command (L372) is only ever
printed. So the README/safety-model row "Brute-force … runs with `--aggressive`" is
false — it's emitted to the report but never executed.
**Fix:** Add an explicit `category == "brute"` dispatch in `auto_exploit` that runs
hydra with the configured wordlists, bounded by `profile.max_brute_attempts`, lab-only,
`--aggressive`-only. Or, if intentional-by-omission, change the docs to say brute is
*identified only*. (Recommend implementing it, since the goal is full automation.)

### #7 — Tomcat default-creds are advertised but never tested ✅
**Where:** `exploit._DEFAULT_CREDS` (has `tomcat`), `_run_default_creds` (no tomcat
branch).
**What:** A Tomcat candidate is created and claims to try `tomcat:tomcat` etc., but
`_run_default_creds` only handles ssh/ftp (via hydra) and mysql (via client). Tomcat
falls through and tests nothing. Verified by title→proto parse.
**Fix:** Implement the Tomcat manager check (`curl` to `/manager/html` with basic-auth
for each pair, look for 200/403-vs-401), or drop tomcat from the set. Manager-deploy
RCE is a classic Metasploitable/HTB win, so implement it.

### #8 — `(community or True)` makes the SNMP guard a no-op; `snmp-check` branch is dead ✅
**Where:** `enumerate._enum_snmp`.
**What:** `if (community or True) and _have(cfg, "snmpwalk")` is always truthy on its
left side, so `snmpwalk` is attempted whether or not a community string was found, and
the `elif _have(cfg, "snmp-check")` can never be reached. Verified.
**Fix:** Decide the intent. Probably: try `onesixtyone` first; if a community is found
use it for `snmpwalk`; if `snmpwalk` is unavailable, fall back to `snmp-check`. Remove
the `or True`. Also `snmpwalk` is hardcoded to community `public` even if onesixtyone
found `private`/`community` — thread the discovered string through.

### #9 — msfrpc post-exploit reads session output once with no wait → usually empty ✅
**Where:** `postexploit._via_msfrpc`.
**What:** `shell.write(cmd)` then a single `shell.read()` with no delay/loop. The
Metasploit RPC shell is asynchronous; the command almost certainly hasn't produced
output yet, so `read()` returns empty. linpeas output (hundreds of lines, many seconds)
will never be captured this way. Also `scriptp` is chosen by `"windows" in str(sess)`,
a fragile heuristic over the repr of the session dict.
**Fix:** Loop: write, then poll `read()` with small sleeps until output stalls or a
timeout. Detect platform from `sess["platform"]`/`sess["type"]` (e.g. `meterpreter`
type or `platform == "windows"`), not the dict repr. Better: for linpeas, upload the
script and run it via a dedicated `post/multi/gather` flow or a meterpreter
`execute`-and-read loop. (See #20 for a cleaner approach.)

### #10 — SQLi "confirmed" detection is substring-based and can false-positive ✅
**Where:** `exploit.auto_exploit` (sqlmap result parse).
**What:** `injected = ... or ("parameter '" in out and "injectable" in out)`. Operator
precedence is actually fine (verified), but the *signal* is weak: a page or sqlmap log
that merely contains the word "injectable" (e.g. "no parameter seems injectable") can
flip `session_opened = True`. That then surfaces as a "Confirmed access" win in the
report.
**Fix:** Parse sqlmap's machine output instead of stdout scraping — run with
`--results-file`/`--output-dir` and read the structured result, or check for the
explicit `sqlmap identified the following injection point(s)` block and the
`Parameter: … (… injectable)` marker together. Treat anything else as "not confirmed."

### #11 — hydra success detection (`"login:" in out and "password:" in out`) is unreliable 🔎
**Where:** `exploit._run_default_creds`.
**What:** hydra prints the literal words "login:" and "password:" in its run banner and
status lines even on failure, so this can both false-positive and (with `-f` early
exit) mis-parse. Verified the check string.
**Fix:** Match hydra's actual success line format
(`[<port>][<proto>] host: <ip>   login: <u>   password: <p>`) with a regex anchored on
`host:` + `login:` on the *same* line, or use `-o -` JSON/`-b json` output and parse it.

### #12 — Samba (and any dual-port service) fires the same exploit twice ✅
**Where:** `exploit._signature_candidates`, `auto_exploit` (no dedupe).
**What:** Ports 139 and 445 both match the Samba usermap signature → two identical
candidates → the same MSF module runs twice against the same host. Verified with the
Metasploitable XML (two `:139`/`:445` Samba candidates). Wasteful and noisy; can also
double-open sessions.
**Fix:** Dedupe candidates by `(msf_module, host.ip)` before running; or key Samba on
the host, not the port. Generally, run each unique `msf_module` at most once per host.

### #13 — `--resume` flag exists but does nothing 🔎
**Where:** `cli.py` (`--resume` parsed into `cfg.resume`), `util.load_state/save_state`
(defined, never called).
**What:** The resume plumbing (`state_*.json`, `load_state`, `save_state`) is written
but nothing reads or writes state, and no phase checks `cfg.resume`. So `--resume` is a
no-op and a long scan can't be continued. Verified: no call sites.
**Fix:** Persist recon (parsed `HostResult`) and enum results to state after each phase;
on `--resume`, load and skip completed phases. The dataclasses are `asdict`-able
already, so serialization is straightforward.

### #14 — gentle/HTB profile still runs `whatweb`, `nikto`, `gobuster`, sqlmap-sweep 🔎
**Where:** `enumerate._enum_http`, `exploit._web_candidates`, gate in `auto_exploit`.
**What:** The HTB "gentle" profile disables auto-exploit and UDP/NSE, but enumeration
still launches `nikto` (very noisy) and `gobuster`, and `_web_candidates` still emits a
sqlmap-crawl candidate. On HTB, only auto-exploit is blocked — the *enumeration* noise
isn't profile-aware. `nikto` against shared infra is exactly the kind of automated
noise HTB discourages.
**Fix:** Make enumeration intensity profile-driven: under gentle, skip nikto, lower
gobuster threads/wordlist, skip the param-crawl-driven active web stage. Tie each
enum tool to a `profile` capability flag.

---

## S3 — Robustness

### #15 — Malformed/truncated nmap XML crashes the whole run ✅
**Where:** `recon.scan` → `parse_nmap_xml` (unguarded `ET.parse`).
**What:** If nmap is Ctrl-C'd or times out mid-write, the XML file exists but is
truncated; `ET.parse` raises an uncaught `ParseError` and the process dies (verified
with garbage input → `ParseError`). `scan()` checks `os.path.exists` but not validity.
**Fix:** Wrap `parse_nmap_xml` in try/except (`ParseError`, `OSError`); on failure warn
and return an empty `HostResult` so the run degrades instead of crashing. Consider also
parsing nmap's `-oG`/stdout as a fallback.

### #16 — `parse_nmap_xml` only reads the first `<host>`; multi-host/CIDR loses the rest ✅
**Where:** `recon.parse_nmap_xml` (`root.find("host")`).
**What:** `find` returns the first host element only. A CIDR scan (a stated TODO:
"multi-host CIDR sweep") would silently report just one host. Verified.
**Fix:** Iterate `root.findall("host")` and return a list of `HostResult`. This is a
prerequisite for the CIDR-sweep feature (#22).

### #17 — Per-tool timeouts can exceed the runner timeout; no global budget 🔎
**Where:** `util.run` (per-call `timeout`), various callers.
**What:** Several calls pass `timeout` up to 1800s (NSE, full TCP). With concurrent
enum workers each able to block for minutes, a single target can run for a very long
time with no overall cap and no progress heartbeat for long scans.
**Fix:** Add a global wall-clock budget per target and per phase; emit periodic
"still running (Ns)" heartbeats for long calls; make timeouts profile-scaled.

### #18 — `_have()` warns once per call site, not once per tool → repeated identical warnings 🔎
**Where:** `enumerate._have`.
**What:** For every HTTP service (80/443/8080/…) the same "X not installed" warning
prints again. On a host with several web ports this is noisy.
**Fix:** Track already-warned tools in a set (on `cfg` or module-level) and warn once.

### #19 — Concurrency + shared stdout: interleaved/garbled log lines 🔎
**Where:** `util.parallel_map` + all the `info/good/warn` prints from worker threads.
**What:** Handlers run on a thread pool and all write to stdout via `print`; lines from
different services interleave. Cosmetic but hurts readability of a live run.
**Fix:** Use the `logging` module with a thread-safe handler, or funnel worker output
through a queue and print from the main thread. (See #25.)

---

## S4 — Capability gaps (toward full end-to-end automation)

### #20 — No real session management / proof-of-exploitation loop 💡
**What:** The exploit phase fires MSF modules and greps stdout for "session opened,"
but there's no durable handle on the resulting session, no automatic
`getuid`/`sysinfo`/`hostname`/flag-grab, and post-exploit can't reliably reach those
sessions (#9). For "automate the entire process," the win condition should be: open
session → confirm identity → collect proof (id, uname, user.txt/root.txt on HTB) →
feed privesc enum.
**Fix:** Drive everything through a single persistent `msfrpcd` client for the whole
run: load modules, run, enumerate `client.sessions`, and for each session run a small
fixed recipe (`id`, `uname -a`, `hostname`, look for `user.txt`/`root.txt`,
`sudo -n -l`). Capture into the report as evidence. This unifies exploit + post-exploit
and fixes the async-read problem.

### #21 — No privesc *automation*, only enumeration staging 💡
**What:** Post-exploit runs linpeas and dumps text. It doesn't parse linpeas/LinEnum
output for actionable wins (writable `/etc/passwd`, SUID `nmap`/`find`/`vim`, sudo
NOPASSWD, cron, kernel-exploit candidates) nor attempt the easy ones.
**Fix:** Parse PEAS output into structured findings; map known patterns to GTFOBins
suggestions; optionally auto-attempt the safe, deterministic ones (e.g. SUID GTFOBins
one-liners) under an explicit flag. Run `linux-exploit-suggester` and surface ranked
kernel candidates.

### #22 — No multi-host / CIDR sweep (stated TODO) 💡
**What:** Single-target only. The notes list "multi-host CIDR sweep" as next.
**Fix:** Accept CIDR/host-file input, do a fast host-discovery pass, then fan out the
full pipeline per live host with bounded global concurrency. Depends on #16. Report an
index + per-host reports.

### #23 — Thin web coverage for modern targets (HTB has moved past Metasploitable-era) 💡
**What:** Web exploitation is sqlmap + LFI + CMS + `.git`. Missing the bread-and-butter
of current HTB/lab web: directory brute with extensions and recursion (feroxbuster),
parameter discovery (arjun/ffuf), default creds on admin panels, SSTI probing, basic
auth-bypass checks, API/Swagger discovery, upload-to-RCE patterns, and known-CVE
exploitation beyond CMS (e.g. exposed Jenkins/Tomcat/Spring).
**Fix:** Add handlers incrementally; prioritize feroxbuster recursion, arjun param
discovery feeding the existing sqlmap/LFI stages, and a small SSTI/`{{7*7}}` probe.
Make searchsploit results version-matched (#24) so service CVEs drive exploit attempts,
not just web.

### #24 — `searchsploit` results aren't version-matched or actioned ✅
**Where:** `exploit._searchsploit_candidates`.
**What:** It queries the raw banner string and dumps up to 20 titles as a `MANUAL`
candidate with `safe=False`. There's no version comparison, no ranking, and no path
from a strong match (e.g. "vsftpd 2.3.4") to an actual exploit attempt — the curated
signatures cover a handful by hand, but everything else is just a list. Verified the
candidate is informational only.
**Fix:** Normalize product+version, filter searchsploit hits to version-applicable
ones, rank, and where a Metasploit module exists for the CVE, auto-promote it into the
gated exploit flow (lab-only). At minimum, `searchsploit -m` the top match into loot.

### #25 — No structured run log / NDJSON event stream for automation 💡
**What:** Output is colored stdout + a final MD/JSON. For chaining ctfauto into larger
automation (or re-analysis), a machine-readable event log written incrementally is more
useful than only an end-of-run JSON.
**Fix:** Emit NDJSON events (phase start/stop, finding, candidate, exploit result) to
`events.ndjson` as they happen. Pairs well with #13 (resume) and #19 (logging).

### #26 — No requirements/setup/toolchain check (stated TODO) 💡
**What:** `detect_tools()` reports missing tools but there's no `setup.sh` /
`requirements.txt` / `--check` that tells you what to `apt install`, nor a
`pip install pymetasploit3` reminder wired to the post-exploit path.
**Fix:** Add `requirements.txt` (pymetasploit3), a `setup.sh` that apt-installs the CLI
toolchain on Kali, and a `--check`/`--doctor` mode that prints a tool matrix and the
exact install commands for whatever's missing. Wire wordlist/seclists path detection
here too (#27).

### #27 — Hardcoded wordlist/seclists paths with no detection ✅ RESOLVED
**Where:** `enumerate._enum_http`, `_brute_candidates`, `_run_brute`, `_probe_lfi`.
**What:** Wordlist paths were hardcoded; the vhost path in particular had no fallback
and silently skipped when SecLists wasn't at that exact location (and the apt vs
pip/git capitalisation differs: `/usr/share/seclists` vs `/usr/share/SecLists`).
**Fixed:** New `ctfauto/wordlists.py` resolves the SecLists root across all common
install locations + `$CTFAUTO_SECLISTS` + `--seclists-dir`, with named getters
(directory, files, vhost, LFI, params, usernames, passwords) that try SecLists first
and fall back to dirb/rockyou/metasploit lists. All consumers route through it; the
LFI stage now augments its built-in payloads from the SecLists LFI list (capped at
60). `--check` shows the resolved root + each wordlist. Covered by `TestWordlists`.

---

## S4 — Capability (cloud)

### #32 — Cloud recon: unauthenticated public-misconfiguration discovery ✅ ADDED
**What:** ctfauto was host-only (IP + ports). Added a cloud phase
(`ctfauto/modules/cloud.py`) for the cloud equivalent of recon — finding
**publicly-exposed** storage a target has left open.
**Scope (deliberately narrow):** probes only resources reachable to anonymous
requests; never private resources, IAM, or credentials. AWS S3 (exists / listable /
readable / writable) and Azure Blob (account + anonymous container listing).
Candidate names generated from a seed keyword OR domain (`--cloud-name`), plus
bucket names harvested from the web-enum crawl. Uses `aws --no-sign-request` when
present, anonymous-HTTP fallback otherwise.
**Safety:** requires `--allow-cloud` (its own authorization gate, since cloud
targets are public provider infra). Read-only by default; the world-writable test
is gated behind `--aggressive`, writes one innocuous marker, and prints the delete
command. Candidate cap (200) + rate-limited. Findings surface in the report with
severity, behind a cloud-exposure banner. NOT authenticated cloud testing — that's
a deliberate non-goal. Covered by `TestCloud` (13 offline, mocked tests).
**Future (out of scope here):** an authenticated mode (supply a key → enumerate
access / privesc / loot) would be a separate module with a credential-handling +
authorization model; not built.

---

## S5 — Packaging & polish

### #28 — No tests at all 💡
**What:** Zero test files. The bugs above (gate logic, XML parse, dedupe, precedence)
are exactly what a small unit suite would have caught.
**Fix:** Add `tests/` with: classification table tests, gate-decision tests
(matrix of flags × class → what runs), `parse_nmap_xml` fixtures (valid, malformed,
multi-host), and dedupe tests. Pure-stdlib `unittest` keeps the no-dependency promise.

### #29 — No packaging metadata 🔎
**Where:** repo root (no `pyproject.toml`/`setup.py`, no `requirements.txt`).
**What:** Runs via `python run.py` only; not installable as `ctfauto` despite `cli:main`
being structured for an entry point.
**Fix:** Add `pyproject.toml` with a console-script entry point (`ctfauto = ctfauto.cli:main`)
and an optional extra for pymetasploit3.

### #30 — `__version__` import will crash; `__init__.py` is effectively empty ✅
**Where:** `cli.py` imports `from . import __version__`; `ctfauto/__init__.py` is 2
lines.
**What:** `cli.py` and `--version` reference `__version__`, and the report/run banners
print `ctfauto 0.1.0`, so `__init__.py` must define it. It currently shows as a 2-line
file — confirm `__version__ = "0.1.0"` is actually there (the banner printed `0.1.0` in
testing, so it likely is, but it's the kind of thing that breaks on refactor).
**Fix:** Pin `__version__` in one place and have packaging read from it.

### #31 — Secrets/loot hygiene 💡
**What:** `.git` dumps, sqlmap output, and SNMP/SMB findings can contain credentials and
PII and are written under `loot/`. `.gitignore` covers them, but there's no redaction in
the report and no warning that loot may contain secrets.
**Fix:** Note in the report header that loot may contain sensitive data; optionally
redact obvious secrets (passwords, keys) in the *Markdown* report while keeping raw data
in the gitignored JSON/loot.

---

## Suggested order of work

1. **Safety first (S1):** #1, #2, #3 — stop the tool from hitting public IPs with the lab
   profile, and fix HTB classification. These are the only items that change *whether the
   tool can do something it shouldn't*.
2. **Fix the lies (S2):** #6, #7, #8, #12, #13 — features the docs claim that don't work.
3. **Stop the crashes (S3):** #15, #16 — XML robustness + multi-host parse.
4. **Then build capability (S4):** #20 → #21 (the session/privesc spine), then #22–#27.
5. **Harden (S5):** #28 tests alongside each fix.
