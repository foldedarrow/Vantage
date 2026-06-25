# vantage web dashboard

A Flask **control panel + viewer** over vantage. It launches scans, shows them
running live, and renders the artifacts each run produces:

- **New scan** — a form exposing the CLI options (target, profile incl. **stealth**,
  aggressive, cloud, stealth knobs, scope file, authorization). Starts a real
  `run.py` and drops you on the live view.
- **Live scans** — what's running right now, the **current command**, and a
  streaming activity log; with a **stop** button. Killed/stalled runs are detected
  and shown separately, not as live.
- **Targets overview** — one card per `report_<target>.json`: classification,
  profile, counts, and the top **priority leads**.
- **Report view** — the Markdown report as HTML, the ranked priority leads, and the
  run's **event timeline**.
- **CIDR sweeps** — renders each `index_<range>.md` and links per-host reports.

The core scanner stays stdlib-only; Flask/Markdown are needed *only* for this
optional dashboard.

## Run

On Kali (PEP 668 blocks system pip), install via apt:

```bash
sudo apt install -y python3-flask python3-markdown
python3 webui/app.py                       # serves ./loot on http://127.0.0.1:5000
```

Or a venv anywhere:

```bash
python3 -m venv webui/.venv
webui/.venv/bin/pip install -r webui/requirements.txt
webui/.venv/bin/python webui/app.py --loot /path/to/loot
```

Flags: `--loot <dir>` (or `$VANTAGE_LOOT`, default `./loot`), `--host <addr>`
(default `127.0.0.1`), `--port <n>` (default `5000`), `--debug`.

**Run it with `sudo`** if you want full scan capability — nmap needs root for SYN
scans, OS detection, and stealth fragmentation. Unprivileged, scans still run but
fall back to a connect scan (the form warns you and offers `--connect`).

## Security model

Launching scans means this is no longer a passive viewer — it fires real network
traffic. The guardrails:

- **Scans can only be launched from localhost.** `/scan` and the stop endpoint
  check the client address and return 403 otherwise — so even if you bind to
  `0.0.0.0`, a remote browser cannot start or stop scans.
- **It drives the real CLI.** The form is converted to a `run.py` **argv** (never a
  shell string — no command injection) and the tool's own **authorization gate,
  scope file, and external-target refusal still apply**. The "I'm authorized"
  checkbox maps to `--yes`; an external/public target additionally needs the
  explicit "authorize external" checkbox → `--allow-external`.
- **Targets are validated** (IP / hostname / CIDR only).
- **Loot may hold secrets.** Reports/dumps can contain credentials and PII (the
  Markdown report redacts; the raw JSON does not). Keep this bound to localhost.
- **No authentication.** It's a single-user local console, not a multi-user service.
  Do not expose it on a routable interface.
