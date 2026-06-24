# ctfauto web dashboard

A small, **read-only** Flask viewer over ctfauto's `loot/` output. It runs no
scans and writes nothing — it just renders the artifacts ctfauto already produces:

- **Targets overview** — one card per `report_<target>.json`, with classification,
  profile, service/finding/candidate counts, and the top **priority leads**.
- **Report view** — the full Markdown report rendered as HTML, the ranked priority
  leads, and the run's **event timeline** (from `events_<target>.ndjson`).
- **CIDR sweeps** — renders each `index_<range>.md` and links per-host reports.

It is decoupled from the scanner: the core tool stays stdlib-only; Flask/Markdown
are needed *only* for this optional dashboard.

## Run

```bash
pip install -r webui/requirements.txt
python webui/app.py                      # serves ./loot on http://127.0.0.1:5000
# or point it at a specific loot dir:
python webui/app.py --loot /path/to/loot
CTFAUTO_LOOT=/path/to/loot python webui/app.py
```

Flags: `--loot <dir>`, `--host <addr>` (default `127.0.0.1` — localhost only),
`--port <n>` (default `5000`), `--debug`.

## Security notes

- **Bind to localhost.** The default host is `127.0.0.1`. Loot can contain
  credentials, dumps, and PII (the same data the Markdown report redacts but the
  raw JSON does not) — do not expose this on a routable interface.
- The dashboard validates every slug and refuses paths that escape the loot dir
  (no traversal), and it only ever *reads* files.
- There is no auth. It's a local triage UI, not a multi-user service.
