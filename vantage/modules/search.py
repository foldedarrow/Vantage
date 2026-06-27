"""Web-intelligence enrichment (optional, opt-in).

This is vantage's answer to METATRON's search.py — pull public context for the
CVEs and software versions vantage already identified — but rebuilt to vantage's
rules:

  * Stdlib-only. METATRON's search.py needs `requests` + `bs4` + `ddgs`. This
    module uses only urllib/re/json/html, matching vantage's "stdlib orchestrates
    the toolchain, adds no Python deps" design.
  * Recon-only. It enriches the REPORT with public references; it never touches
    the target with the harvested intel.
  * Privacy-aware. It searches GENERIC identifiers only — CVE IDs and
    product+version strings — and refuses any query containing the target's
    IP/hostname, so turning it on never leaks who you're testing to a third party.
  * Off by default. --search enables it. It is the ONLY part of vantage that makes
    outbound requests to anything other than the target itself; every other phase
    talks only to the box you're authorized to scan.

Sources: DuckDuckGo's keyless HTML endpoint for general search, and CIRCL's
keyless CVE API (https://cve.circl.lu) for CVE summaries, with a DDG fallback.
Everything degrades to "" on any network/parse error — enrichment must never
break a run.
"""
from __future__ import annotations

import html as _html
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from ..config import RunConfig
from ..modules.recon import HostResult
from ..modules.exploit import ExploitResult
from ..util import info, good, warn, warn_once, budget_remaining

# A real browser UA — DuckDuckGo and many sites 403 the default urllib UA.
_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
# Two keyless DDG endpoints with different page layouts. We try html then lite;
# either may serve a bot-detection "anomaly" page when our IP is rate-limited, so
# web search is BEST-EFFORT (the reliable enrichment is CIRCL's by-CVE-ID API).
_DDG_HTML = "https://html.duckduckgo.com/html/"
_DDG_LITE = "https://lite.duckduckgo.com/lite/"
_CIRCL_CVE = "https://cve.circl.lu/api/cve/"
_POLITE_DELAY = 2.0          # min seconds between outbound queries (be a good citizen)
_MAX_BYTES = 2_000_000       # cap any single response we read into memory

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_last_query_t = [0.0]


@dataclass
class SearchHit:
    title: str
    url: str
    snippet: str = ""


# --- low-level HTTP (stdlib only) --------------------------------------------
def _http(url: str, data: bytes | None = None, timeout: int = 15) -> str:
    """GET/POST and return decoded text, or "" on any failure. Honours the global
    wall-clock budget like util.run() does for subprocesses."""
    rem = budget_remaining()
    if rem is not None:
        if rem <= 0:
            return ""
        timeout = min(timeout, int(rem) or 1)
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": _UA, "Accept": "text/html,application/json,*/*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(_MAX_BYTES)
            enc = r.headers.get_content_charset() or "utf-8"
            return raw.decode(enc, "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        warn_once("search-net",
                  f"web search request failed ({e}). Are you online? "
                  "(--search makes outbound requests; drop it to stay fully offline.)")
        return ""


def _throttle() -> None:
    dt = time.time() - _last_query_t[0]
    if dt < _POLITE_DELAY:
        time.sleep(_POLITE_DELAY - dt)
    _last_query_t[0] = time.time()


# --- HTML helpers (no BeautifulSoup) -----------------------------------------
def _strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s)
    return _html.unescape(s).strip()


def _decode_ddg_href(href: str) -> str:
    """DDG wraps result links as //duckduckgo.com/l/?uddg=<urlencoded>&...;
    pull the real destination back out."""
    href = _html.unescape(href)
    m = re.search(r"[?&]uddg=([^&]+)", href)
    if m:
        return urllib.parse.unquote(m.group(1))
    return ("https:" + href) if href.startswith("//") else href


# html-endpoint layout
_RES_A = re.compile(r'<a[^>]+class="result__a"[^>]+href="(.*?)".*?>(.*?)</a>', re.S)
_RES_SNIP = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S)
# lite-endpoint layout (used as a fallback; different markup)
_LITE_A = re.compile(r'<a[^>]+class="result-link"[^>]+href="(.*?)".*?>(.*?)</a>', re.S)
_LITE_SNIP = re.compile(r'class="result-snippet"[^>]*>(.*?)</td>', re.S)


def _looks_blocked(html: str) -> bool:
    """True if the page carries no results and looks like DDG's bot-detection /
    'anomaly' interstitial rather than a genuine empty result set."""
    if "result__a" in html or 'class="result-link"' in html:
        return False
    low = html.lower()
    return "anomaly" in low or "blocked" in low or len(html) < 2000


def _parse_ddg_html(html: str, max_results: int) -> list[SearchHit]:
    """Parse either endpoint's layout into SearchHits."""
    if "result__a" in html:
        titles, snips = _RES_A.findall(html), _RES_SNIP.findall(html)
    else:
        titles, snips = _LITE_A.findall(html), _LITE_SNIP.findall(html)
    hits: list[SearchHit] = []
    for i, (href, title) in enumerate(titles[:max_results]):
        snippet = _strip_tags(snips[i]) if i < len(snips) else ""
        hits.append(SearchHit(_strip_tags(title), _decode_ddg_href(href), snippet))
    return hits


# --- public search primitives ------------------------------------------------
def web_search(query: str, max_results: int = 5, timeout: int = 15) -> list[SearchHit]:
    """Keyless DuckDuckGo search (html endpoint, falling back to lite). BEST-EFFORT:
    returns [] if DDG rate-limits us (serves an anomaly page) or on any error, and
    warns once so an empty result is never silently confusing."""
    _throttle()
    info(f"search: {query}")
    body = urllib.parse.urlencode({"q": query}).encode()
    blocked_seen = False
    for endpoint in (_DDG_HTML, _DDG_LITE):
        html = _http(endpoint, data=body, timeout=timeout)
        if not html:
            continue
        if _looks_blocked(html):
            blocked_seen = True
            continue
        hits = _parse_ddg_html(html, max_results)
        if hits:
            return hits
    if blocked_seen:
        warn_once("ddg-blocked",
                  "DuckDuckGo rate-limited the web search (anomaly page) — "
                  "exploit-reference search is skipped for now. CVE-by-ID intel "
                  "(CIRCL) is unaffected. Retry later from a different network, or "
                  "drop --search.")
    return []


def fetch_page(url: str, max_chars: int = 3000, timeout: int = 15) -> str:
    """Fetch a URL and return de-tagged plain text, truncated for readability."""
    raw = _http(url, timeout=timeout)
    if not raw:
        return ""
    raw = re.sub(r"(?is)<(script|style|nav|footer|header|aside)\b.*?</\1>", " ", raw)
    text = _strip_tags(raw)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    clean = "\n".join(lines)
    if len(clean) > max_chars:
        clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"
    return clean


def _parse_cve_record(d: dict) -> tuple[str, float | None, list[str]]:
    """Extract (summary, cvss, refs) from a CVE 5.x Record Format document (the
    schema CIRCL now serves). CVSS is taken from the highest baseScore found in
    either the CNA or ADP metric blocks; the English description is preferred."""
    containers = d.get("containers") or {}
    cna = containers.get("cna") or {}
    blocks = [cna] + list(containers.get("adp") or [])

    summary = ""
    for desc in cna.get("descriptions") or []:
        if (desc.get("lang") or "").lower().startswith("en") and desc.get("value"):
            summary = desc["value"].strip()
            break

    cvss: float | None = None
    refs: list[str] = []
    for blk in blocks:
        for metric in blk.get("metrics") or []:
            for key, val in metric.items():
                if key.lower().startswith("cvssv") and isinstance(val, dict):
                    score = val.get("baseScore")
                    if isinstance(score, (int, float)):
                        cvss = max(cvss, float(score)) if cvss is not None else float(score)
        for ref in blk.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if url and url not in refs:
                refs.append(url)
    return summary, cvss, refs[:5]


def lookup_cve(cve_id: str, timeout: int = 15) -> dict:
    """CVE summary via CIRCL's keyless API (CVE 5.x format), falling back to a web
    search when the record can't be fetched. Returns {cve, summary, cvss, refs[], hits[]}."""
    cve_id = cve_id.upper()
    out = {"cve": cve_id, "summary": "", "cvss": None, "refs": [], "hits": []}
    body = _http(_CIRCL_CVE + urllib.parse.quote(cve_id), timeout=timeout)
    if body:
        try:
            out["summary"], out["cvss"], out["refs"] = _parse_cve_record(json.loads(body))
        except (ValueError, AttributeError, TypeError):
            pass
    if not out["summary"]:
        out["hits"] = web_search(f"{cve_id} vulnerability exploit", max_results=3,
                                 timeout=timeout)
    return out


# --- banner → generic search query -------------------------------------------
# A version token that keeps build suffixes (9.6p1, 1.3.3c) so we don't truncate
# mid-version. Anchored on \d+\.\d+ so a bare "protocol 2.0" tail can't win when a
# real software version (e.g. OpenSSH 9.6p1) appears earlier in the banner.
_VER_TOKEN = re.compile(r"\d+\.\d+(?:\.\d+)*(?:[a-z]+\d*)?", re.I)


def _query_from_banner(banner: str) -> str:
    """Build a generic search query 'product version' from a service banner,
    cutting at the END of the first version token and dropping parentheticals.

      'OpenSSH 9.6p1 Ubuntu ... protocol 2.0' -> 'OpenSSH 9.6p1'   (not '... 2.0')
      'nginx 1.24.0 Ubuntu'                   -> 'nginx 1.24.0'
      'Apache httpd 2.2.8 ((Ubuntu))'         -> 'Apache httpd 2.2.8'
      'Samba smbd'                            -> 'Samba smbd'       (no version)

    Taking the slice up to the first version anchors the product to the software
    that version belongs to, fixing the old split that read the SSH 'protocol 2.0'
    tail as the version."""
    b = banner.strip()
    if not b:
        return ""
    m = _VER_TOKEN.search(b)
    end = m.end() if m else len(b)
    return b[:end].split("(")[0].strip()[:60]


# --- report enrichment -------------------------------------------------------
def enrich_report(cfg: RunConfig, host: HostResult, exploits: ExploitResult,
                  enum=None) -> str:
    """Build a Markdown 'Web intel' block: CVE summaries for NSE-flagged CVEs,
    exploit references for fingerprinted software (nmap banners), and — when `enum`
    is supplied — for web applications whatweb fingerprinted (e.g. Flowise), which
    are not nmap services and were previously missed. Bounded by cfg.search_cap
    total queries (politeness + the global time budget). Returns "" if nothing
    useful or if the network is unavailable."""
    cap = getattr(cfg, "search_cap", 12) or 12
    # Never search the target's own identity — keep the engagement private.
    blocked = {x.lower() for x in (cfg.target, cfg.hostname) if x}
    used = 0
    L: list[str] = []

    # 1. CVE intelligence for every NSE-flagged CVE.
    cves = getattr(host, "nse_cves", []) or []
    if cves:
        section: list[str] = []
        for cve in cves:
            if used >= cap:
                break
            d = lookup_cve(cve)
            used += 1
            head = f"- **{cve}**" + (f" — CVSS {d['cvss']}" if d.get("cvss") else "")
            section.append(head)
            if d.get("summary"):
                section.append(f"  - {d['summary'][:400]}")
            for ref in d.get("refs", [])[:3]:
                section.append(f"  - {ref}")
            for h in d.get("hits", [])[:3]:
                section.append(f"  - [{h.title}]({h.url})")
        if section:
            L.append("### CVE intelligence")
            L.extend(section)
            L.append("")

    # 2. Exploit references for fingerprinted software (product + version only —
    #    derived from banners, never from the target's address).
    seen: set[str] = set()
    refs: list[str] = []
    for s in host.services:
        if used >= cap:
            break
        query = _query_from_banner(s.banner)
        # Require a version fingerprint — a bare service name ('http', 'Samba smbd')
        # floods the search with irrelevant noise, so skip it.
        if not query or not any(ch.isdigit() for ch in query):
            continue
        key = query.lower()
        if key in seen or any(b in key for b in blocked):
            continue
        seen.add(key)
        hits = web_search(query + " exploit", max_results=3)
        used += 1
        if not hits:
            continue
        refs.append(f"- **:{s.port}** `{query}`")
        for h in hits:
            refs.append(f"  - [{h.title}]({h.url})")

    # 2b. Web applications fingerprinted by whatweb (Flowise, Grafana, …). These
    #     aren't nmap services, so search for app-level exploits/CVEs too.
    if enum is not None:
        for f in getattr(enum, "findings", []):
            if used >= cap:
                break
            app = (f.tags or {}).get("app")
            if not app:
                continue
            ver = (f.tags or {}).get("app_version", "")
            query = (app.split(" admin")[0] + (" " + ver if ver else "")).strip()
            key = query.lower()
            if not query or key in seen or any(b in key for b in blocked):
                continue
            seen.add(key)
            hits = web_search(query + " exploit CVE", max_results=3)
            used += 1
            if not hits:
                continue
            refs.append(f"- **:{f.service_port}** `{query}` _(web app)_")
            for h in hits:
                refs.append(f"  - [{h.title}]({h.url})")

    if refs:
        L.append("### Exploit references")
        L.extend(refs)
        L.append("")

    if not L:
        info("web intel: nothing to enrich (no CVEs or fingerprinted versions).")
        return ""
    good(f"web intel gathered ({used} quer{'y' if used == 1 else 'ies'}).")
    return "\n".join(L)
