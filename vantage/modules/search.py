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
from ..modules.exploit import ExploitResult, _parse_version
from ..util import info, good, warn, warn_once, budget_remaining

# A real browser UA — DuckDuckGo and many sites 403 the default urllib UA.
_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
_DDG_HTML = "https://html.duckduckgo.com/html/"
_CIRCL_CVE = "https://cve.circl.lu/api/cve/"
_POLITE_DELAY = 1.0          # min seconds between outbound queries (be a good citizen)
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


_RES_A = re.compile(r'<a[^>]+class="result__a"[^>]+href="(.*?)".*?>(.*?)</a>', re.S)
_RES_SNIP = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.S)


def _parse_ddg_html(html: str, max_results: int) -> list[SearchHit]:
    titles = _RES_A.findall(html)
    snips = _RES_SNIP.findall(html)
    hits: list[SearchHit] = []
    for i, (href, title) in enumerate(titles[:max_results]):
        snippet = _strip_tags(snips[i]) if i < len(snips) else ""
        hits.append(SearchHit(_strip_tags(title), _decode_ddg_href(href), snippet))
    return hits


# --- public search primitives ------------------------------------------------
def web_search(query: str, max_results: int = 5, timeout: int = 15) -> list[SearchHit]:
    """DuckDuckGo HTML search. No API key. Returns [] on any failure."""
    _throttle()
    info(f"search: {query}")
    body = urllib.parse.urlencode({"q": query}).encode()
    html = _http(_DDG_HTML, data=body, timeout=timeout)
    return _parse_ddg_html(html, max_results) if html else []


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
def _product(banner: str) -> str:
    """Pull the product name from a service banner, dropping the version tail and
    parentheticals. 'Apache httpd 2.2.8 ((Ubuntu))' -> 'Apache httpd'."""
    b = banner.strip()
    if not b:
        return ""
    m = re.search(r"\d+\.\d+", b)
    head = (b[:m.start()] if m else b).split("(")[0].strip()
    return head[:60]


# --- report enrichment -------------------------------------------------------
def enrich_report(cfg: RunConfig, host: HostResult, exploits: ExploitResult) -> str:
    """Build a Markdown 'Web intel' block: CVE summaries for NSE-flagged CVEs and
    exploit references for fingerprinted software. Bounded by cfg.search_cap total
    queries (politeness + the global time budget). Returns "" if nothing useful or
    if the network is unavailable."""
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
        prod = _product(s.banner)
        if not prod:
            continue
        ver = _parse_version(s.banner)
        query = (prod + " " + ver).strip()
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
    if refs:
        L.append("### Exploit references")
        L.extend(refs)
        L.append("")

    if not L:
        info("web intel: nothing to enrich (no CVEs or fingerprinted versions).")
        return ""
    good(f"web intel gathered ({used} quer{'y' if used == 1 else 'ies'}).")
    return "\n".join(L)
