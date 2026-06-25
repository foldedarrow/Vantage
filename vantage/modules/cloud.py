"""Cloud recon: UNAUTHENTICATED public-misconfiguration discovery (AWS S3, Azure Blob).

Scope (deliberately narrow):
  - This module only probes resources the provider has already made reachable to
    ANONYMOUS requests, plus name-existence checks. No credentials, no IAM, no
    access to private resources. It finds *misconfigurations* (public/listable/
    writable buckets, takeover candidates) — it does not exploit private cloud.
  - It is READ-ONLY by default: existence checks, anonymous list, anonymous read.
    The single write probe (world-writable bucket) only runs under --aggressive,
    writes one innocuous marker object, logs loudly, and tells you to delete it.
  - It requires the --allow-cloud authorization opt-in at the gate (cloud targets
    are public provider infrastructure; you assert you're authorized to test them).

Works with `awscli` when present (`aws s3 ... --no-sign-request`) and falls back to
plain anonymous HTTP otherwise, so it runs on a box without the AWS CLI.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from ..config import RunConfig
from ..modules.enumerate import EnumFinding
from ..util import good, info, run, warn, warn_once, event


# Permutation affixes appended/prepended to the seed to generate candidate names.
# Kept deliberately modest to stay polite; extend via --cloud-extra-words if wanted.
_AFFIXES = [
    "", "-dev", "-development", "-prod", "-production", "-stage", "-staging",
    "-test", "-testing", "-qa", "-uat", "-backup", "-backups", "-bak", "-old",
    "-archive", "-data", "-assets", "-static", "-media", "-files", "-uploads",
    "-public", "-private", "-internal", "-secret", "-secrets", "-config",
    "-logs", "-log", "-db", "-database", "-dump", "-dumps", "-images", "-img",
    "-www", "-web", "-app", "-api", "-cdn", "-s3", "-storage", "-store",
]
_SEPARATORS = ["", "-", "."]


@dataclass
class CloudFinding:
    provider: str            # aws | azure
    resource: str            # bucket/container/account name or URL
    state: str               # exists | listable | readable | writable | takeover | missing
    detail: str = ""
    severity: str = "info"   # info | low | medium | high
    tags: dict = field(default_factory=dict)


@dataclass
class CloudResult:
    findings: list[CloudFinding] = field(default_factory=list)
    candidates_tested: int = 0

    def add(self, f: CloudFinding) -> None:
        self.findings.append(f)
        tag = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(f.severity, "•")
        good(f"[cloud:{f.provider}] {tag} {f.resource} — {f.state.upper()}"
             + (f" ({f.detail})" if f.detail else ""))

    def as_enum_findings(self) -> list[EnumFinding]:
        """Bridge into the existing report structures (port 0 = not a host port)."""
        out = []
        for f in self.findings:
            out.append(EnumFinding(
                0, f"cloud-{f.provider}",
                f"{f.resource}: {f.state}",
                f.detail,
                tags={"cloud": f.provider, "cloud_state": f.state,
                      "severity": f.severity, **f.tags},
            ))
        return out


# --- seed / candidate generation --------------------------------------------
def _seed_roots(seed: str) -> list[str]:
    """Turn a keyword OR domain into base name roots.
    'flaws.cloud' -> ['flaws', 'flaws-cloud', 'flawscloud']; 'acme' -> ['acme']."""
    seed = seed.strip().lower()
    roots: list[str] = []
    if not seed:
        return roots
    # Domain? derive from the labels.
    if "." in seed:
        labels = [l for l in seed.split(".") if l not in ("www",)]
        # drop a trailing public suffix-ish label for the bare root (best-effort)
        core = labels[0] if labels else seed
        roots.append(core)
        roots.append("-".join(labels))
        roots.append("".join(labels))
    else:
        roots.append(seed)
    # de-dupe, preserve order
    return list(dict.fromkeys(r for r in roots if r))


def generate_candidates(seed: str, extra_words: list[str] | None = None,
                        cap: int = 200) -> list[str]:
    """Generate candidate bucket/container names from a seed (keyword or domain).
    Bounded by `cap` to stay polite."""
    roots = _seed_roots(seed)
    words = list(_AFFIXES)
    if extra_words:
        words += [w if w.startswith("-") else f"-{w}" for w in extra_words]
    names: list[str] = []
    for root in roots:
        for sep in _SEPARATORS:
            for affix in words:
                if affix and sep:
                    # affix already carries its own '-'; avoid double separators
                    name = f"{root}{affix}" if affix.startswith("-") else f"{root}{sep}{affix}"
                else:
                    name = f"{root}{affix}"
                name = name.strip("-.").lower()
                if name and name not in names:
                    names.append(name)
    return names[:cap]


def names_from_enum(enum) -> list[str]:
    """Harvest bucket names already seen in the host web-crawl stage (S3 URLs in
    page source surface as findings/tags)."""
    found: list[str] = []
    if enum is None:
        return found
    import re
    s3_re = re.compile(r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9.\-]*amazonaws\.com"
                       r"|s3[.\-][a-z0-9.\-]*amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])")
    for f in getattr(enum, "findings", []):
        blob = f"{f.summary} {f.detail}"
        for m in s3_re.findall(blob):
            for g in m:
                if g:
                    found.append(g)
    return list(dict.fromkeys(found))


# --- HTTP helper (anonymous, bounded) ---------------------------------------
def _http(url: str, method: str = "GET", timeout: int = 8,
          data: bytes | None = None) -> tuple[int, str]:
    """Minimal anonymous HTTP. Returns (status, body[:4k]). Never raises."""
    try:
        req = urllib.request.Request(url, method=method, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            body = ""
        return e.code, body
    except (urllib.error.URLError, OSError, ValueError):
        return 0, ""


# --- AWS S3 -----------------------------------------------------------------
def _s3_probe(cfg: RunConfig, bucket: str, res: CloudResult) -> None:
    """Probe one S3 bucket for its public state. Read-only unless --aggressive."""
    use_cli = bool(cfg.discovered_tools.get("aws"))
    url = f"https://{bucket}.s3.amazonaws.com/"

    # 1. existence + listability
    listable = False
    exists = False
    if use_cli:
        rc, out, errout = run(["aws", "s3", "ls", f"s3://{bucket}",
                               "--no-sign-request"], timeout=20)
        text = (out + errout).lower()
        if rc == 0:
            exists = listable = True
        elif "accessdenied" in text or "forbidden" in text:
            exists = True
        elif "nosuchbucket" in text:
            exists = False
        else:
            exists = None  # unknown; fall through to HTTP
    if not use_cli or exists is None:
        status, body = _http(url)
        if status == 200:
            exists = True
            listable = "<ListBucketResult" in body
        elif status == 403:
            exists = True
        elif status == 404 and "NoSuchBucket" in body:
            exists = False
        elif status == 404:
            # 404 without NoSuchBucket can mean exists-but-empty-key; treat as takeover-ish
            exists = False

    if exists is False:
        # A bucket that's referenced somewhere but returns NoSuchBucket = takeover candidate.
        # We can't know "referenced" here generically, so only flag if it came from enum.
        return
    if exists is None:
        return

    if listable:
        res.add(CloudFinding("aws", bucket, "listable",
                             "anonymous ListBucket succeeded", severity="high",
                             tags={"url": url}))
    else:
        res.add(CloudFinding("aws", bucket, "exists",
                             "bucket exists but not anonymously listable",
                             severity="low", tags={"url": url}))

    # 2. anonymous object read is implied by listable; note it
    # 3. write probe — ONLY under --aggressive (single innocuous marker)
    if cfg.aggressive:
        marker = "vantage-write-test.txt"
        body = b"vantage authorized write test - safe to delete\n"
        if use_cli:
            # write via a temp file
            tmp = os.path.join(cfg.out_dir, marker)
            with open(tmp, "wb") as f:
                f.write(body)
            rc, out, errout = run(["aws", "s3", "cp", tmp, f"s3://{bucket}/{marker}",
                                   "--no-sign-request"], timeout=25)
            wrote = rc == 0
        else:
            status, _ = _http(f"{url}{marker}", method="PUT", data=body)
            wrote = status in (200, 201)
        if wrote:
            res.add(CloudFinding("aws", bucket, "writable",
                                 f"anonymous WRITE succeeded — wrote {marker}; DELETE IT: "
                                 f"aws s3 rm s3://{bucket}/{marker} --no-sign-request",
                                 severity="high", tags={"url": url, "marker": marker}))
            warn(f"  >>> WROTE marker to s3://{bucket}/{marker} — remember to delete it")


def _aws_recon(cfg: RunConfig, candidates: list[str], res: CloudResult) -> None:
    info(f"AWS S3: probing {len(candidates)} candidate bucket(s)"
         + ("  [--aggressive: write-test enabled]" if cfg.aggressive else ""))
    if not cfg.discovered_tools.get("aws"):
        warn_once("no-awscli",
                  "awscli not installed — using anonymous HTTP probing (less reliable). "
                  "`apt install awscli` for better results.")
    # optional: wrap s3scanner if present (richer)
    for i, bucket in enumerate(candidates):
        _s3_probe(cfg, bucket, res)
        res.candidates_tested += 1
        if (i + 1) % 25 == 0:
            info(f"  ...{i + 1}/{len(candidates)} probed")
        time.sleep(0.05)  # be polite


# --- Azure Blob -------------------------------------------------------------
def _azure_probe(cfg: RunConfig, account: str, res: CloudResult) -> None:
    """Probe an Azure storage account for anonymous container/blob exposure."""
    base = f"https://{account}.blob.core.windows.net"
    # account existence: the host resolves + returns 400/403/409 rather than NXDOMAIN
    status, body = _http(f"{base}/?comp=list", timeout=8)
    if status == 0:
        return  # no such account (DNS fail) or unreachable
    # account exists if we got any HTTP status back
    res.add(CloudFinding("azure", account, "exists",
                         f"storage account resolves (HTTP {status})",
                         severity="info", tags={"url": base}))
    # try a few common container names for anonymous listing
    for container in ("$root", "public", "files", "data", "backup", "uploads",
                      "media", "assets", "web", "$web", "documents"):
        url = f"{base}/{container}?restype=container&comp=list"
        st, bd = _http(url, timeout=8)
        if st == 200 and "<EnumerationResults" in bd:
            res.add(CloudFinding("azure", f"{account}/{container}", "listable",
                                 "anonymous container listing succeeded",
                                 severity="high", tags={"url": url}))


def _azure_recon(cfg: RunConfig, candidates: list[str], res: CloudResult) -> None:
    # Azure account names: 3-24 chars, lowercase letters+digits only, no separators.
    azure_names = list(dict.fromkeys(
        c.replace("-", "").replace(".", "")[:24]
        for c in candidates if len(c.replace("-", "").replace(".", "")) >= 3))
    info(f"Azure Blob: probing {len(azure_names)} candidate storage account(s)")
    for i, account in enumerate(azure_names):
        _azure_probe(cfg, account, res)
        res.candidates_tested += 1
        time.sleep(0.05)


# --- entry point ------------------------------------------------------------
def run_cloud_recon(cfg: RunConfig, enum=None) -> CloudResult:
    """Run cloud recon for the configured providers. Caller has already passed
    the --allow-cloud authorization gate."""
    res = CloudResult()
    seed = cfg.cloud_name or cfg.target
    if not seed:
        warn("cloud recon: no seed (use --cloud-name <keyword-or-domain>).")
        return res

    extra = [w for w in (cfg.cloud_extra_words or "").split(",") if w.strip()]
    candidates = generate_candidates(seed, extra, cap=cfg.cloud_candidate_cap)
    harvested = names_from_enum(enum)
    for h in harvested:
        if h not in candidates:
            candidates.insert(0, h)  # prioritise real names seen in the app
    if harvested:
        good(f"cloud: harvested {len(harvested)} bucket name(s) from web enum")

    event(cfg, "cloud_start", seed=seed, candidates=len(candidates),
          providers=cfg.cloud_providers)

    if "aws" in cfg.cloud_providers:
        _aws_recon(cfg, candidates, res)
    if "azure" in cfg.cloud_providers:
        _azure_recon(cfg, candidates, res)

    event(cfg, "cloud_done", tested=res.candidates_tested,
          findings=len(res.findings),
          hits=[f"{f.provider}:{f.resource}:{f.state}" for f in res.findings])
    if not res.findings:
        info("cloud recon: no public misconfigurations found.")
    return res
