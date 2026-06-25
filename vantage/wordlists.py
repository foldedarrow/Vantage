"""Wordlist resolution, with first-class SecLists support.

SecLists ships an enormous, well-curated set of wordlists, but where it lives
depends on how it was installed:
  - apt (Kali `seclists` package):   /usr/share/seclists
  - pip / git clone:                 /usr/share/SecLists, /opt/SecLists, ~/SecLists
  - custom:                          $VANTAGE_SECLISTS or --seclists-dir

This module finds the SecLists root ONCE (cached), then exposes named getters
for the wordlists vantage actually uses. Every getter tries the SecLists-relative
path first and falls back to a non-SecLists equivalent, so the tool still works
on a box without SecLists — it just uses smaller lists.

Resolution precedence for the SecLists root:
  1. explicit override (cfg.seclists_dir / --seclists-dir)
  2. $VANTAGE_SECLISTS
  3. the first known install location that exists on disk
"""
from __future__ import annotations

import os

from .util import warn_once, info

# Known SecLists roots, in preference order. Case matters on Linux, and apt vs
# pip/git disagree on capitalisation, so both spellings are listed.
_SECLISTS_ROOTS = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/opt/seclists",
    "/opt/SecLists",
    os.path.expanduser("~/seclists"),
    os.path.expanduser("~/SecLists"),
    os.path.expanduser("~/.local/share/seclists"),
]

# Cache: resolved once per process. "" means "looked, found nothing".
_seclists_root_cache: str | None = None


def _seclists_root(cfg=None) -> str:
    """Return the SecLists root dir, or '' if not found. Cached after first call.
    An explicit override on cfg (seclists_dir) is checked first and is NOT cached
    so that different configs in-process behave correctly (tests)."""
    # 1. explicit override always wins and bypasses the cache
    override = getattr(cfg, "seclists_dir", "") if cfg is not None else ""
    if override:
        if os.path.isdir(override):
            return override
        warn_once("bad-seclists-override",
                  f"--seclists-dir {override} is not a directory; ignoring it.")

    global _seclists_root_cache
    if _seclists_root_cache is not None:
        return _seclists_root_cache

    # 2. environment variable (new name, with legacy ctfauto fallback)
    env = os.environ.get("VANTAGE_SECLISTS", "") or os.environ.get("CTFAUTO_SECLISTS", "")
    if env and os.path.isdir(env):
        _seclists_root_cache = env
        info(f"SecLists: using $VANTAGE_SECLISTS -> {env}")
        return env

    # 3. known locations
    for root in _SECLISTS_ROOTS:
        if os.path.isdir(root):
            _seclists_root_cache = root
            return root

    _seclists_root_cache = ""
    return ""


def seclists_available(cfg=None) -> str:
    """Public: the SecLists root if present, else ''."""
    return _seclists_root(cfg)


def _first_existing(paths: list[str]) -> str:
    for p in paths:
        if p and os.path.exists(p):
            return p
    return ""


def _sl(cfg, *relparts: str) -> str:
    """Build a SecLists-relative path if the root exists, else ''."""
    root = _seclists_root(cfg)
    if not root:
        return ""
    return os.path.join(root, *relparts)


# --- Named wordlist getters --------------------------------------------------
# Each returns a usable absolute path, or '' if nothing suitable is on disk.
# `override` (a --wordlist-* value) is honoured first when provided.

def directory_wordlist(cfg, override: str = "") -> str:
    """Wordlist for directory/content brute-forcing."""
    if override and os.path.exists(override):
        return override
    if override:
        warn_once("bad-dir-wordlist",
                  f"directory wordlist {override} not found; trying SecLists/defaults.")
    return _first_existing([
        _sl(cfg, "Discovery", "Web-Content", "raft-medium-directories.txt"),
        _sl(cfg, "Discovery", "Web-Content", "directory-list-2.3-medium.txt"),
        _sl(cfg, "Discovery", "Web-Content", "common.txt"),
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirb/big.txt",
    ])


def files_wordlist(cfg, override: str = "") -> str:
    """Wordlist for FILE discovery (raft files list) — richer than dirs-only."""
    if override and os.path.exists(override):
        return override
    return _first_existing([
        _sl(cfg, "Discovery", "Web-Content", "raft-medium-files.txt"),
        _sl(cfg, "Discovery", "Web-Content", "raft-small-files.txt"),
        directory_wordlist(cfg),  # fall back to the directory list
    ])


def vhost_wordlist(cfg, override: str = "") -> str:
    """Subdomain/vhost wordlist for ffuf Host-header fuzzing."""
    if override and os.path.exists(override):
        return override
    return _first_existing([
        _sl(cfg, "Discovery", "DNS", "subdomains-top1million-5000.txt"),
        _sl(cfg, "Discovery", "DNS", "subdomains-top1million-20000.txt"),
        _sl(cfg, "Discovery", "DNS", "namelist.txt"),
        "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    ])


def lfi_wordlist(cfg, override: str = "") -> str:
    """LFI / path-traversal payload list to augment the built-in payloads."""
    if override and os.path.exists(override):
        return override
    return _first_existing([
        _sl(cfg, "Fuzzing", "LFI", "LFI-Jhaddix.txt"),
        _sl(cfg, "Fuzzing", "LFI", "LFI-gracefulsecurity-linux.txt"),
        _sl(cfg, "Fuzzing", "LFI", "LFI-LFISuite-pathtotest-huge.txt"),
    ])


def param_wordlist(cfg, override: str = "") -> str:
    """Common HTTP parameter names (feeds arjun / manual param fuzzing)."""
    if override and os.path.exists(override):
        return override
    return _first_existing([
        _sl(cfg, "Discovery", "Web-Content", "burp-parameter-names.txt"),
        _sl(cfg, "Miscellaneous", "web", "http-request-params.txt"),
    ])


def username_wordlist(cfg, override: str = "") -> str:
    """Usernames for hydra brute-force."""
    if override and os.path.exists(override):
        return override
    if override:
        warn_once("bad-user-wordlist",
                  f"users wordlist {override} not found; trying SecLists/defaults.")
    return _first_existing([
        _sl(cfg, "Usernames", "top-usernames-shortlist.txt"),
        _sl(cfg, "Usernames", "Names", "names.txt"),
        "/usr/share/wordlists/metasploit/unix_users.txt",
    ])


def password_wordlist(cfg, override: str = "") -> str:
    """Passwords for hydra brute-force. rockyou first (most useful), then SecLists."""
    if override and os.path.exists(override):
        return override
    if override:
        warn_once("bad-pass-wordlist",
                  f"password wordlist {override} not found; trying SecLists/defaults.")
    return _first_existing([
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",  # apt ships it gzipped; user unzips
        _sl(cfg, "Passwords", "Leaked-Databases", "rockyou.txt"),
        _sl(cfg, "Passwords", "Common-Credentials", "10-million-password-list-top-1000000.txt"),
        _sl(cfg, "Passwords", "Common-Credentials", "10k-most-common.txt"),
    ])


def summary(cfg) -> dict:
    """For the --check doctor: resolved paths (or '' if missing)."""
    return {
        "seclists_root": _seclists_root(cfg) or "(not found)",
        "directory": directory_wordlist(cfg) or "(none)",
        "files": files_wordlist(cfg) or "(none)",
        "vhost": vhost_wordlist(cfg) or "(none)",
        "lfi": lfi_wordlist(cfg) or "(none)",
        "params": param_wordlist(cfg) or "(none)",
        "usernames": username_wordlist(cfg) or "(none)",
        "passwords": password_wordlist(cfg) or "(none)",
    }
