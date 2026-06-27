"""Tests for the optional enrichment modules (search + advise).

Network-free: only the pure parsing / query-building / summary logic is exercised
(the HTTP and Ollama calls are never made). Run: python -m unittest discover -s tests
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vantage.config import Profile, RunConfig
from vantage.modules.recon import HostResult, Service
from vantage.modules.enumerate import EnumResult
from vantage.modules.exploit import ExploitResult, ExploitCandidate
from vantage.modules import search as S
from vantage.modules import advise as A


class TestSearchParsing(unittest.TestCase):
    def test_strip_tags_and_entities(self):
        self.assertEqual(S._strip_tags("<b>Apache</b> &amp; nginx"), "Apache & nginx")

    def test_decode_ddg_redirect_href(self):
        href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fcve&rut=abc"
        self.assertEqual(S._decode_ddg_href(href), "https://example.com/cve")

    def test_decode_plain_protocol_relative_href(self):
        self.assertEqual(S._decode_ddg_href("//example.com/x"), "https://example.com/x")

    def test_parse_ddg_html(self):
        html = (
            '<a class="result__a" href="//duckduckgo.com/l/?uddg='
            'https%3A%2F%2Fexploit-db.com%2F123">vsftpd 2.3.4 Backdoor</a>'
            '<a class="result__snippet" href="x">Remote root via the '
            '<b>smiley</b> backdoor.</a>'
        )
        hits = S._parse_ddg_html(html, max_results=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].title, "vsftpd 2.3.4 Backdoor")
        self.assertEqual(hits[0].url, "https://exploit-db.com/123")
        self.assertIn("smiley backdoor", hits[0].snippet)

    def test_query_from_banner(self):
        # Cut at the END of the first version token, keep build suffixes.
        self.assertEqual(S._query_from_banner("nginx 1.24.0 Ubuntu"), "nginx 1.24.0")
        self.assertEqual(S._query_from_banner("Apache httpd 2.2.8 ((Ubuntu))"),
                         "Apache httpd 2.2.8")
        self.assertEqual(S._query_from_banner("vsftpd 2.3.4"), "vsftpd 2.3.4")
        self.assertEqual(S._query_from_banner("Samba smbd"), "Samba smbd")  # no version
        self.assertEqual(S._query_from_banner(""), "")

    def test_query_from_banner_ignores_protocol_tail(self):
        # Regression for the live HTB run: the SSH banner's 'protocol 2.0' tail must
        # NOT become the version — the real version (9.6p1) appears first.
        b = "OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 Ubuntu Linux; protocol 2.0"
        self.assertEqual(S._query_from_banner(b), "OpenSSH 9.6p1")
        self.assertNotIn("2.0", S._query_from_banner(b))

    def test_looks_blocked_detects_anomaly_page(self):
        # DDG's bot-detection page has no result anchors and mentions 'anomaly'.
        self.assertTrue(S._looks_blocked("<html>...anomaly detected...</html>"))
        self.assertFalse(S._looks_blocked('x<a class="result__a" href="u">t</a>' * 50))

    def test_parse_lite_layout(self):
        # The lite-endpoint fallback uses a different anchor class.
        html = ('<a class="result-link" href="https://example.com/x">Title X</a>'
                '<td class="result-snippet">a snippet</td>')
        hits = S._parse_ddg_html(html, 5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].url, "https://example.com/x")
        self.assertEqual(hits[0].title, "Title X")

    def test_parse_cve_5x_record(self):
        # The CVE 5.x Record Format CIRCL serves: description + CVSS live under
        # containers.cna; CVSS may instead sit in an ADP block.
        record = {"containers": {
            "cna": {
                "descriptions": [
                    {"lang": "es", "value": "ignored"},
                    {"lang": "en", "value": "Remote code execution in Foo."},
                ],
                "references": [{"url": "https://example.com/a"},
                               {"url": "https://example.com/a"}],  # dup → collapsed
            },
            "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 9.8}}],
                     "references": [{"url": "https://example.com/b"}]}],
        }}
        summary, cvss, refs = S._parse_cve_record(record)
        self.assertEqual(summary, "Remote code execution in Foo.")
        self.assertEqual(cvss, 9.8)
        self.assertEqual(refs, ["https://example.com/a", "https://example.com/b"])

    def test_parse_cve_record_handles_empty(self):
        self.assertEqual(S._parse_cve_record({}), ("", None, []))


class TestEnrichPrivacy(unittest.TestCase):
    def _cfg(self, **kw):
        return RunConfig(target="10.10.10.5", profile=Profile.lab(),
                         hostname="box.htb", **kw)

    def test_enrich_never_queries_the_target_identity(self):
        # A service whose banner literally contains the target IP/hostname must not
        # be turned into an outbound query — enabling --search must not leak who
        # you're testing. We stub web_search to capture any query it's handed.
        captured = []
        orig = S.web_search
        S.web_search = lambda q, **k: captured.append(q) or []
        try:
            host = HostResult(ip="10.10.10.5", services=[
                Service(80, "tcp", "http", product="box.htb admin", version="1.0"),
            ])
            cfg = self._cfg(search_cap=5)
            S.enrich_report(cfg, host, ExploitResult())
        finally:
            S.web_search = orig
        self.assertFalse(any("box.htb" in q.lower() or "10.10.10.5" in q
                             for q in captured), captured)

    def test_enrich_respects_query_cap(self):
        captured = []
        orig = S.web_search
        S.web_search = lambda q, **k: captured.append(q) or []
        try:
            svcs = [Service(1000 + i, "tcp", "x", product=f"prod{i}", version="1.0")
                    for i in range(10)]
            cfg = self._cfg(search_cap=3)
            S.enrich_report(cfg, HostResult(ip="10.10.10.5", services=svcs),
                            ExploitResult())
        finally:
            S.web_search = orig
        self.assertLessEqual(len(captured), 3)


class TestAdviseSummary(unittest.TestCase):
    def test_summary_includes_services_cves_and_candidates(self):
        host = HostResult(
            ip="10.10.10.5", os_guess="Linux 2.6.x",
            services=[Service(21, "tcp", "ftp", product="vsftpd", version="2.3.4")],
            nse_cves=["CVE-2011-2523"],
        )
        exp = ExploitResult()
        exp.candidates.append(ExploitCandidate(
            21, "vsftpd 2.3.4 backdoor", "root shell on 6200",
            msf_module="exploit/unix/ftp/vsftpd_234_backdoor",
            high_confidence=True, category="service"))
        cfg = RunConfig(target="10.10.10.5", profile=Profile.lab())
        summary = A._build_summary(cfg, host, EnumResult(), exp)
        self.assertIn("OPEN SERVICES", summary)
        self.assertIn("vsftpd 2.3.4", summary)
        self.assertIn("CVE-2011-2523", summary)
        self.assertIn("EXPLOIT CANDIDATES", summary)
        # the advisory summary must not carry markdown bold from the lead bullets
        self.assertNotIn("**", summary)

    def test_advise_returns_empty_with_no_services(self):
        # No open services → nothing to analyze → no Ollama call, returns "".
        cfg = RunConfig(target="10.10.10.5", profile=Profile.lab())
        out = A.advise(cfg, HostResult(ip="10.10.10.5"), EnumResult(),
                       ExploitResult())
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
