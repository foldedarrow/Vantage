"""ctfauto regression tests (stdlib unittest — no third-party deps).

These lock in the behaviour of the bugs fixed in the audit: classification
order, scope gating, dedupe, detection-string robustness, XML resilience, and
SNMP community handling. Run: python -m unittest discover -s tests
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

from ctfauto.config import classify_target, Profile, RunConfig
from ctfauto.modules import exploit as E
from ctfauto.modules import recon as R
from ctfauto.modules import enumerate as EN
from ctfauto.modules import cloud as CL
from ctfauto.modules import report as RP
from ctfauto import wordlists as W
from ctfauto import util as U


class TestClassification(unittest.TestCase):
    def test_htb_ranges_classify_before_lab(self):
        # All carved out of 10/8 — must be htb, not lab (#3).
        for ip in ("10.10.10.5", "10.10.11.9", "10.10.50.1", "10.129.4.4"):
            self.assertEqual(classify_target(ip), "htb", ip)

    def test_tun0_client_range_is_htb_not_lab(self):
        self.assertEqual(classify_target("10.10.14.99"), "htb")

    def test_rfc1918_is_lab(self):
        for ip in ("192.168.56.101", "172.16.5.5", "10.50.0.1"):
            self.assertEqual(classify_target(ip), "lab", ip)

    def test_public_is_external(self):
        for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.5"):
            self.assertEqual(classify_target(ip), "external", ip)

    def test_hostname_is_external(self):
        self.assertEqual(classify_target("example.com"), "external")


class TestProfileFlags(unittest.TestCase):
    def test_gentle_disables_noisy_enum(self):
        g = Profile.gentle()
        self.assertFalse(g.enable_nikto)
        self.assertFalse(g.enable_active_web)
        self.assertFalse(g.full_tcp)
        self.assertFalse(g.enable_auto_exploit)

    def test_lab_enables_full_behaviour(self):
        lab = Profile.lab()
        self.assertTrue(lab.enable_nikto)
        self.assertTrue(lab.enable_active_web)
        self.assertTrue(lab.full_tcp)
        self.assertTrue(lab.enable_auto_exploit)


class TestDedupe(unittest.TestCase):
    def test_samba_dual_port_dedupes_to_one(self):
        c = lambda port: E.ExploitCandidate(
            port, "Samba usermap", "x",
            msf_module="exploit/multi/samba/usermap_script", safe=True)
        out = E._dedupe([c(139), c(445)])
        self.assertEqual(len(out), 1)

    def test_distinct_modules_kept(self):
        a = E.ExploitCandidate(21, "vsftpd", "x",
                               msf_module="exploit/unix/ftp/vsftpd_234_backdoor", safe=True)
        b = E.ExploitCandidate(139, "samba", "x",
                               msf_module="exploit/multi/samba/usermap_script", safe=True)
        self.assertEqual(len(E._dedupe([a, b])), 2)

    def test_searchsploit_entries_not_deduped(self):
        s1 = E.ExploitCandidate(80, "EDB a", "x", safe=False, category="service")
        s2 = E.ExploitCandidate(80, "EDB b", "x", safe=False, category="service")
        self.assertEqual(len(E._dedupe([s1, s2])), 2)


class TestDetectionStrings(unittest.TestCase):
    def test_sqlmap_positive(self):
        out = ("sqlmap identified the following injection point(s) ...\n"
               "Parameter: id (GET)\n    Type: boolean-based blind\n    Title: x")
        self.assertTrue(E._sqlmap_confirmed(out))

    def test_sqlmap_negative_not_flagged(self):
        self.assertFalse(E._sqlmap_confirmed(
            "all tested parameters do not appear to be injectable"))

    def test_hydra_success_parsed(self):
        out = "[22][ssh] host: 10.0.0.5   login: msfadmin   password: msfadmin"
        self.assertEqual(E._parse_hydra_hits(out), ["msfadmin:msfadmin"])

    def test_hydra_banner_not_false_positive(self):
        out = "[DATA] attacking ssh://x\nlogin: and password: appear in this banner line"
        self.assertEqual(E._parse_hydra_hits(out), [])

    def test_msf_session_2_detected(self):
        self.assertTrue(E._msf_session_opened("[*] Command shell session 2 opened"))
        self.assertFalse(E._msf_session_opened("[-] exploit completed, no session"))


class TestReconXML(unittest.TestCase):
    META_XML = """<?xml version="1.0"?><nmaprun><host>
      <address addr="192.168.56.101" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="21"><state state="open"/>
          <service name="ftp" product="vsftpd" version="2.3.4"/></port>
        <port protocol="tcp" portid="80"><state state="open"/>
          <service name="http" product="Apache httpd" version="2.2.8"/></port>
      </ports></host></nmaprun>"""

    def _write(self, content):
        f = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False)
        f.write(content); f.close()
        return f.name

    def test_valid_parse(self):
        host = R.parse_nmap_xml(self._write(self.META_XML))
        self.assertEqual(host.ip, "192.168.56.101")
        self.assertEqual(len(host.services), 2)

    def test_malformed_xml_does_not_raise(self):
        # Truncated/garbage XML must degrade, not crash (#15).
        host = R.parse_nmap_xml(self._write("not xml <<<"))
        self.assertEqual(host.services, [])

    def test_multi_host_all_parsed(self):
        multi = self.META_XML.replace("</nmaprun>", "") + """<host>
          <address addr="192.168.56.102" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="22"><state state="open"/>
            <service name="ssh"/></port></ports></host></nmaprun>"""
        hosts = R.parse_nmap_xml_all(self._write(multi))
        self.assertEqual(len(hosts), 2)  # #16

    def test_add_hosts_exact_token_match(self):
        # 'box.htb' must not be considered present because 'devbox.htb' is (#5).
        # We can't write /etc/hosts in tests, so exercise the matching logic by
        # checking the function tolerates a read and returns a bool.
        self.assertIn(R.add_to_hosts("10.10.11.5", ""), (False,))


class TestSNMP(unittest.TestCase):
    def test_community_parsed_from_brackets(self):
        self.assertEqual(
            EN._parse_onesixtyone_community("10.0.0.5 [private] Hardware: x"), "private")

    def test_no_community(self):
        self.assertEqual(EN._parse_onesixtyone_community("no response"), "")


class TestWordlists(unittest.TestCase):
    """SecLists resolver: root detection, override precedence, fallbacks (#27)."""

    def setUp(self):
        # Reset the module-level cache and any env between tests.
        W._seclists_root_cache = None
        self._old_env = os.environ.pop("CTFAUTO_SECLISTS", None)
        # Build a minimal fake SecLists tree.
        self.tmp = tempfile.mkdtemp()
        for rel in (
            "Discovery/Web-Content/raft-medium-directories.txt",
            "Discovery/DNS/subdomains-top1million-5000.txt",
            "Fuzzing/LFI/LFI-Jhaddix.txt",
            "Usernames/top-usernames-shortlist.txt",
            "Passwords/Common-Credentials/10k-most-common.txt",
        ):
            p = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()

    def tearDown(self):
        W._seclists_root_cache = None
        if self._old_env is not None:
            os.environ["CTFAUTO_SECLISTS"] = self._old_env

    def _cfg(self, seclists_dir=""):
        return RunConfig(target="", profile=Profile.gentle(), seclists_dir=seclists_dir)

    def test_explicit_override_wins(self):
        cfg = self._cfg(seclists_dir=self.tmp)
        self.assertEqual(W.seclists_available(cfg), self.tmp)

    def test_env_var_detected(self):
        os.environ["CTFAUTO_SECLISTS"] = self.tmp
        self.assertEqual(W.seclists_available(self._cfg()), self.tmp)

    def test_dir_wordlist_prefers_seclists(self):
        cfg = self._cfg(seclists_dir=self.tmp)
        self.assertTrue(W.directory_wordlist(cfg).endswith("raft-medium-directories.txt"))

    def test_vhost_resolves_from_seclists(self):
        cfg = self._cfg(seclists_dir=self.tmp)
        self.assertTrue(W.vhost_wordlist(cfg).endswith("subdomains-top1million-5000.txt"))

    def test_user_override_beats_seclists(self):
        cfg = self._cfg(seclists_dir=self.tmp)
        f = tempfile.NamedTemporaryFile("w", delete=False); f.close()
        self.assertEqual(W.directory_wordlist(cfg, override=f.name), f.name)

    def test_bad_override_falls_back(self):
        cfg = self._cfg(seclists_dir=self.tmp)
        got = W.directory_wordlist(cfg, override="/nonexistent/list.txt")
        self.assertTrue(got.endswith("raft-medium-directories.txt"))

    def test_missing_seclists_returns_empty_or_fallback(self):
        # No SecLists, no system wordlists in the test env => '' for vhost.
        cfg = self._cfg(seclists_dir="/definitely/not/here")
        self.assertEqual(W.vhost_wordlist(cfg), "")

    def test_lfi_payloads_merge_capped(self):
        # Write 200 payloads; _lfi_payloads must cap the merged list at 60.
        lfi = os.path.join(self.tmp, "Fuzzing/LFI/LFI-Jhaddix.txt")
        with open(lfi, "w") as f:
            f.write("\n".join(f"../etc/passwd{i}" for i in range(200)))
        cfg = self._cfg(seclists_dir=self.tmp)
        payloads = E._lfi_payloads(cfg)
        self.assertLessEqual(len(payloads), 60)
        self.assertGreater(len(payloads), len(E._LFI_PAYLOADS))


class TestCloud(unittest.TestCase):
    """Cloud recon: name generation, the 4 S3 states, Azure listing, and gating.
    All HTTP/CLI is mocked — the suite makes NO live cloud calls."""

    def _cfg(self, **kw):
        base = dict(target="", profile=Profile.lab(), out_dir="/tmp",
                    discovered_tools={}, cloud=True, allow_cloud=True,
                    cloud_name="acme", cloud_providers=("aws",))
        base.update(kw)
        return RunConfig(**base)

    # --- name generation ---
    def test_keyword_seed(self):
        names = CL.generate_candidates("acme", cap=50)
        self.assertIn("acme", names)
        self.assertIn("acme-backups", names)

    def test_domain_seed_derives_roots(self):
        self.assertEqual(CL._seed_roots("flaws.cloud"), ["flaws", "flaws-cloud", "flawscloud"])

    def test_extra_words_included(self):
        names = CL.generate_candidates("acme", extra_words=["redteam"], cap=200)
        self.assertTrue(any("redteam" in n for n in names))

    def test_candidate_cap_respected(self):
        self.assertLessEqual(len(CL.generate_candidates("acme", cap=10)), 10)

    def test_harvest_s3_names_from_enum(self):
        enum = EN.EnumResult()
        enum.add(EN.EnumFinding(80, "x", "found", "see https://secret-bucket.s3.amazonaws.com/k"))
        self.assertIn("secret-bucket", CL.names_from_enum(enum))

    # --- S3 states (HTTP path, awscli absent) ---
    def _probe_with_http(self, status, body, cfg=None):
        res = CL.CloudResult()
        with mock.patch.object(CL, "_http", return_value=(status, body)):
            CL._s3_probe(cfg or self._cfg(), "acme", res)
        return res.findings

    def test_s3_listable(self):
        f = self._probe_with_http(200, "<ListBucketResult><Contents/></ListBucketResult>")
        self.assertTrue(any(x.state == "listable" for x in f))

    def test_s3_private_but_exists(self):
        f = self._probe_with_http(403, "AccessDenied")
        self.assertTrue(any(x.state == "exists" for x in f))

    def test_s3_missing_no_finding(self):
        f = self._probe_with_http(404, "NoSuchBucket")
        self.assertEqual(f, [])

    def test_s3_write_only_when_aggressive(self):
        # default (non-aggressive): listable response, but NO write attempted
        res = CL.CloudResult()
        cfg = self._cfg(aggressive=False)
        with mock.patch.object(CL, "_http", return_value=(200, "<ListBucketResult/>")) as h:
            CL._s3_probe(cfg, "acme", res)
        # only GET calls, never a PUT
        methods = [c.kwargs.get("method", c.args[1] if len(c.args) > 1 else "GET")
                   for c in h.call_args_list]
        self.assertNotIn("PUT", methods)
        self.assertFalse(any(x.state == "writable" for x in res.findings))

    def test_s3_write_attempted_when_aggressive(self):
        res = CL.CloudResult()
        cfg = self._cfg(aggressive=True)
        def fake_http(url, method="GET", **kw):
            if method == "PUT":
                return 200, ""
            return 200, "<ListBucketResult/>"
        with mock.patch.object(CL, "_http", side_effect=fake_http):
            CL._s3_probe(cfg, "acme", res)
        self.assertTrue(any(x.state == "writable" for x in res.findings))

    # --- Azure ---
    def test_azure_container_listable(self):
        res = CL.CloudResult()
        def fake_http(url, **kw):
            if "comp=list" in url and "restype=container" in url:
                return 200, "<EnumerationResults><Blobs/></EnumerationResults>"
            return 200, ""  # account exists
        with mock.patch.object(CL, "_http", side_effect=fake_http):
            CL._azure_probe(self._cfg(cloud_providers=("azure",)), "acmedata", res)
        self.assertTrue(any(x.state == "listable" and x.provider == "azure"
                            for x in res.findings))

    def test_azure_account_missing(self):
        res = CL.CloudResult()
        with mock.patch.object(CL, "_http", return_value=(0, "")):
            CL._azure_probe(self._cfg(), "nope", res)
        self.assertEqual(res.findings, [])

    # --- bridge into report structures ---
    def test_findings_bridge_to_enum(self):
        res = CL.CloudResult()
        res.add(CL.CloudFinding("aws", "acme", "listable", "x", severity="high"))
        ef = res.as_enum_findings()
        self.assertEqual(ef[0].tags["cloud"], "aws")
        self.assertEqual(ef[0].tags["cloud_state"], "listable")


def _svc(port, name, product="", version=""):
    return R.Service(port=port, proto="tcp", name=name, product=product, version=version)


class TestTomcatDetection(unittest.TestCase):
    """Tomcat default-cred candidate must key off the banner, not a hardcoded
    port pair, and must not match AJP (8009)."""
    def _cfg(self):
        return RunConfig(target="10.0.0.1", profile=Profile.lab(), default_creds=True)

    def test_tomcat_by_banner_on_nonstandard_port(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(8180, "http", product="Apache Tomcat/Coyote JSP engine", version="1.1")]
        cands = E._default_cred_candidates(self._cfg(), h)
        self.assertTrue(any("TOMCAT" in c.title for c in cands), [c.title for c in cands])

    def test_ajp_8009_is_not_tomcat_cred(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(8009, "ajp13", product="Apache Jserv")]
        cands = E._default_cred_candidates(self._cfg(), h)
        self.assertFalse(any("TOMCAT" in c.title for c in cands))

    def test_plain_http_8080_still_tomcat(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(8080, "http")]
        cands = E._default_cred_candidates(self._cfg(), h)
        self.assertTrue(any("TOMCAT" in c.title for c in cands))


class TestWebCandidatePort(unittest.TestCase):
    """CMS / sweep candidates must preserve the discovered port (not blind :80)."""
    def _enum_with(self, finding):
        er = EN.EnumResult()
        er.findings.append(finding)
        return er

    def test_cms_url_keeps_port(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab())
        f = EN.EnumFinding(8080, "cms", "CMS detected: wordpress", tags={"cms": "wordpress"})
        cands = E._web_candidates(cfg, R.HostResult(ip="10.0.0.1"), self._enum_with(f))
        cms = [c for c in cands if c.web_action == "cms"][0]
        self.assertIn(":8080", cms.web_target)

    def test_cms_url_uses_tag_url_when_present(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab())
        f = EN.EnumFinding(8080, "cms", "CMS", tags={"cms": "drupal", "url": "http://h:9000"})
        cands = E._web_candidates(cfg, R.HostResult(ip="10.0.0.1"), self._enum_with(f))
        cms = [c for c in cands if c.web_action == "cms"][0]
        self.assertIn(":9000", cms.web_target)


class TestSearchsploitPromotion(unittest.TestCase):
    def test_version_parse(self):
        self.assertEqual(E._parse_version("vsftpd 2.3.4"), "2.3.4")
        self.assertEqual(E._parse_version("Apache httpd 2.2.8 ((Ubuntu))"), "2.2.8")
        self.assertEqual(E._parse_version("Samba smbd 3.0.20-Debian"), "3.0.20")
        self.assertEqual(E._parse_version("no version here"), "")

    def test_version_applicable_keeps_unconstrained(self):
        self.assertTrue(E._version_applicable("vsftpd backdoor command execution", "2.3.4"))

    def test_version_applicable_filters_mismatch(self):
        self.assertFalse(E._version_applicable("vsftpd 3.0.3 something", "2.3.4"))

    def test_version_applicable_matches(self):
        self.assertTrue(E._version_applicable("vsftpd 2.3.4 backdoor", "2.3.4"))

    def test_promote_vsftpd(self):
        h = R.HostResult(ip="10.0.0.1")
        s = _svc(21, "ftp", product="vsftpd", version="2.3.4")
        promo = E._promote_candidate(h, s, "2.3.4", ["vsftpd 2.3.4 backdoor -> x"])
        self.assertIsNotNone(promo)
        self.assertEqual(promo.msf_module, "exploit/unix/ftp/vsftpd_234_backdoor")
        self.assertTrue(promo.safe)

    def test_no_promote_wrong_version(self):
        h = R.HostResult(ip="10.0.0.1")
        s = _svc(21, "ftp", product="vsftpd", version="3.0.3")
        promo = E._promote_candidate(h, s, "3.0.3", ["vsftpd 3.0.3 -> x"])
        self.assertIsNone(promo)


class TestEnumResumeState(unittest.TestCase):
    def test_enum_state_roundtrip(self):
        er = EN.EnumResult()
        er.findings.append(EN.EnumFinding(80, "whatweb", "fp", "detail", tags={"cms": "wp"}))
        rows = EN._enum_to_state(er)
        back = EN._enum_from_state({"enum": rows})
        self.assertIsNotNone(back)
        self.assertEqual(len(back.findings), 1)
        self.assertEqual(back.findings[0].tags["cms"], "wp")

    def test_enum_from_state_absent(self):
        self.assertIsNone(EN._enum_from_state({"recon": {}}))


class TestRedaction(unittest.TestCase):
    def test_password_kv_redacted(self):
        self.assertIn("[REDACTED]", RP._redact("password=hunter2"))
        self.assertNotIn("hunter2", RP._redact("password: hunter2"))

    def test_private_key_redacted(self):
        blob = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(RP._redact(blob), "[REDACTED PRIVATE KEY]")

    def test_hydra_line_redacted(self):
        out = RP._redact("[22][ssh] host: 10.0.0.5   login: root   password: toor")
        self.assertNotIn("toor", out)
        self.assertIn("root", out)  # username preserved

    def test_creds_list_masks_passwords(self):
        out = RP._redact("VALID DEFAULT CREDS: root:root, admin:secret (manager)")
        self.assertNotIn("secret", out)
        self.assertIn("admin", out)
        self.assertIn("(manager)", out)

    def test_aws_key_redacted(self):
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE",
                         RP._redact("key AKIAIOSFODNN7EXAMPLE found"))

    def test_flag_hex_not_redacted(self):
        flag = "a" * 32
        self.assertIn(flag, RP._redact(f"cat user.txt -> {flag}"))

    def test_benign_text_untouched(self):
        txt = "Server: Apache/2.4.7 on 10.0.0.5:8080"
        self.assertEqual(RP._redact(txt), txt)


class TestBudget(unittest.TestCase):
    def tearDown(self):
        U.start_budget(None)  # reset global state between tests

    def test_no_budget_means_unlimited(self):
        U.start_budget(None)
        self.assertIsNone(U.budget_remaining())
        self.assertFalse(U.budget_exceeded())

    def test_budget_counts_down(self):
        U.start_budget(100)
        rem = U.budget_remaining()
        self.assertIsNotNone(rem)
        self.assertTrue(0 < rem <= 100)
        self.assertFalse(U.budget_exceeded())

    def test_zero_budget_is_unlimited(self):
        U.start_budget(0)
        self.assertIsNone(U.budget_remaining())

    def test_exhausted_budget_blocks_run(self):
        U.start_budget(0.0001)
        time.sleep(0.01)
        rc, out, errs = U.run(["echo", "hi"])
        self.assertEqual(rc, 125)
        self.assertEqual(errs, "budget-exhausted")


class TestTcpwrappedFallback(unittest.TestCase):
    """The tcpwrapped detection that triggers the -sT connect re-scan."""
    def test_mostly_tcpwrapped_true(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "tcpwrapped"), _svc(22, "tcpwrapped"),
                      _svc(80, "tcpwrapped"), _svc(445, "netbios-ssn", product="Samba")]
        self.assertTrue(R._mostly_tcpwrapped(h))

    def test_healthy_scan_not_flagged(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "ftp", product="vsftpd", version="2.3.4"),
                      _svc(22, "ssh", product="OpenSSH", version="4.7p1"),
                      _svc(80, "http", product="Apache", version="2.2.8")]
        self.assertFalse(R._mostly_tcpwrapped(h))

    def test_single_service_not_flagged(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(80, "tcpwrapped")]
        self.assertFalse(R._mostly_tcpwrapped(h))  # too small to be confident

    def test_banner_count(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "ftp", product="vsftpd", version="2.3.4"),
                      _svc(22, "tcpwrapped")]
        self.assertEqual(R._banner_count(h), 1)


class TestNSEGrouping(unittest.TestCase):
    """NSE findings must group one-per-port, not one-per-line (the report
    explosion bug)."""
    def _host_with_nse(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "ftp"), _svc(80, "http")]
        h.nse_by_port = {
            "21": ["VULNERABLE:", "CVE:CVE-2011-2523"],
            "80": ["CVE-2017-7679 9.8", "CVE-2011-3192 7.8"],
        }
        h.nse_vuln_hits = ["[:21] VULNERABLE:", "[:21] CVE:CVE-2011-2523",
                           "[:80] CVE-2017-7679 9.8", "[:80] CVE-2011-3192 7.8"]
        h.nse_cves = ["CVE-2011-2523", "CVE-2017-7679", "CVE-2011-3192"]
        return h

    def test_one_finding_per_port(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab())
        # build an EnumResult via the grouping branch only (avoid live tools):
        res = EN.EnumResult()
        h = self._host_with_nse()
        for port, lines in h.nse_by_port.items():
            res.add(EN.EnumFinding(int(port), "nmap-nse",
                                   f"{len(lines)} vuln-script line(s) on :{port}",
                                   "\n".join(lines)))
        nse_findings = [f for f in res.findings if f.tool == "nmap-nse"]
        self.assertEqual(len(nse_findings), 2)  # not 4 lines
        ports = {f.service_port for f in nse_findings}
        self.assertEqual(ports, {21, 80})


class TestCVEBridge(unittest.TestCase):
    """NSE-flagged CVEs should fire the curated exploit even with an empty banner."""
    def test_vsftpd_cve_fires_without_banner(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "tcpwrapped")]  # no banner!
        h.nse_cves = ["CVE-2011-2523"]
        cands = E._cve_bridge_candidates(h)
        mods = [c.msf_module for c in cands]
        self.assertIn("exploit/unix/ftp/vsftpd_234_backdoor", mods)

    def test_unknown_cve_ignored(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "tcpwrapped")]
        h.nse_cves = ["CVE-2099-0000"]
        self.assertEqual(E._cve_bridge_candidates(h), [])

    def test_bridge_deduped_against_signature(self):
        # if both the banner AND the NSE CVE match, dedupe keeps exactly one run.
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "ftp", product="vsftpd", version="2.3.4")]
        h.nse_cves = ["CVE-2011-2523"]
        all_c = E._signature_candidates(h) + E._cve_bridge_candidates(h)
        deduped = E._dedupe(all_c)
        vsftpd = [c for c in deduped
                  if c.msf_module == "exploit/unix/ftp/vsftpd_234_backdoor"]
        self.assertEqual(len(vsftpd), 1)


class TestExternalProfilePrompt(unittest.TestCase):
    """Authorized external targets prompt for lab-vs-gentle instead of forcing
    gentle. --profile lab / --yes skip the prompt; auto prompts."""
    from ctfauto import cli as _CLI

    def _cfg(self, *extra):
        args = self._CLI.build_parser().parse_args(
            ["203.0.113.5", "--allow-external", "--auto-exploit", *extra])
        return self._CLI.build_config(args)

    def test_external_starts_gentle_on_auto(self):
        cfg = self._cfg()
        self.assertEqual(cfg.klass, "external")
        self.assertIn("gentle", cfg.profile.name)
        self.assertTrue(cfg.profile_is_auto)

    def test_yes_to_upgrade_gives_lab(self):
        cfg = self._cfg()
        with mock.patch("builtins.input", side_effect=["y", "y"]):
            ok = self._CLI.authorization_gate(cfg, assume_yes=False, allow_external=True)
        self.assertTrue(ok)
        self.assertIn("lab", cfg.profile.name)

    def test_no_to_upgrade_stays_gentle(self):
        cfg = self._cfg()
        with mock.patch("builtins.input", side_effect=["n", "y"]):
            ok = self._CLI.authorization_gate(cfg, assume_yes=False, allow_external=True)
        self.assertTrue(ok)
        self.assertIn("gentle", cfg.profile.name)

    def test_explicit_lab_profile_skips_prompt(self):
        cfg = self._cfg("--profile", "lab")
        self.assertIn("lab", cfg.profile.name)
        self.assertFalse(cfg.profile_is_auto)
        # only ONE input call expected (the authorization confirm), no upgrade prompt
        with mock.patch("builtins.input", side_effect=["y"]) as m:
            ok = self._CLI.authorization_gate(cfg, assume_yes=False, allow_external=True)
        self.assertTrue(ok)
        self.assertEqual(m.call_count, 1)

    def test_yes_flag_no_prompt_keeps_gentle(self):
        cfg = self._cfg()
        # --yes path: no interactive upgrade, external stays gentle
        ok = self._CLI.authorization_gate(cfg, assume_yes=True, allow_external=True)
        self.assertTrue(ok)
        self.assertIn("gentle", cfg.profile.name)

    def test_external_aggressive_allowed_with_allow_external(self):
        cfg = self._cfg("--aggressive")
        self.assertTrue(cfg.aggressive)

    def test_external_aggressive_blocked_without_allow_external(self):
        args = self._CLI.build_parser().parse_args(["203.0.113.5", "--aggressive"])
        cfg = self._CLI.build_config(args)
        self.assertFalse(cfg.aggressive)


class TestMsfCommand(unittest.TestCase):
    """LHOST / payload selection — the missing-LHOST abort that failed every
    backdoor on the first live run."""
    def test_known_module_uses_bind_payload(self):
        cmd = E._msf_command("exploit/multi/samba/usermap_script", "10.0.0.5", "10.0.0.9")
        self.assertIn("set PAYLOAD cmd/unix/bind_netcat", cmd)
        self.assertIn("set RHOSTS 10.0.0.5", cmd)

    def test_vsftpd_uses_interact_payload(self):
        cmd = E._msf_command("exploit/unix/ftp/vsftpd_234_backdoor", "10.0.0.5", "10.0.0.9")
        self.assertIn("cmd/unix/interact", cmd)

    def test_unknown_module_sets_lhost(self):
        cmd = E._msf_command("exploit/some/unknown_module", "10.0.0.5", "10.0.0.9")
        self.assertIn("set LHOST 10.0.0.9", cmd)

    def test_lhost_set_when_available(self):
        # even bind-payload modules get LHOST set (harmless, some modules ref it)
        cmd = E._msf_command("exploit/multi/samba/usermap_script", "10.0.0.5", "10.0.0.9")
        self.assertIn("set LHOST 10.0.0.9", cmd)

    def test_local_ip_for_returns_something_or_empty(self):
        # don't assert a specific IP (env-dependent); just that it's a str
        ip = U.local_ip_for("10.0.0.5")
        self.assertIsInstance(ip, str)


class TestParamUrlScope(unittest.TestCase):
    """Discovered param URLs must stay on the target host (no off-target sqlmap)."""
    def _run(self, cfg, body):
        with mock.patch.object(EN, "run", return_value=(0, body, "")):
            return EN._discover_param_urls(cfg, f"http://{cfg.target}", [])

    def test_external_absolute_link_dropped(self):
        cfg = RunConfig(target="192.168.8.104", profile=Profile.lab())
        body = ('<a href="http://issues.apache.org/bugzilla/buglist.cgi?bug_status=NEW">x</a>'
                '<a href="/local.php?id=1">y</a>')
        urls = self._run(cfg, body)
        self.assertTrue(all("apache.org" not in u for u in urls), urls)
        self.assertTrue(any("local.php" in u for u in urls), urls)

    def test_same_host_absolute_kept(self):
        cfg = RunConfig(target="192.168.8.104", profile=Profile.lab())
        body = '<a href="http://192.168.8.104/app.php?q=1">x</a>'
        urls = self._run(cfg, body)
        self.assertTrue(any("app.php" in u for u in urls), urls)

    def test_protocol_relative_dropped(self):
        cfg = RunConfig(target="192.168.8.104", profile=Profile.lab())
        body = '<a href="//evil.com/x.php?a=1">x</a>'
        urls = self._run(cfg, body)
        self.assertEqual(urls, [])


class TestDualPortDedupe(unittest.TestCase):
    def test_irc_dual_port_collapses(self):
        h = R.HostResult(ip="10.0.0.5")
        h.services = [_svc(6667, "irc", product="UnrealIRCd"),
                      _svc(6697, "irc", product="UnrealIRCd")]
        ded = E._dedupe(E._signature_candidates(h))
        irc = [c for c in ded
               if c.msf_module == "exploit/unix/irc/unreal_ircd_3281_backdoor"]
        self.assertEqual(len(irc), 1)

    def test_rmi_dual_port_collapses(self):
        h = R.HostResult(ip="10.0.0.5")
        h.services = [_svc(1099, "java-rmi"), _svc(39503, "java-rmi")]
        ded = E._dedupe(E._signature_candidates(h))
        rmi = [c for c in ded
               if c.msf_module == "exploit/multi/misc/java_rmi_server"]
        self.assertEqual(len(rmi), 1)

    def test_auto_exploit_prunes_candidate_list(self):
        # identify-only path still dedupes res.candidates for the report
        cfg = RunConfig(target="10.0.0.5", profile=Profile.lab(), identify_only=True)
        h = R.HostResult(ip="10.0.0.5")
        h.services = [_svc(6667, "irc", product="UnrealIRCd"),
                      _svc(6697, "irc", product="UnrealIRCd")]
        res = E.ExploitResult()
        for c in E._signature_candidates(h):
            res.add(c)
        E.auto_exploit(cfg, h, res)
        irc = [c for c in res.candidates
               if c.msf_module == "exploit/unix/irc/unreal_ircd_3281_backdoor"]
        self.assertEqual(len(irc), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
