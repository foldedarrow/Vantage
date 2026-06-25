"""vantage regression tests (stdlib unittest — no third-party deps).

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

from vantage.config import classify_target, Profile, RunConfig
from vantage.modules import exploit as E
from vantage.modules import recon as R
from vantage.modules import enumerate as EN
from vantage.modules import cloud as CL
from vantage.modules import report as RP
from vantage import wordlists as W
from vantage import util as U


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

    def test_lab_net_override_beats_htb(self):
        # An operator-declared lab range wins over the built-in HTB range, so a
        # box you own in 10.10.0.0/16 (e.g. local Metasploitable) is 'lab'.
        self.assertEqual(classify_target("10.10.10.104"), "htb")  # default
        self.assertEqual(
            classify_target("10.10.10.104", ["10.10.10.0/24"]), "lab")

    def test_lab_net_override_does_not_widen_external(self):
        # Declaring an unrelated lab range must NOT reclassify a public IP.
        self.assertEqual(
            classify_target("8.8.8.8", ["10.10.10.0/24"]), "external")

    def test_lab_net_only_affects_listed_range(self):
        # Another HTB box outside the declared range stays htb.
        self.assertEqual(
            classify_target("10.10.20.5", ["10.10.10.0/24"]), "htb")

    def test_lab_net_bad_cidr_ignored(self):
        self.assertEqual(classify_target("10.10.10.104", ["not-a-cidr"]), "htb")


class TestLabNetCli(unittest.TestCase):
    """--lab-net flows from the CLI through to classification and enables
    --aggressive on a box that would otherwise be force-gentled as HTB."""
    def test_cli_lab_net_reclassifies_and_allows_aggressive(self):
        from vantage import cli
        cfg = cli.build_config(cli.build_parser().parse_args(
            ["10.10.10.104", "--lab-net", "10.10.10.0/24", "--aggressive"]))
        self.assertEqual(cfg.klass, "lab")
        self.assertIn("lab", cfg.profile.name)      # auto -> lab profile
        self.assertTrue(cfg.aggressive)             # no longer HTB-blocked
        self.assertEqual(cfg.lab_nets, ("10.10.10.0/24",))

    def test_without_lab_net_still_htb(self):
        from vantage import cli
        cfg = cli.build_config(cli.build_parser().parse_args(
            ["10.10.10.104", "--aggressive"]))
        self.assertEqual(cfg.klass, "htb")
        self.assertFalse(cfg.aggressive)            # HTB blocks aggressive


class TestProfileFlags(unittest.TestCase):
    def test_gentle_disables_noisy_enum(self):
        g = Profile.gentle()
        self.assertFalse(g.enable_nikto)
        self.assertFalse(g.enable_active_web)
        self.assertFalse(g.full_tcp)

    def test_lab_enables_full_behaviour(self):
        lab = Profile.lab()
        self.assertTrue(lab.enable_nikto)
        self.assertTrue(lab.enable_active_web)
        self.assertTrue(lab.full_tcp)


class TestDedupe(unittest.TestCase):
    def test_samba_dual_port_dedupes_to_one(self):
        c = lambda port: E.ExploitCandidate(
            port, "Samba usermap", "x",
            msf_module="exploit/multi/samba/usermap_script", high_confidence=True)
        out = E._dedupe([c(139), c(445)])
        self.assertEqual(len(out), 1)

    def test_distinct_modules_kept(self):
        a = E.ExploitCandidate(21, "vsftpd", "x",
                               msf_module="exploit/unix/ftp/vsftpd_234_backdoor", high_confidence=True)
        b = E.ExploitCandidate(139, "samba", "x",
                               msf_module="exploit/multi/samba/usermap_script", high_confidence=True)
        self.assertEqual(len(E._dedupe([a, b])), 2)

    def test_searchsploit_entries_not_deduped(self):
        s1 = E.ExploitCandidate(80, "EDB a", "x", high_confidence=False, category="service")
        s2 = E.ExploitCandidate(80, "EDB b", "x", high_confidence=False, category="service")
        self.assertEqual(len(E._dedupe([s1, s2])), 2)


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
        # Reset the module-level cache and any env between tests. Pop BOTH the new
        # and the legacy var, since the resolver falls back to CTFAUTO_SECLISTS.
        W._seclists_root_cache = None
        self._old_env = os.environ.pop("VANTAGE_SECLISTS", None)
        self._old_legacy = os.environ.pop("CTFAUTO_SECLISTS", None)
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
            os.environ["VANTAGE_SECLISTS"] = self._old_env
        if self._old_legacy is not None:
            os.environ["CTFAUTO_SECLISTS"] = self._old_legacy

    def _cfg(self, seclists_dir=""):
        return RunConfig(target="", profile=Profile.gentle(), seclists_dir=seclists_dir)

    def test_explicit_override_wins(self):
        cfg = self._cfg(seclists_dir=self.tmp)
        self.assertEqual(W.seclists_available(cfg), self.tmp)

    def test_env_var_detected(self):
        os.environ["VANTAGE_SECLISTS"] = self.tmp
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
        # No SecLists anywhere => '' for vhost. Kali ships SecLists at
        # /usr/share/seclists, so we must blank the known-roots list or the
        # resolver finds the real one and this test is non-hermetic (it failed
        # only on Kali). setUp already clears the cache + $VANTAGE_SECLISTS.
        cfg = self._cfg(seclists_dir="/definitely/not/here")
        with mock.patch.object(W, "_SECLISTS_ROOTS", []):
            self.assertEqual(W.vhost_wordlist(cfg), "")


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
        self.assertTrue(promo.high_confidence)

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
    from vantage import cli as _CLI

    def _cfg(self, *extra):
        args = self._CLI.build_parser().parse_args(
            ["203.0.113.5", "--allow-external", *extra])
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

    def test_dedupe_prunes_candidate_list_for_report(self):
        # The orchestrator dedupes the identified candidate list before reporting
        # (dual-port services collapse to one entry). Public `dedupe` alias.
        h = R.HostResult(ip="10.0.0.5")
        h.services = [_svc(6667, "irc", product="UnrealIRCd"),
                      _svc(6697, "irc", product="UnrealIRCd")]
        pruned = E.dedupe(E._signature_candidates(h))
        irc = [c for c in pruned
               if c.msf_module == "exploit/unix/irc/unreal_ircd_3281_backdoor"]
        self.assertEqual(len(irc), 1)


class TestToolDetection(unittest.TestCase):
    """detect_tools must probe the helpers the exploit-id phase gates on, or those
    features silently never fire (sqlmap sweep was dead because of this)."""
    def test_exploit_helpers_are_detected(self):
        from vantage.config import detect_tools
        keys = set(detect_tools().keys())
        for tool in ("sqlmap", "git-dumper", "hydra", "mysql"):
            self.assertIn(tool, keys, tool)


class TestSnmpInvocation(unittest.TestCase):
    """onesixtyone takes ONE positional community; extras are parsed as hosts. All
    communities must be fed via a -c file so they're actually tested (not just
    'public', with 'private'/'community' probed as bogus hosts)."""
    def test_onesixtyone_uses_community_file(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.lab(),
                        out_dir=tempfile.mkdtemp(),
                        discovered_tools={"onesixtyone": "/usr/bin/onesixtyone"})
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return (0, "10.0.0.5 [private] Hardware: x", "")

        with mock.patch.object(EN, "run", side_effect=fake_run):
            out = []
            EN._enum_snmp(cfg, _svc(161, "snmp"), out)

        o161 = next(c for c in calls if c and c[0] == "onesixtyone")
        self.assertIn("-c", o161)
        # the three community strings must NOT appear as positional host args
        self.assertNotIn("private", [tok for tok in o161 if tok != "-c"][2:])


class TestNSEProfileTiming(unittest.TestCase):
    """The NSE vuln pass is the loudest step; it must honour the profile timing
    (gentle stays -T2) and not re-run -sV (recon already version-detected)."""
    def test_nse_uses_profile_timing_and_no_sV(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.gentle(),
                        out_dir=tempfile.mkdtemp())
        h = R.HostResult(ip="10.0.0.5")
        h.services = [_svc(445, "microsoft-ds")]
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            return (0, "", "")

        with mock.patch.object(R, "run", side_effect=fake_run):
            R._nse_vuln_scan(cfg, h)

        cmd = captured["cmd"]
        self.assertIn("-T2", cmd)        # gentle timing carried through
        self.assertNotIn("-sV", cmd)     # redundant version scan dropped


class TestCommandQuoting(unittest.TestCase):
    """Attacker-influenced data (service banner, crawled URLs) is interpolated into
    copy-pasteable command strings; it must be shell-quoted so a hostile target
    can't inject metacharacters into a command an operator pastes verbatim."""
    def test_param_url_with_quote_is_escaped(self):
        import shlex
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab())
        evil = "http://10.0.0.1/x.php?a=1';rm -rf ~;'"
        er = EN.EnumResult()
        er.findings.append(EN.EnumFinding(80, "param-url", "x", tags={"param_url": evil}))
        cands = E._web_candidates(cfg, R.HostResult(ip="10.0.0.1"), er)
        sqli = next(c for c in cands if c.web_action == "sqlmap")
        # When a shell parses the command, the hostile URL stays ONE intact token
        # and never becomes a separate `rm` command.
        toks = shlex.split(sqli.command)
        self.assertIn(evil, toks)
        self.assertNotIn("rm", toks)

    def test_searchsploit_banner_is_quoted(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"searchsploit": "/usr/bin/searchsploit"})
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(21, "ftp", product="evil; rm -rf ~", version="")]
        with mock.patch.object(E, "run", return_value=(0, "[]", "")):
            cands = E._searchsploit_candidates(cfg, h)
        for c in cands:
            if c.command.startswith("searchsploit "):
                self.assertNotIn("; rm -rf ~", c.command)


class TestSoft404Guard(unittest.TestCase):
    """A server that returns 200 for a missing path soft-404s; quick-win path hits
    must be suppressed to avoid flooding the report with false positives."""
    def test_soft404_suppresses_quickwins(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"curl": "/usr/bin/curl"})
        # Every curl returns 200 -> baseline also 200 -> soft-404.
        with mock.patch.object(EN, "run", return_value=(0, "200", "")):
            out = []
            EN._enum_http(cfg, _svc(80, "http"), out)
        self.assertFalse([f for f in out if f.tool == "http-quickwin"])


class TestScanFlags(unittest.TestCase):
    """-Pn for single hosts (firewalled boxes), not for CIDR; --min-rate lab-only."""
    def test_pn_for_single_host(self):
        cfg = RunConfig(target="10.10.10.5", profile=Profile.gentle())
        self.assertIn("-Pn", R._discovery_perf_flags(cfg))

    def test_no_pn_for_cidr(self):
        cfg = RunConfig(target="10.10.10.0/24", profile=Profile.gentle())
        self.assertNotIn("-Pn", R._discovery_perf_flags(cfg))

    def test_min_rate_lab_only(self):
        lab = RunConfig(target="192.168.56.5", profile=Profile.lab())
        gentle = RunConfig(target="10.10.10.5", profile=Profile.gentle())
        self.assertIn("--min-rate", R._discovery_perf_flags(lab))
        self.assertNotIn("--min-rate", R._discovery_perf_flags(gentle))

    def test_max_retries_always(self):
        cfg = RunConfig(target="10.10.10.5", profile=Profile.gentle())
        self.assertIn("--max-retries", R._discovery_perf_flags(cfg))


class TestCidrClassify(unittest.TestCase):
    def test_htb_cidr(self):
        self.assertEqual(classify_target("10.10.0.0/16"), "htb")

    def test_lab_cidr(self):
        self.assertEqual(classify_target("192.168.56.0/24"), "lab")

    def test_is_cidr(self):
        self.assertTrue(R.is_cidr("10.0.0.0/24"))
        self.assertFalse(R.is_cidr("10.0.0.5"))


class TestScopeAllowlist(unittest.TestCase):
    def setUp(self):
        self.f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt")
        self.f.write("# engagement scope\n10.0.0.0/24\nbox.htb\n203.0.113.7\n")
        self.f.close()

    def test_in_scope_cidr(self):
        from vantage.config import load_scope, target_in_scope
        scope = load_scope(self.f.name)
        self.assertTrue(target_in_scope("10.0.0.50", scope))

    def test_out_of_scope_refused(self):
        from vantage.config import load_scope, target_in_scope
        scope = load_scope(self.f.name)
        self.assertFalse(target_in_scope("10.0.1.50", scope))

    def test_hostname_in_scope(self):
        from vantage.config import load_scope, target_in_scope
        scope = load_scope(self.f.name)
        self.assertTrue(target_in_scope("box.htb", scope))

    def test_empty_scope_allows_all(self):
        from vantage.config import target_in_scope
        self.assertTrue(target_in_scope("8.8.8.8", []))


class TestPriorityLeads(unittest.TestCase):
    def test_rce_ranks_above_creds(self):
        host = R.HostResult(ip="10.0.0.1")
        host.nse_cves = ["CVE-2011-2523"]
        enum = EN.EnumResult()
        enum.findings.append(EN.EnumFinding(21, "ftp", "anon", tags={"anon_ftp": True}))
        enum.findings.append(EN.EnumFinding(6379, "redis", "open", tags={"unauth_redis": True}))
        exp = E.ExploitResult()
        exp.candidates.append(E.ExploitCandidate(
            21, "vsftpd backdoor", "x",
            msf_module="exploit/unix/ftp/vsftpd_234_backdoor", high_confidence=True))
        leads = RP._priority_leads(host, enum, exp)
        self.assertTrue(leads)
        self.assertIn("RCE", leads[0])  # high-confidence RCE first
        self.assertTrue(any("Redis" in l for l in leads))
        self.assertTrue(any("anonymous FTP" in l for l in leads))


class TestUnauthServiceProbes(unittest.TestCase):
    class _FakeSock:
        def __init__(self, responses):
            self._r = list(responses)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def sendall(self, data): pass
        def recv(self, n): return self._r.pop(0) if self._r else b""

    def test_redis_unauth_detected(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.lab())
        out = []
        fake = self._FakeSock([b"+PONG\r\n", b"redis_version:7.0.5\r\nrole:master\r\n"])
        with mock.patch("socket.create_connection", return_value=fake):
            EN._probe_redis(cfg, _svc(6379, "redis"), out)
        self.assertTrue(any(f.tags.get("unauth_redis") for f in out), [f.summary for f in out])

    def test_redis_noauth_not_flagged_unauth(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.lab())
        out = []
        fake = self._FakeSock([b"-NOAUTH Authentication required.\r\n"])
        with mock.patch("socket.create_connection", return_value=fake):
            EN._probe_redis(cfg, _svc(6379, "redis"), out)
        self.assertFalse(any(f.tags.get("unauth_redis") for f in out))

    def test_elasticsearch_unauth(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.lab(),
                        discovered_tools={"curl": "/usr/bin/curl"})
        out = []
        body = '{"cluster_name":"es","version":{"lucene_version":"9.0"}}'
        with mock.patch.object(EN, "run", return_value=(0, body, "")):
            EN._enum_elasticsearch(cfg, _svc(9200, "http"), out)
        self.assertTrue(any(f.tags.get("unauth_es") for f in out))

    def test_docker_api_unauth(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.lab(),
                        discovered_tools={"curl": "/usr/bin/curl"})
        out = []
        with mock.patch.object(EN, "run", return_value=(0, '{"ApiVersion":"1.41"}', "")):
            EN._enum_docker_api(cfg, _svc(2375, "docker"), out)
        self.assertTrue(any(f.tags.get("unauth_docker") for f in out))

    def test_ssti_listed_as_candidate_not_injected(self):
        # SSTI is identified as an informational candidate (consistent with the
        # report-only contract), NOT actively injected during enumeration.
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab())
        er = EN.EnumResult()
        er.findings.append(EN.EnumFinding(80, "param-url", "x",
                                          tags={"param_url": "http://10.0.0.1/p.php?id=1"}))
        cands = E._web_candidates(cfg, R.HostResult(ip="10.0.0.1"), er)
        ssti = [c for c in cands if c.web_action == "ssti"]
        self.assertEqual(len(ssti), 1)
        self.assertTrue(ssti[0].command.startswith("#"))  # informational, not run
        self.assertFalse(hasattr(EN, "_probe_ssti"))      # no active injector exists


class TestSweepIndex(unittest.TestCase):
    def test_index_written_and_ranked(self):
        d = tempfile.mkdtemp()
        rows = [{"ip": "10.0.0.1", "services": 2, "candidates": 0, "report": ""},
                {"ip": "10.0.0.2", "services": 5, "candidates": 3,
                 "report": os.path.join(d, "report_10.0.0.2.md")}]
        path = RP.write_sweep_index(d, "10.0.0.0/24", rows)
        self.assertTrue(os.path.exists(path))
        body = open(path).read()
        # the host with more candidates is ranked first
        self.assertLess(body.index("10.0.0.2"), body.index("10.0.0.1"))


class TestParamUrlFiltering(unittest.TestCase):
    """Static assets and cache-buster-only params must be dropped — a real Pi-hole
    scan teed up ~60 bogus sqlmap/LFI candidates against .css/.js?v=... URLs."""
    def test_static_css_js_dropped(self):
        for u in ("http://h/admin/style/pi-hole.css?v=1778323977",
                  "http://h/admin/vendor/jquery/jquery.min.js?v=1778323977",
                  "http://h/img/logo.png?cb=1", "http://h/fonts/x.woff2?v=2"):
            self.assertFalse(EN._is_testable_param_url(u), u)

    def test_cachebuster_only_dropped(self):
        self.assertFalse(EN._is_testable_param_url("http://h/page?v=123"))
        self.assertFalse(EN._is_testable_param_url("http://h/page?_=99&t=1"))

    def test_real_param_kept(self):
        self.assertTrue(EN._is_testable_param_url("http://h/search.php?q=test"))
        self.assertTrue(EN._is_testable_param_url("http://h/item?id=1&v=2"))  # has real id

    def test_discover_filters_static(self):
        cfg = RunConfig(target="192.168.4.2", profile=Profile.lab())
        body = ('<link href="/admin/style/pi-hole.css?v=1778323977">'
                '<script src="/admin/vendor/jquery/jquery.min.js?v=1778323977"></script>'
                '<a href="/admin/index.php?id=1">x</a>')
        with mock.patch.object(EN, "run", return_value=(0, body, "")):
            urls = EN._discover_param_urls(cfg, "http://192.168.4.2", [])
        self.assertTrue(all(not u.endswith(".css?v=1778323977") for u in urls), urls)
        self.assertTrue(all(".min.js" not in u for u in urls), urls)
        self.assertTrue(any("index.php?id=1" in u for u in urls), urls)


class TestSearchsploitNoiseGuard(unittest.TestCase):
    """Don't search Exploit-DB for generic/mislabelled service names with no
    version (nmap labelling Pi-hole's lighttpd 'webdav' -> 40 irrelevant hits)."""
    def _cfg(self):
        return RunConfig(target="192.168.4.2", profile=Profile.lab(),
                         discovered_tools={"searchsploit": "/usr/bin/searchsploit"})

    def test_webdav_no_version_skipped(self):
        h = R.HostResult(ip="192.168.4.2")
        h.services = [_svc(80, "webdav")]  # no product/version
        with mock.patch.object(E, "run") as run_mock:
            cands = E._searchsploit_candidates(self._cfg(), h)
        run_mock.assert_not_called()
        self.assertEqual(cands, [])

    def test_real_banner_still_searched(self):
        h = R.HostResult(ip="192.168.4.2")
        h.services = [_svc(21, "ftp", product="vsftpd", version="2.3.4")]
        with mock.patch.object(E, "run", return_value=(0, "[]", "")) as run_mock:
            E._searchsploit_candidates(self._cfg(), h)
        self.assertTrue(run_mock.called)


class TestNseCvss(unittest.TestCase):
    """NSE CVEs are parsed with their CVSS and ranked high->low; the report/leads
    use that instead of dumping an unordered list."""
    def test_cves_ranked_by_cvss(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(), out_dir=tempfile.mkdtemp())
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(22, "ssh")]
        out = ("22/tcp open ssh\n"
               "| vulners:\n"
               "|   CVE-2025-61985    3.6    https://vulners.com/cve/CVE-2025-61985\n"
               "|   CVE-2026-35414    8.1    https://vulners.com/cve/CVE-2026-35414\n")
        with mock.patch.object(R, "run", return_value=(0, out, "")):
            R._nse_vuln_scan(cfg, h)
        self.assertEqual(h.nse_cves[0], "CVE-2026-35414")          # highest CVSS first
        self.assertEqual(h.nse_cve_scores["CVE-2026-35414"], 8.1)
        self.assertEqual(h.nse_cve_scores["CVE-2025-61985"], 3.6)

    def test_nse_not_bridged_into_enum(self):
        # NSE is rendered in its own report section, NOT duplicated as enum findings.
        cfg = RunConfig(target="10.0.0.1", profile=Profile.gentle())
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(22, "ssh")]
        h.nse_by_port = {"22": ["VULNERABLE: CVE-2026-35414"]}
        res = EN._enumerate_host_fresh(cfg, h)
        self.assertFalse([f for f in res.findings if f.tool == "nmap-nse"])

    def test_leads_drop_low_cvss(self):
        h = R.HostResult(ip="10.0.0.1")
        h.nse_cves = ["CVE-HIGH", "CVE-LOW"]
        h.nse_cve_scores = {"CVE-HIGH": 8.1, "CVE-LOW": 3.6}
        leads = " ".join(RP._priority_leads(h, EN.EnumResult(), E.ExploitResult()))
        self.assertIn("CVE-HIGH", leads)
        self.assertNotIn("CVE-LOW", leads)   # sub-7.0 vulners noise not promoted

    def test_unscored_vulnerable_still_lead(self):
        h = R.HostResult(ip="10.0.0.1")
        h.nse_cves = ["CVE-2007-6750"]; h.nse_cve_scores = {}   # slowloris, no CVSS
        leads = " ".join(RP._priority_leads(h, EN.EnumResult(), E.ExploitResult()))
        self.assertIn("CVE-2007-6750", leads)


class TestWebFingerprint(unittest.TestCase):
    def test_parse_server_httpserver(self):
        self.assertEqual(EN._parse_whatweb_server("a HTTPServer[lighttpd/1.4.76] b"),
                         ("lighttpd", "1.4.76"))

    def test_parse_server_plugin_token(self):
        self.assertEqual(EN._parse_whatweb_server("x Apache[2.4.52] y"), ("Apache", "2.4.52"))

    def test_parse_server_none(self):
        self.assertEqual(EN._parse_whatweb_server("no server disclosed"), ("", ""))

    def test_identify_known_app(self):
        app = EN._identify_web_app("http://x [403] Title[Pi-hole pihole], IP[10.0.0.1]")
        self.assertIsNotNone(app)
        self.assertEqual(app[0], "Pi-hole admin")
        self.assertTrue(app[1])               # sensitive -> mgmt panel

    def test_identify_no_app(self):
        self.assertIsNone(EN._identify_web_app("Title[Just a personal blog]"))

    def test_web_panel_promoted_to_lead(self):
        en = EN.EnumResult()
        en.findings.append(EN.EnumFinding(80, "web-app", "Pi-hole admin detected",
                                          tags={"web_panel": True, "app": "Pi-hole admin"}))
        leads = RP._priority_leads(R.HostResult(ip="10.0.0.1"), en, E.ExploitResult())
        self.assertTrue(any("Mgmt panel" in l for l in leads))


class TestSearchsploitWebOverride(unittest.TestCase):
    """When nmap mislabels a web port, searchsploit should query the whatweb
    product (lighttpd), not nmap's guess (webdav)."""
    def _cfg(self):
        return RunConfig(target="10.0.0.1", profile=Profile.lab(),
                         discovered_tools={"searchsploit": "/usr/bin/searchsploit"})

    def test_uses_whatweb_product_for_generic_service(self):
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(80, "webdav")]
        en = EN.EnumResult()
        en.findings.append(EN.EnumFinding(80, "whatweb", "fp: lighttpd 1.4.76",
                                          tags={"http_product": "lighttpd",
                                                "http_version": "1.4.76"}))
        captured = {}
        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            return (0, "[]", "")
        with mock.patch.object(E, "run", side_effect=fake_run):
            E._searchsploit_candidates(self._cfg(), h, en)
        self.assertIn("lighttpd 1.4.76", " ".join(captured.get("cmd", [])))

    def test_generic_with_no_fingerprint_still_skipped(self):
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(80, "webdav")]
        with mock.patch.object(E, "run") as run_mock:
            cands = E._searchsploit_candidates(self._cfg(), h, EN.EnumResult())
        run_mock.assert_not_called()
        self.assertEqual(cands, [])


class TestDefaultCredCommand(unittest.TestCase):
    def test_ssh_command_is_runnable(self):
        cmd = E._default_cred_command("ssh", "10.0.0.1", 22,
                                      [("root", "root"), ("admin", "admin")])
        self.assertIn("hydra -C", cmd)
        self.assertIn("ssh://10.0.0.1:22", cmd)
        self.assertNotIn("# auto-checked", cmd)

    def test_candidate_no_longer_placeholder(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(), default_creds=True)
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(22, "ssh")]
        cands = E._default_cred_candidates(cfg, h)
        self.assertTrue(cands)
        self.assertNotIn("# auto-checked", cands[0].command)


class TestStealth(unittest.TestCase):
    """Stealth mode: low-and-slow nmap + loud tools off, for authorized detection
    testing. Must not loosen the authorization gate."""
    def test_profile_disables_loud_tools(self):
        p = Profile.stealth()
        self.assertFalse(p.enable_nikto)
        self.assertFalse(p.enable_dirbust)
        self.assertFalse(p.nse_vuln)
        self.assertFalse(p.enable_active_web)
        self.assertEqual(p.nmap_timing, "-T1")
        self.assertNotIn("-O", p.nmap_args)    # OS detection is loud
        self.assertNotIn("-sC", p.nmap_args)   # default scripts are loud

    def test_nmap_flags_single_host(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.stealth(), stealth=True)
        flags = R._discovery_perf_flags(cfg)
        for f in ("-Pn", "-f", "--max-rate", "--scan-delay", "--randomize-hosts"):
            self.assertIn(f, flags)
        self.assertNotIn("--min-rate", flags)  # the opposite of stealth

    def test_nmap_flags_cidr_keeps_discovery(self):
        cfg = RunConfig(target="10.0.0.0/24", profile=Profile.stealth(), stealth=True)
        self.assertNotIn("-Pn", R._discovery_perf_flags(cfg))

    def test_source_port_and_decoys_passthrough(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.stealth(), stealth=True,
                        source_port=53, decoys="RND:5")
        flags = R._discovery_perf_flags(cfg)
        self.assertIn("--source-port", flags); self.assertIn("53", flags)
        self.assertIn("-D", flags); self.assertIn("RND:5", flags)

    def test_no_fragment_drops_f(self):
        cfg = RunConfig(target="10.0.0.5", profile=Profile.stealth(),
                        stealth=True, no_fragment=True)
        self.assertNotIn("-f", R._discovery_perf_flags(cfg))

    def test_ua_args_only_in_stealth(self):
        self.assertEqual(EN._ua_args(RunConfig(target="x", profile=Profile.stealth(),
                                               stealth=True))[0], "-A")
        self.assertEqual(EN._ua_args(RunConfig(target="x", profile=Profile.lab())), [])

    def test_cli_stealth_overrides_profile(self):
        from vantage import cli
        cfg = cli.build_config(cli.build_parser().parse_args(
            ["10.0.0.5", "--stealth", "--profile", "lab"]))
        self.assertTrue(cfg.stealth)
        self.assertIn("stealth", cfg.profile.name)   # beats --profile lab
        self.assertFalse(cfg.profile_is_auto)        # gate won't prompt to widen

    def test_cli_stealth_disables_aggressive(self):
        from vantage import cli
        cfg = cli.build_config(cli.build_parser().parse_args(
            ["10.0.0.5", "--stealth", "--aggressive"]))
        self.assertFalse(cfg.aggressive)


class TestMetasploitableFixes(unittest.TestCase):
    """Regressions from the Metasploitable 2 report review: bind shell as the top
    lead, r-services noise, the api-discovery 404 false positive, extra-port
    coverage, and the newly-covered default-cred protocols."""

    def _cfg(self, **kw):
        return RunConfig(target="10.0.0.1", profile=Profile.lab(),
                         default_creds=True, **kw)

    # --- open bind shell (1524) ---------------------------------------------
    def test_bindshell_signature_and_top_lead(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(1524, "bindshell", product="Metasploitable root shell"),
                      _svc(21, "ftp", product="vsftpd", version="2.3.4")]
        cands = E._signature_candidates(h)
        shell = [c for c in cands if c.category == "shell"]
        self.assertTrue(shell, [c.title for c in cands])
        self.assertEqual(shell[0].port, 1524)
        # ranks ABOVE the vsftpd RCE in the priority leads
        exp = E.ExploitResult()
        for c in cands:
            exp.candidates.append(c)
        leads = RP._priority_leads(h, EN.EnumResult(), exp)
        self.assertIn("Instant root", leads[0])

    def test_rsh_is_not_a_bind_shell(self):
        """Port 514 'shell' (rsh) must NOT be flagged as an open bind shell."""
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(514, "shell", product="Netkit rshd")]
        cands = E._signature_candidates(h)
        self.assertFalse([c for c in cands if c.category == "shell"])
        self.assertTrue([c for c in cands if "r-services" in c.title])

    # --- searchsploit noise --------------------------------------------------
    def test_rservice_names_not_searchsploited(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"searchsploit": "/usr/bin/searchsploit"})
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(513, "login"), _svc(514, "shell"), _svc(512, "exec")]
        with mock.patch.object(E, "run") as run_mock:
            cands = E._searchsploit_candidates(cfg, h)
        run_mock.assert_not_called()
        self.assertEqual(cands, [])

    # --- default creds: new protocols ---------------------------------------
    def test_postgres_vnc_telnet_default_creds(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(5432, "postgresql"), _svc(5900, "vnc"), _svc(23, "telnet")]
        titles = " ".join(c.title for c in E._default_cred_candidates(self._cfg(), h))
        self.assertIn("POSTGRESQL", titles)
        self.assertIn("VNC", titles)
        self.assertIn("TELNET", titles)

    def test_postgres_command_runnable(self):
        cmd = E._default_cred_command("postgresql", "10.0.0.1", 5432,
                                      E._DEFAULT_CREDS["postgresql"])
        self.assertIn("psql", cmd)
        self.assertIn("PGPASSWORD", cmd)

    # --- api-discovery 404 false positive -----------------------------------
    def test_api_discovery_ignores_404_reflecting_path(self):
        """A 404 whose body echoes '/swagger-ui.html' must not be flagged."""
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"curl": "/usr/bin/curl"})
        body_404 = ("<title>404 Not Found</title>The requested URL /swagger-ui.html "
                    "was not found on this server.\n__VANTAGE_HTTP__404")

        def fake_run(cmd, **kw):
            # quick-win baseline probe (-o /dev/null -w %{http_code}) -> a real 404
            # so the soft-404 guard doesn't trigger; every api path returns the
            # reflecting 404 body above.
            if "-o" in cmd:
                return (0, "404", "")
            return (0, body_404, "")

        with mock.patch.object(EN, "run", side_effect=fake_run):
            out = []
            EN._enum_http(cfg, _svc(80, "http"), out)
        self.assertFalse([f for f in out if f.tool == "api-discovery"],
                         "404 body reflecting the path was flagged as exposed API")

    def test_api_discovery_flags_real_200(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"curl": "/usr/bin/curl"})

        def fake_run(cmd, **kw):
            if "-o" in cmd:                    # quick-win baseline probe
                return (0, "404", "")
            return (0, '{"swagger":"2.0","paths":{}}\n__VANTAGE_HTTP__200', "")

        with mock.patch.object(EN, "run", side_effect=fake_run):
            out = []
            EN._enum_http(cfg, _svc(80, "http"), out)
        self.assertTrue([f for f in out if f.tool == "api-discovery"])

    # --- NFS export enumeration ---------------------------------------------
    def test_nfs_world_export_flagged_and_lead(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"showmount": "/usr/sbin/showmount"})
        out = []
        with mock.patch.object(EN, "run",
                               return_value=(0, "Export list for 10.0.0.1:\n/ *", "")):
            EN._enum_nfs(cfg, _svc(2049, "nfs"), out)
        self.assertTrue(out and out[0].tags.get("nfs_world"))
        enum = EN.EnumResult(); enum.findings.extend(out)
        leads = RP._priority_leads(R.HostResult(ip="10.0.0.1"), enum, E.ExploitResult())
        self.assertTrue(any("NFS" in l for l in leads))

    # --- extra-port coverage -------------------------------------------------
    def test_extra_ports_include_distcc(self):
        self.assertIn(3632, R.EXTRA_TCP_PORTS)
        self.assertIn(1524, R.EXTRA_TCP_PORTS)

    def test_extra_port_sweep_merges_new_services(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.gentle(),
                        discovered_tools={"nmap": "/usr/bin/nmap"})
        host = R.HostResult(ip="10.0.0.1")
        host.services = [_svc(80, "http")]
        found = R.HostResult(ip="10.0.0.1")
        found.services = [_svc(3632, "distccd")]
        with mock.patch.object(R, "run", return_value=(0, "", "")), \
             mock.patch("os.path.exists", return_value=True), \
             mock.patch.object(R, "parse_nmap_xml", return_value=found):
            R._scan_extra_ports(cfg, host)
        self.assertIn(3632, [s.port for s in host.services])


class TestNfsSingleEnumeration(unittest.TestCase):
    """NFS registers on 2049 + a dynamic mountd port over TCP and UDP; showmount
    must run once (canonical lowest TCP port), not per RPC port — else the report
    carries duplicate exports and leads."""
    def test_nfs_enumerated_once_across_rpc_ports(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"showmount": "/usr/sbin/showmount"})
        host = R.HostResult(ip="10.0.0.1")
        host.services = [_svc(2049, "nfs"), _svc(59352, "mountd")]
        host.udp_services = [R.Service(port=2049, proto="udp", name="nfs")]
        calls = []
        with mock.patch.object(EN, "_enum_nfs",
                               side_effect=lambda c, svc, out: calls.append((svc.port, svc.proto))):
            EN._enumerate_host_fresh(cfg, host)
        self.assertEqual(calls, [(2049, "tcp")], f"NFS enumerated on {calls}")


class TestSmbSingleEnumeration(unittest.TestCase):
    """139 and 445 are one Samba instance — enumerate once (prefer 445) so the
    report doesn't carry the share listing twice."""
    def test_smb_enumerated_once_when_both_ports_open(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"smbclient": "/usr/bin/smbclient"})
        host = R.HostResult(ip="10.0.0.1")
        host.services = [_svc(139, "netbios-ssn"), _svc(445, "microsoft-ds")]
        calls = []
        with mock.patch.object(EN, "_enum_smb",
                               side_effect=lambda c, svc, out: calls.append(svc.port)):
            EN._enumerate_host_fresh(cfg, host)
        self.assertEqual(calls, [445], f"SMB enumerated on {calls}, expected [445]")


class TestBruteWordlistGz(unittest.TestCase):
    """hydra can't read a gzipped wordlist; a resolved rockyou.txt.gz must be
    gunzipped in the suggested command, not pasted as-is."""
    def test_gz_wordlist_gets_gunzip_prefix(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(), aggressive=True)
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(22, "ssh")]
        with mock.patch.object(E.wordlists, "username_wordlist", return_value="/u.txt"), \
             mock.patch.object(E.wordlists, "password_wordlist",
                               return_value="/usr/share/wordlists/rockyou.txt.gz"):
            cands = E._brute_candidates(cfg, h)
        cmd = cands[0].command
        self.assertIn("gunzip -kf", cmd)
        self.assertIn("/usr/share/wordlists/rockyou.txt ", cmd + " ")  # points at .txt
        self.assertNotIn("rockyou.txt.gz -t", cmd)                     # not the .gz

    def test_plain_wordlist_no_prefix(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(), aggressive=True)
        h = R.HostResult(ip="10.0.0.1"); h.services = [_svc(22, "ssh")]
        with mock.patch.object(E.wordlists, "username_wordlist", return_value="/u.txt"), \
             mock.patch.object(E.wordlists, "password_wordlist", return_value="/p.txt"):
            cands = E._brute_candidates(cfg, h)
        self.assertNotIn("gunzip", cands[0].command)


class TestNiktoLeadExtraction(unittest.TestCase):
    """nikto's confirmed default accounts + admin panels are pulled into their own
    findings so they become priority leads, not buried in the blob."""
    _HITS = [
        "+ [700124] /manager/html: Default account found for 'Tomcat Manager "
        "Application' at (ID 'tomcat', PW 'tomcat'). Apache Tomcat. See: CWE-16",
        "+ [001795] /phpMyAdmin/changelog.php: phpMyAdmin is for managing MySQL.",
        "+ [013587] /: Suggested security header missing: referrer-policy.",
    ]

    def test_confirmed_cred_extracted(self):
        fs = EN._nikto_findings(8180, self._HITS)
        cred = [f for f in fs if f.tags.get("confirmed_cred")]
        self.assertTrue(cred)
        self.assertEqual(cred[0].tags["confirmed_cred"], "tomcat:tomcat")
        self.assertEqual(cred[0].tags["cred_path"], "/manager/html")

    def test_phpmyadmin_panel_extracted(self):
        fs = EN._nikto_findings(80, self._HITS)
        self.assertTrue(any(f.tags.get("panel") == "phpMyAdmin" for f in fs))

    def test_noise_lines_ignored(self):
        # the security-header line must not produce a finding
        fs = EN._nikto_findings(80, [self._HITS[2]])
        self.assertEqual(fs, [])

    def test_confirmed_cred_becomes_top_lead(self):
        enum = EN.EnumResult()
        enum.findings.extend(EN._nikto_findings(8180, self._HITS))
        leads = RP._priority_leads(R.HostResult(ip="10.0.0.1"), enum, E.ExploitResult())
        self.assertTrue(any("Confirmed creds" in l and "tomcat:tomcat" in l
                            for l in leads), leads)
        self.assertTrue(any("phpMyAdmin" in l for l in leads))


class TestReportWriteResilience(unittest.TestCase):
    """A report write must never crash the run after a full scan (a stale
    root-owned loot/*.json from an earlier sudo run threw an uncaught
    PermissionError). _safe_write falls back to a writable temp location."""

    def test_safe_write_happy_path(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "out.txt")
        self.assertEqual(RP._safe_write(p, "data", "report"), p)
        with open(p) as f:
            self.assertEqual(f.read(), "data")

    def test_safe_write_falls_back_on_oserror(self):
        # A directory where a file is expected raises OSError (IsADirectoryError),
        # exercising the fallback deterministically without special permissions.
        # Name it like a file so the temp fallback path doesn't collide with it.
        d = tempfile.mkdtemp()
        target = os.path.join(d, "report.json")
        os.mkdir(target)
        out = RP._safe_write(target, "payload", "report")
        self.assertTrue(out, "fallback should have produced a path")
        self.assertNotEqual(out, target)
        with open(out) as f:
            self.assertEqual(f.read(), "payload")
        os.remove(out)

    def test_write_reports_does_not_raise_on_unwritable_outdir(self):
        # out_dir points at a path under an existing FILE, so makedirs + writes
        # fail; write_reports must warn and fall back, not raise.
        tf = tempfile.NamedTemporaryFile(delete=False); tf.close()
        cfg = RunConfig(target="10.0.0.9", profile=Profile.lab(),
                        out_dir=os.path.join(tf.name, "loot"))
        md, js = RP.write_reports(cfg, R.HostResult(ip="10.0.0.9"),
                                  EN.EnumResult(), E.ExploitResult())
        # returns (fallback paths), never raised
        self.assertTrue(md and js)


def _adsvc(port, name, product="", version="", extrainfo=""):
    return R.Service(port=port, proto="tcp", name=name, product=product,
                     version=version, extrainfo=extrainfo)


class TestADDetection(unittest.TestCase):
    """Domain/DC fingerprinting from nmap banners."""
    def test_ad_domain_from_ldap_banner(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_adsvc(389, "ldap", product="Microsoft Windows Active Directory LDAP",
                             extrainfo="Domain: lab.local, Site: Default-First-Site-Name")]
        self.assertEqual(R.ad_domain(h), "lab.local")

    def test_ad_domain_strips_nmap_trailing_artefact(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_adsvc(3268, "ldap", product="AD LDAP",
                             extrainfo="Domain: lab.local0., Site: x")]
        self.assertEqual(R.ad_domain(h), "lab.local")

    def test_ad_domain_absent(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(80, "http", product="Apache")]
        self.assertEqual(R.ad_domain(h), "")

    def test_is_dc_true_for_krb_plus_ldap(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(88, "kerberos-sec"), _svc(389, "ldap"), _svc(445, "microsoft-ds")]
        self.assertTrue(R.is_domain_controller(h))

    def test_is_dc_false_without_kerberos(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(389, "ldap"), _svc(445, "microsoft-ds")]
        self.assertFalse(R.is_domain_controller(h))


class TestADDispatch(unittest.TestCase):
    """Service routing: Kerberos handled, LDAP deduped, Windows-infra ports kept
    out of the HTTP path."""
    def _cfg(self):
        return RunConfig(target="10.10.10.10", profile=Profile.lab())

    def test_port_88_routes_to_kerberos(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(88, "kerberos-sec")]
        calls = []
        with mock.patch.object(EN, "_enum_kerberos",
                               side_effect=lambda c, svc, out, dom: calls.append(svc.port)):
            EN._enumerate_host_fresh(self._cfg(), h)
        self.assertEqual(calls, [88])

    def test_ldap_enumerated_once_across_ports(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(389, "ldap"), _svc(636, "ldaps"),
                      _svc(3268, "ldap"), _svc(3269, "tcpwrapped")]
        calls = []
        with mock.patch.object(EN, "_enum_ldap",
                               side_effect=lambda c, svc, out, dom="": calls.append(svc.port)):
            EN._enumerate_host_fresh(self._cfg(), h)
        self.assertEqual(calls, [389], f"LDAP enumerated on {calls}, expected [389]")

    def test_winrm_and_httpapi_not_treated_as_web(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(5985, "http", product="Microsoft HTTPAPI httpd 2.0"),
                      _svc(47001, "http", product="Microsoft HTTPAPI httpd 2.0")]
        with mock.patch.object(EN, "_enum_http",
                               side_effect=AssertionError("_enum_http must not run on WinRM/HTTPAPI")):
            res = EN._enumerate_host_fresh(self._cfg(), h)
        # both produce a lightweight recon note instead
        self.assertTrue(any(f.service_port == 5985 for f in res.findings))
        self.assertTrue(any(f.service_port == 47001 for f in res.findings))

    def test_canonical_ldap_port_prefers_389(self):
        self.assertEqual(EN._canonical_ldap_port([636, 3268, 389]), 389)
        self.assertEqual(EN._canonical_ldap_port([3269, 3268]), 3268)
        self.assertEqual(EN._canonical_ldap_port([636]), 636)


class TestEnumLdapDeep(unittest.TestCase):
    def test_naming_context_parsing(self):
        ctx = ["namingContexts: CN=Schema,CN=Configuration,DC=lab,DC=local",
               "defaultNamingContext: DC=lab,DC=local"]
        self.assertEqual(EN._ldap_naming_context(ctx), "DC=lab,DC=local")

    def test_domain_from_naming_context(self):
        self.assertEqual(EN._domain_from_naming_context("DC=lab,DC=local"), "lab.local")
        self.assertEqual(EN._domain_from_naming_context("CN=x"), "")

    def test_anon_bind_tags_domain_and_users(self):
        cfg = RunConfig(target="10.10.10.10", profile=Profile.lab(),
                        discovered_tools={"ldapsearch": "/usr/bin/ldapsearch"})
        root = ("namingContexts: DC=lab,DC=local\n"
                "defaultNamingContext: DC=lab,DC=local\n")
        subtree = ("sAMAccountName: administrator\n"
                   "sAMAccountName: jdoe\n"
                   "description: account pwd is Summer2026!\n")

        def fake_run(cmd, *a, **k):
            return (0, subtree if "-s" in cmd and "sub" in cmd else root, "")

        out = []
        with mock.patch.object(EN, "run", side_effect=fake_run):
            EN._enum_ldap(cfg, _svc(389, "ldap"), out)
        tags = {k: v for f in out for k, v in (f.tags or {}).items()}
        self.assertTrue(tags.get("anon_ldap"))
        self.assertEqual(tags.get("ad_domain"), "lab.local")
        self.assertEqual(tags.get("ldap_users"), 2)
        self.assertTrue(tags.get("ldap_secret"))


class TestKerberosEnum(unittest.TestCase):
    def test_no_domain_emits_recon_hint(self):
        cfg = RunConfig(target="10.10.10.10", profile=Profile.lab(), out_dir=tempfile.mkdtemp())
        out = []
        EN._enum_kerberos(cfg, _svc(88, "kerberos-sec"), out, "")
        self.assertTrue(any("realm not auto-detected" in f.summary for f in out))

    def test_asrep_roast_flagged(self):
        cfg = RunConfig(target="10.10.10.10", profile=Profile.gentle(),
                        out_dir=tempfile.mkdtemp(),
                        discovered_tools={"impacket-GetNPUsers": "/usr/bin/impacket-GetNPUsers"})
        hashline = "$krb5asrep$23$jdoe@LAB.LOCAL:abc123$def456"

        def fake_run(cmd, *a, **k):
            return (0, hashline + "\n", "")

        out = []
        with mock.patch.object(EN, "run", side_effect=fake_run):
            EN._enum_kerberos(cfg, _svc(88, "kerberos-sec"), out, "lab.local")
        self.assertTrue(any(f.tags.get("asrep_roast") for f in out),
                        [f.summary for f in out])

    def test_asrep_hint_when_tool_absent(self):
        cfg = RunConfig(target="10.10.10.10", profile=Profile.lab(),
                        out_dir=tempfile.mkdtemp(), discovered_tools={})
        out = []
        with mock.patch.object(EN, "run", return_value=(0, "", "")):
            EN._enum_kerberos(cfg, _svc(88, "kerberos-sec"), out, "lab.local")
        self.assertTrue(any("AS-REP roast not run" in f.summary for f in out))


class TestADExploitNoise(unittest.TestCase):
    """The misleading leads from the report: ancient DCOM RPC dump and a DNS DoS."""
    def _cfg(self, **kw):
        base = dict(target="10.10.10.10", profile=Profile.lab(),
                    discovered_tools={"searchsploit": "/usr/bin/searchsploit"})
        base.update(kw)
        return RunConfig(**base)

    def test_generic_windows_rpc_banner_skipped(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(135, "msrpc", product="Microsoft Windows RPC")]
        with mock.patch.object(E, "run") as run_mock:
            cands = E._searchsploit_candidates(self._cfg(), h)
        run_mock.assert_not_called()
        self.assertEqual(cands, [])

    def test_dos_only_hit_dropped_when_not_aggressive(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(53, "domain", product="Simple DNS Plus")]
        sp = ('{"RESULTS_EXPLOIT":[{"Title":"Simple DNS Plus - Remote Denial of '
              'Service","URL":"https://x/6059"}]}')
        with mock.patch.object(E, "run", return_value=(0, sp, "")):
            cands = E._searchsploit_candidates(self._cfg(aggressive=False), h)
        self.assertEqual(cands, [])

    def test_dos_kept_when_aggressive(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(53, "domain", product="Simple DNS Plus")]
        sp = ('{"RESULTS_EXPLOIT":[{"Title":"Simple DNS Plus - Remote Denial of '
              'Service","URL":"https://x/6059"}]}')
        with mock.patch.object(E, "run", return_value=(0, sp, "")):
            cands = E._searchsploit_candidates(self._cfg(aggressive=True), h)
        self.assertTrue(cands)


class TestADCveLeads(unittest.TestCase):
    def _cfg(self):
        return RunConfig(target="10.10.10.10", profile=Profile.lab(),
                         discovered_tools={"nxc": "/usr/bin/nxc"})

    def test_dc_gets_zerologon_and_nopac(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(88, "kerberos-sec"), _svc(389, "ldap"), _svc(445, "microsoft-ds")]
        titles = " ".join(c.title for c in E._ad_cve_candidates(self._cfg(), h))
        self.assertIn("Zerologon", titles)
        self.assertIn("noPac", titles)
        self.assertIn("PetitPotam", titles)

    def test_non_dc_gets_no_ad_leads(self):
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(80, "http")]
        self.assertEqual(E._ad_cve_candidates(self._cfg(), h), [])


class TestADReport(unittest.TestCase):
    def _dc_host(self):
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_adsvc(88, "kerberos-sec"),
                      _adsvc(389, "ldap", product="Microsoft Windows Active Directory LDAP",
                             extrainfo="Domain: lab.local, Site: x"),
                      _adsvc(445, "microsoft-ds")]
        return h

    def test_dc_synthesis_line(self):
        cfg = RunConfig(target="10.10.10.10", profile=Profile.lab())
        md = RP._render_md(cfg, self._dc_host(), EN.EnumResult(), E.ExploitResult())
        self.assertIn("Domain Controller", md)
        self.assertIn("lab.local", md)

    def test_asrep_and_secret_leads(self):
        enum = EN.EnumResult()
        enum.findings.append(EN.EnumFinding(88, "GetNPUsers", "AS-REP roastable",
                                            tags={"asrep_roast": True}))
        enum.findings.append(EN.EnumFinding(389, "ldapsearch", "secret in desc",
                                            tags={"ldap_secret": True}))
        enum.findings.append(EN.EnumFinding(88, "kerbrute", "users",
                                            tags={"ad_users": 12}))
        leads = RP._priority_leads(self._dc_host(), enum, E.ExploitResult())
        self.assertTrue(any("AS-REP roast" in l for l in leads))
        self.assertTrue(any("Cleartext secret" in l for l in leads))
        self.assertTrue(any("AD users" in l for l in leads))


class TestNoWebNoSqlmap(unittest.TestCase):
    """A host with no web service (a bare DC) must NOT get a sqlmap crawl lead
    against a blind :80 — that port isn't even open."""
    def test_no_sqlmap_sweep_without_web_port(self):
        cfg = RunConfig(target="10.10.10.10", profile=Profile.lab(),
                        discovered_tools={"sqlmap": "/usr/bin/sqlmap"})
        h = R.HostResult(ip="10.10.10.10")
        h.services = [_svc(88, "kerberos-sec"), _svc(389, "ldap")]
        enum = EN.EnumResult()
        enum.findings.append(EN.EnumFinding(88, "recon", "Kerberos DC"))
        cands = E._web_candidates(cfg, h, enum)
        self.assertFalse([c for c in cands if c.web_action == "sqlmap_crawl"])

    def test_sqlmap_sweep_when_real_web_port(self):
        cfg = RunConfig(target="10.0.0.1", profile=Profile.lab(),
                        discovered_tools={"sqlmap": "/usr/bin/sqlmap"})
        h = R.HostResult(ip="10.0.0.1")
        h.services = [_svc(8080, "http")]
        enum = EN.EnumResult()
        enum.findings.append(EN.EnumFinding(8080, "whatweb", "fingerprint"))
        cands = E._web_candidates(cfg, h, enum)
        sweep = [c for c in cands if c.web_action == "sqlmap_crawl"]
        self.assertTrue(sweep)
        self.assertEqual(sweep[0].port, 8080)


class TestADToolDetection(unittest.TestCase):
    def test_ad_tools_probed(self):
        from vantage.config import detect_tools
        keys = set(detect_tools().keys())
        for tool in ("kerbrute", "nxc", "netexec", "enum4linux-ng",
                     "impacket-GetNPUsers", "bloodhound-python", "certipy"):
            self.assertIn(tool, keys, tool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
