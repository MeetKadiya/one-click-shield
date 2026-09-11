import os
import sys
from pathlib import Path
import unittest
import asyncio

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from core.headers_scanner import HeadersScanner
from core.cookies_scanner import CookiesScanner
from core.scoring import ScoringEngine
from core.remediator import AutoRemediator


class TestScannerModules(unittest.TestCase):

    def setUp(self):
        self.headers_scanner = HeadersScanner()
        self.cookies_scanner = CookiesScanner()

    def test_headers_missing_detection(self):
        empty_headers = {}
        result = self.headers_scanner.scan(empty_headers, is_https=True)
        missing_keys = [m["header"] for m in result["missing_headers"]]
        self.assertIn("strict-transport-security", missing_keys)
        self.assertIn("content-security-policy", missing_keys)
        self.assertIn("x-content-type-options", missing_keys)
        self.assertIn("x-frame-options", missing_keys)

    def test_headers_contradiction_detection(self):
        contradictory_headers = {
            "x-frame-options": "DENY",
            "content-security-policy": "frame-ancestors 'self' https://partner.example.com"
        }
        result = self.headers_scanner.scan(contradictory_headers, is_https=True)
        self.assertTrue(len(result["contradictions"]) > 0)
        self.assertEqual(result["contradictions"][0]["id"], "contradiction-xfo-vs-csp-frame-ancestors")

    def test_headers_deprecated_xss_protection(self):
        legacy_headers = {
            "x-xss-protection": "1; mode=block"
        }
        result = self.headers_scanner.scan(legacy_headers, is_https=True)
        dep_ids = [d["id"] for d in result["breaking_changes"]]
        self.assertIn("deprecated-x-xss-protection-enabled", dep_ids)

    def test_cookies_missing_flags(self):
        raw_cookies = [
            "sessionid=xyz123; Path=/; Domain=.example.com"
        ]
        result = self.cookies_scanner.scan(raw_cookies, url="https://example.com")
        self.assertEqual(result["total_cookies"], 1)
        self.assertEqual(result["missing_httponly_count"], 1)
        self.assertEqual(result["missing_secure_count"], 1)
        self.assertEqual(result["missing_samesite_count"], 1)

    def test_cookie_prefix_rules(self):
        raw_cookies = [
            "__Host-user=123; Path=/; Domain=example.com"  # __Host- violates domain rule
        ]
        result = self.cookies_scanner.scan(raw_cookies, url="https://example.com")
        issue_ids = [i["id"] for i in result["issues"]]
        self.assertTrue(any("cookie-invalid-host-prefix-domain" in i_id for i_id in issue_ids))

    def test_scoring_and_grades(self):
        # Clean results
        clean_ssl = {"issues": []}
        clean_headers = {"issues": []}
        clean_cookies = {"issues": []}
        clean_edge = {"issues": []}

        score_res = ScoringEngine.calculate_score(clean_ssl, clean_headers, clean_cookies, clean_edge)
        self.assertEqual(score_res["overall_score"], 100)
        self.assertEqual(score_res["grade"], "A+")

        # Critical issue drops score significantly
        crit_ssl = {"issues": [{"severity": "CRITICAL", "title": "Cert Expired"}]}
        score_crit = ScoringEngine.calculate_score(crit_ssl, clean_headers, clean_cookies, clean_edge)
        self.assertLess(score_crit["overall_score"], 60)
        self.assertIn(score_crit["grade"], ["C", "D", "F"])

    def test_remediator_generation(self):
        dummy_scan = {
            "headers": {"present_headers": {}},
            "score": {"overall_score": 50, "grade": "C", "all_issues": []}
        }
        rems = AutoRemediator.generate_all_remediations("test-domain.com", dummy_scan)
        self.assertIn("nginx", rems)
        self.assertIn("apache", rems)
        self.assertIn("caddy", rems)
        self.assertIn("cloudflare", rems)
        self.assertIn("nodejs", rems)
        self.assertIn("docker", rems)
        self.assertIn("README_FIXES.md", rems["readme"]["filename"])
        self.assertIn("test-domain.com", rems["nginx"]["content"])


if __name__ == "__main__":
    unittest.main()
