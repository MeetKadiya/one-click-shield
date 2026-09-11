import os
import sys
from pathlib import Path
import unittest

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from main import app


class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")

    def test_scan_demo_vulnerable(self):
        payload = {"target": "vulnerable-demo.site", "scenario": "demo-vulnerable"}
        res = self.client.post("/api/scan", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["target"], "vulnerable-demo.site")
        self.assertIn("score", data)
        self.assertIn("grade", data["score"])
        self.assertIn("remediations", data)
        self.assertIn("nginx", data["remediations"])
        self.assertIn("apache", data["remediations"])

    def test_scan_demo_secure(self):
        payload = {"target": "hardened-example.org", "scenario": "demo-secure"}
        res = self.client.post("/api/scan", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["score"]["grade"], "A+")

    def test_download_fix_pack(self):
        res = self.client.get("/api/download-fix-pack?domain=demo-target.com")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("content-type"), "application/zip")
        self.assertTrue(len(res.content) > 500)


if __name__ == "__main__":
    unittest.main()
