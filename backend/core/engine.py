import asyncio
import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import httpx

from core.ssl_scanner import SSLScanner
from core.headers_scanner import HeadersScanner
from core.cookies_scanner import CookiesScanner
from core.edge_cases_scanner import EdgeCasesScanner
from core.scoring import ScoringEngine
from core.remediator import AutoRemediator
from core.browser_differ import BrowserMatrixAnalyzer


class UnifiedScannerEngine:
    """
    Main orchestrator for the "One-Click Shield" scanner.
    Coordinates SSL/TLS analysis, header inspection, cookie auditing,
    edge cases, scoring, and auto-remediation generation.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.ssl_scanner = SSLScanner(timeout=timeout)
        self.headers_scanner = HeadersScanner()
        self.cookies_scanner = CookiesScanner()
        self.edge_cases_scanner = EdgeCasesScanner(timeout=timeout)

    async def scan_target(self, target: str, is_demo_scenario: Optional[str] = None) -> Dict[str, Any]:
        hostname = self._clean_target(target)

        # Support built-in curated demo targets for hackathon judging & offline tests
        if is_demo_scenario or hostname in ["demo-vulnerable.local", "demo-expired.local", "demo-secure.local"]:
            return self._generate_scenario_data(hostname, is_demo_scenario or hostname)

        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Step 1: Run SSL Scanner (Synchronous TLS socket probing in threadpool)
        loop = asyncio.get_running_loop()
        ssl_task = loop.run_in_executor(None, self.ssl_scanner.scan, hostname, 443)

        # Step 2: Fetch HTTP Headers and Cookies over HTTPS & HTTP
        headers_and_cookies_task = self._fetch_live_headers_and_cookies(hostname)

        # Step 3: Run Edge Cases Scanner (Redirects, DOM mixed content, DNS CAA, Subdomains)
        edge_cases_task = self.edge_cases_scanner.scan(hostname)

        # Execute concurrently with overall timeout
        ssl_result, (headers_dict, raw_cookie_headers, is_https), edge_cases_result = await asyncio.gather(
            ssl_task,
            headers_and_cookies_task,
            edge_cases_task,
            return_exceptions=False
        )

        # Step 4: Run Headers & Cookies Analyzers
        headers_result = self.headers_scanner.scan(headers_dict, is_https=is_https)
        cookies_result = self.cookies_scanner.scan(raw_cookie_headers, url=f"https://{hostname}/")

        # Step 5: Score & Grade the Target
        score_result = ScoringEngine.calculate_score(
            ssl_result=ssl_result,
            headers_result=headers_result,
            cookies_result=cookies_result,
            edge_cases_result=edge_cases_result
        )

        # Step 6: Generate One-Click Auto-Remediation Configs
        unified_data = {
            "target": hostname,
            "scan_timestamp": scan_timestamp,
            "ssl": ssl_result,
            "headers": headers_result,
            "cookies": cookies_result,
            "edge_cases": edge_cases_result,
            "score": score_result
        }

        remediations = AutoRemediator.generate_all_remediations(hostname, unified_data)
        unified_data["remediations"] = remediations
        unified_data["browser_matrix"] = BrowserMatrixAnalyzer.analyze(unified_data)

        return unified_data

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split("/")[0].split(":")[0]

    async def _fetch_live_headers_and_cookies(self, hostname: str) -> tuple[Dict[str, str], List[str], bool]:
        headers: Dict[str, str] = {}
        raw_cookies: List[str] = []
        is_https = True

        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OneClickShield/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9"
        }

        urls_to_try = [f"https://{hostname}/", f"http://{hostname}/"]

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            for url in urls_to_try:
                try:
                    res = await client.get(url, headers=browser_headers)
                    # Merge headers from redirect hops first
                    for hist in res.history:
                        for k, v in hist.headers.items():
                            if k.lower() not in headers:
                                headers[k] = v
                            if k.lower() == "set-cookie" and v not in raw_cookies:
                                raw_cookies.append(v)

                    # Then merge final response headers (takes precedence)
                    for k, v in res.headers.items():
                        headers[k] = v
                        if k.lower() == "set-cookie" and v not in raw_cookies:
                            raw_cookies.append(v)

                    is_https = str(res.url).startswith("https://")
                    if headers:
                        break
                except Exception:
                    continue

        return headers, raw_cookies, is_https

    def _generate_scenario_data(self, hostname: str, scenario: str) -> Dict[str, Any]:
        """Provides simulated comprehensive scan results for demonstrations and test suites."""
        now = datetime.datetime.now(datetime.timezone.utc)
        scan_timestamp = now.isoformat()

        if "secure" in scenario:
            # High-grade A+ target
            ssl_res = {
                "hostname": hostname,
                "port": 443,
                "connected": True,
                "certificate": {
                    "common_name": hostname,
                    "issuer_name": "Let's Encrypt Authority X3",
                    "sans": [hostname, f"www.{hostname}"],
                    "not_before": (now - datetime.timedelta(days=30)).isoformat(),
                    "not_after": (now + datetime.timedelta(days=60)).isoformat(),
                    "days_remaining": 60,
                    "is_expired": False,
                    "signature_algorithm": "sha256WithRSAEncryption",
                    "key_type": "RSA",
                    "key_size": 2048,
                    "hostname_valid": True,
                    "san_match_details": f"Matched pattern '{hostname}'"
                },
                "chain": [
                    {"level": "Leaf", "subject": hostname, "issuer": "Let's Encrypt", "valid_until": "2026-11-10", "is_ca": False},
                    {"level": "Intermediate", "subject": "R3", "issuer": "ISRG Root X1", "valid_until": "2027-01-01", "is_ca": True}
                ],
                "protocols": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
                "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256, "pfs_supported": True},
                "ocsp_stapled": True,
                "alpn_protocols": ["h2", "http/1.1"],
                "issues": [],
                "status": "success"
            }
            headers_dict = {
                "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';",
                "x-content-type-options": "nosniff",
                "x-frame-options": "SAMEORIGIN",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=(), microphone=(), geolocation=()",
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin"
            }
            raw_cookies = [
                "__Host-sid=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=604800"
            ]
            edge_res = {
                "domain": hostname,
                "redirects": {
                    "chain": [
                        {"hop": 1, "url": f"http://{hostname}/", "status_code": 301, "is_https": False, "is_permanent": True},
                        {"hop": 2, "url": f"https://{hostname}/", "status_code": 200, "is_https": True, "is_permanent": False}
                    ],
                    "total_hops": 2,
                    "enforces_https": True,
                    "final_url": f"https://{hostname}/",
                    "issues": []
                },
                "mixed_content": {"active": [], "passive": [], "total_mixed": 0},
                "third_party_resources": [],
                "subdomains": [{"subdomain": f"www.{hostname}", "status": "resolves", "is_parity_counterpart": True}],
                "dns_posture": {"has_caa": True, "caa_records": ["0 issue \"letsencrypt.org\""], "dnssec_enabled": True, "issues": []},
                "issues": []
            }
        else:
            # Vulnerable target illustrating all weaknesses from Problem Statement P18
            ssl_res = {
                "hostname": hostname,
                "port": 443,
                "connected": True,
                "certificate": {
                    "common_name": f"legacy.{hostname}",
                    "issuer_name": "In-House Internal CA",
                    "sans": [f"legacy.{hostname}"],  # Hostname mismatch
                    "not_before": (now - datetime.timedelta(days=400)).isoformat(),
                    "not_after": (now - datetime.timedelta(days=3)).isoformat(),  # Expired
                    "days_remaining": -3,
                    "is_expired": True,
                    "signature_algorithm": "sha1WithRSAEncryption",
                    "key_type": "RSA",
                    "key_size": 1024,
                    "hostname_valid": False,
                    "san_match_details": f"Hostname '{hostname}' did not match SAN 'legacy.{hostname}'"
                },
                "chain": [
                    {"level": "Leaf", "subject": f"legacy.{hostname}", "issuer": "Unknown", "valid_until": "2026-09-08", "is_ca": False}
                ],
                "protocols": {"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False},
                "cipher": {"name": "AES128-SHA", "protocol": "TLSv1.0", "bits": 128, "pfs_supported": False},
                "ocsp_stapled": False,
                "alpn_protocols": ["http/1.1"],
                "issues": [
                    {"id": "hostname-mismatch", "severity": "CRITICAL", "title": "Certificate Hostname Mismatch", "description": f"Target hostname '{hostname}' is not covered by the certificate Common Name or Subject Alternative Names.", "impact": "Browsers will display an untrusted certificate error screen."},
                    {"id": "cert-expired", "severity": "CRITICAL", "title": "SSL/TLS Certificate Expired", "description": "Certificate expired 3 days ago.", "impact": "Users cannot securely access the site; major browsers completely block page access."},
                    {"id": "chain-incomplete-or-self-signed", "severity": "HIGH", "title": "Incomplete Certificate Chain", "description": "Intermediate CA certificate is missing from the server handshake bundle.", "impact": "Mobile apps and curl fail with trust errors."},
                    {"id": "protocol-tls10-enabled", "severity": "HIGH", "title": "Obsolete TLS 1.0 Protocol Enabled", "description": "The server negotiates TLS 1.0, vulnerable to POODLE/BEAST.", "impact": "Vulnerable to cryptographic downgrade attacks."},
                    {"id": "protocol-tls11-enabled", "severity": "HIGH", "title": "Obsolete TLS 1.1 Protocol Enabled", "description": "Deprecated TLS 1.1 protocol is enabled.", "impact": "Fails compliance benchmarks."},
                    {"id": "cipher-no-pfs", "severity": "HIGH", "title": "No Perfect Forward Secrecy (PFS)", "description": "Cipher does not use ephemeral Diffie-Hellman key exchange.", "impact": "Past recorded encrypted traffic can be retroactively decrypted if private key leaks."}
                ],
                "status": "success"
            }

            # Contradictory and missing headers
            headers_dict = {
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
                "x-frame-options": "DENY",
                "content-security-policy": "frame-ancestors 'self' https://partner.com; script-src * 'unsafe-inline' 'unsafe-eval';",
                "x-xss-protection": "1; mode=block"
            }

            raw_cookies = [
                "PHPSESSID=9f82d1c68e1a; Path=/; Domain=.local",  # Missing HttpOnly, Missing Secure, Missing SameSite
                "auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Path=/",  # Missing HttpOnly, Missing Secure
                "__Secure-user=admin; Path=/"  # Prefix violation: missing Secure!
            ]

            edge_res = {
                "domain": hostname,
                "redirects": {
                    "chain": [
                        {"hop": 1, "url": f"http://{hostname}/", "status_code": 302, "is_https": False, "is_permanent": False},
                        {"hop": 2, "url": f"http://login.{hostname}/", "status_code": 302, "is_https": False, "is_permanent": False},
                        {"hop": 3, "url": f"https://{hostname}/dashboard", "status_code": 200, "is_https": True, "is_permanent": False}
                    ],
                    "total_hops": 3,
                    "enforces_https": True,
                    "final_url": f"https://{hostname}/dashboard",
                    "issues": [
                        {"id": "redirect-temporary-http-redirect", "severity": "LOW", "title": "Temporary Redirect Used For HTTPS Upgrade", "description": "Initial redirect from HTTP uses status code 302 instead of 301.", "impact": "Connections not permanently cached."},
                        {"id": "redirect-insecure-intermediate-hop", "severity": "HIGH", "title": "Insecure Intermediate Hop in Redirect Chain", "description": f"Hop 2 (http://login.{hostname}/) reverted to unencrypted HTTP.", "impact": "Exposes traffic to SSL-stripping and network manipulation."}
                    ]
                },
                "mixed_content": {
                    "active": [{"type": "script", "url": "http://cdn.example.org/tracker.js"}],
                    "passive": [{"type": "image", "url": "http://images.example.org/banner.png"}],
                    "total_mixed": 2
                },
                "third_party_resources": [
                    {"type": "script", "origin": "cdn.example.org", "url": "http://cdn.example.org/tracker.js", "has_sri": False, "has_crossorigin": False},
                    {"type": "script", "origin": "code.jquery.com", "url": "https://code.jquery.com/jquery-3.5.1.min.js", "has_sri": False, "has_crossorigin": False}
                ],
                "subdomains": [
                    {"subdomain": f"dev.{hostname}", "ip": "192.168.1.50", "status": "resolves", "is_parity_counterpart": False},
                    {"subdomain": f"admin.{hostname}", "ip": "192.168.1.51", "status": "resolves", "is_parity_counterpart": False}
                ],
                "dns_posture": {
                    "has_caa": False,
                    "caa_records": [],
                    "dnssec_enabled": False,
                    "issues": [
                        {"id": "dns-missing-caa", "severity": "MEDIUM", "title": "Missing DNS CAA Record", "description": f"Domain '{hostname}' has no CAA record in DNS.", "impact": "Any public CA can issue certificates for this domain."}
                    ]
                },
                "issues": [
                    {"id": "mixed-content-active", "severity": "CRITICAL", "title": "Active Mixed Content Detected (1 items)", "description": "Page loads unencrypted HTTP script (http://cdn.example.org/tracker.js) on HTTPS.", "impact": "Browsers block it or MitM attackers can inject code."},
                    {"id": "third-party-script-missing-sri", "severity": "MEDIUM", "title": "External Scripts Lack Subresource Integrity (SRI)", "description": "External scripts lack cryptographic integrity attributes.", "impact": "CDN compromise can inject malicious payloads."},
                    {"id": "subdomain-exposed-dev", "severity": "MEDIUM", "title": f"Sensitive Subdomain Publicly Resolvable: dev.{hostname}", "description": "Development environment exposed to public DNS.", "impact": "Aids attacker reconnaissance."}
                ]
            }

        headers_res = self.headers_scanner.scan(headers_dict, is_https=True)
        cookies_res = self.cookies_scanner.scan(raw_cookies, url=f"https://{hostname}/")
        score_res = ScoringEngine.calculate_score(ssl_res, headers_res, cookies_res, edge_res)

        data = {
            "target": hostname,
            "scan_timestamp": scan_timestamp,
            "ssl": ssl_res,
            "headers": headers_res,
            "cookies": cookies_res,
            "edge_cases": edge_res,
            "score": score_res
        }
        data["remediations"] = AutoRemediator.generate_all_remediations(hostname, data)
        data["browser_matrix"] = BrowserMatrixAnalyzer.analyze(data)
        return data
