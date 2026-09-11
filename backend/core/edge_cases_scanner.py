import socket
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup

try:
    import dns.resolver
except ImportError:
    dns = None


class EdgeCasesScanner:
    """
    Evaluates complex web security edge cases:
    - HTTP-to-HTTPS redirect chains, status codes, intermediate plaintext hops
    - Mixed content (active vs passive) and embedded third-party scripts
    - Subresource Integrity (SRI) on external scripts
    - Subdomain parity (apex vs www) and common subdomain reconnaissance
    - DNS Certificate Authority Authorization (CAA) and DNSSEC posture
    """

    COMMON_SUBDOMAINS = ["www", "api", "admin", "dev", "staging", "mail", "cdn", "portal", "auth"]

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def scan(self, domain: str) -> Dict[str, Any]:
        domain = self._clean_domain(domain)
        results: Dict[str, Any] = {
            "domain": domain,
            "redirects": {},
            "mixed_content": {},
            "third_party_resources": [],
            "subdomains": [],
            "dns_posture": {},
            "issues": []
        }

        # 1. Analyze Redirect Behavior
        redirect_info = await self._analyze_redirects(domain)
        results["redirects"] = redirect_info
        results["issues"].extend(redirect_info.get("issues", []))

        # 2. Analyze Mixed Content & Third-Party Assets
        html_analysis = await self._analyze_html_and_assets(domain)
        results["mixed_content"] = html_analysis.get("mixed_content", {})
        results["third_party_resources"] = html_analysis.get("third_party_resources", [])
        results["issues"].extend(html_analysis.get("issues", []))

        # 3. Analyze DNS Posture (CAA, DNSSEC)
        dns_info = self._analyze_dns_posture(domain)
        results["dns_posture"] = dns_info
        results["issues"].extend(dns_info.get("issues", []))

        # 4. Analyze Subdomain Parity & Exposure
        sub_info = await self._probe_subdomains(domain)
        results["subdomains"] = sub_info.get("subdomains", [])
        results["issues"].extend(sub_info.get("issues", []))

        return results

    def _clean_domain(self, domain: str) -> str:
        if "://" in domain:
            parsed = urlparse(domain)
            return parsed.hostname or domain
        return domain.split("/")[0].split(":")[0]

    async def _analyze_redirects(self, domain: str) -> Dict[str, Any]:
        start_url = f"http://{domain}/"
        chain: List[Dict[str, Any]] = []
        issues: List[Dict[str, Any]] = []

        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OneClickShield/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, verify=False) as client:
                current_url = start_url
                max_hops = 8
                hop_count = 0

                while hop_count < max_hops:
                    try:
                        res = await client.get(current_url, headers=browser_headers)
                    except Exception as e:
                        chain.append({
                            "url": current_url,
                            "status": "error",
                            "error": str(e)
                        })
                        break

                    is_redirect = res.status_code in [301, 302, 303, 307, 308]
                    next_url = res.headers.get("location")

                    chain.append({
                        "hop": hop_count + 1,
                        "url": current_url,
                        "status_code": res.status_code,
                        "is_https": current_url.lower().startswith("https://"),
                        "location_header": next_url,
                        "is_permanent": res.status_code in [301, 308]
                    })

                    if is_redirect and next_url:
                        # Resolve relative redirect URLs
                        current_url = urljoin(current_url, next_url)
                        hop_count += 1
                    else:
                        break

        except Exception as e:
            issues.append({
                "id": "redirect-scan-error",
                "severity": "LOW",
                "title": "Redirect Analysis Warning",
                "description": f"Could not complete redirect chain check: {str(e)}",
                "impact": "Redirect behavior could not be fully mapped."
            })
            return {"chain": chain, "issues": issues, "enforces_https": False}

        if not chain:
            return {"chain": chain, "issues": issues, "enforces_https": False}

        # Analyze the chain
        first_hop = chain[0]
        final_hop = chain[-1]
        enforces_https = final_hop.get("is_https", False)

        if final_hop.get("status") == "error":
            issues.append({
                "id": "redirect-check-timeout",
                "severity": "LOW",
                "title": "Plaintext HTTP Connection Timeout",
                "description": f"HTTP connection to http://{domain} timed out or was reset by the host.",
                "impact": "Could not verify if port 80 redirects to HTTPS due to network timeout."
            })
        elif not enforces_https:
            issues.append({
                "id": "redirect-no-https-enforcement",
                "severity": "CRITICAL",
                "title": "Plaintext HTTP Does Not Redirect to HTTPS",
                "description": f"Requests to http://{domain} do not upgrade to HTTPS.",
                "impact": "Users connecting via HTTP send credentials, session tokens, and data in cleartext, leaving them vulnerable to interception."
            })
        else:
            # Check status code of the initial redirect
            if len(chain) > 1 and first_hop.get("status_code") in [302, 307]:
                issues.append({
                    "id": "redirect-temporary-http-redirect",
                    "severity": "LOW",
                    "title": "Temporary Redirect Used For HTTPS Upgrade",
                    "description": f"Initial redirect from HTTP uses status code {first_hop.get('status_code')} instead of permanent 301 or 308.",
                    "impact": "Browsers and search engines will not cache the redirect, causing recurring unencrypted initial connections on every session."
                })

            # Check for plaintext intermediate hops
            for idx, hop in enumerate(chain[1:-1], start=2):
                if not hop.get("is_https"):
                    had_prior_https = any(h.get("is_https", False) for h in chain[:idx-1])
                    if had_prior_https:
                        issues.append({
                            "id": "redirect-downgrade-intermediate-hop",
                            "severity": "HIGH",
                            "title": "Protocol Downgrade in Redirect Chain",
                            "description": f"Hop {idx} ({hop.get('url')}) reverted from HTTPS back to unencrypted HTTP.",
                            "impact": "Exposes traffic to SSL-stripping and network manipulation during redirection."
                        })
                    else:
                        issues.append({
                            "id": "redirect-multi-hop-http",
                            "severity": "LOW",
                            "title": "Multiple HTTP Redirects Before HTTPS Upgrade",
                            "description": f"Hop {idx} ({hop.get('url')}) performs an intermediate HTTP redirect before upgrading to HTTPS.",
                            "impact": "Unnecessary round-trips; direct 301 redirection to HTTPS is recommended to minimize latency and exposure."
                        })
                    break

        return {
            "chain": chain,
            "total_hops": len(chain),
            "enforces_https": enforces_https,
            "final_url": final_hop.get("url"),
            "issues": issues
        }

    async def _analyze_html_and_assets(self, domain: str) -> Dict[str, Any]:
        target_url = f"https://{domain}/"
        mixed_content = {
            "active": [],
            "passive": [],
            "total_mixed": 0
        }
        third_party_resources = []
        issues = []

        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OneClickShield/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
                res = await client.get(target_url, headers=browser_headers)
                if not res.is_success and res.status_code >= 400:
                    return {"mixed_content": mixed_content, "third_party_resources": [], "issues": []}

                html = res.text
                soup = BeautifulSoup(html, "html.parser")

                # Check scripts
                for script in soup.find_all("script"):
                    src = script.get("src")
                    if not src:
                        continue
                    abs_url = urljoin(target_url, src)
                    parsed = urlparse(abs_url)

                    # Check mixed content
                    if abs_url.lower().startswith("http://"):
                        mixed_content["active"].append({"type": "script", "url": abs_url})

                    # Check 3rd party
                    if parsed.hostname and parsed.hostname != domain and not parsed.hostname.endswith(f".{domain}"):
                        has_sri = bool(script.get("integrity"))
                        has_crossorigin = bool(script.get("crossorigin"))
                        third_party_resources.append({
                            "type": "script",
                            "origin": parsed.hostname,
                            "url": abs_url,
                            "has_sri": has_sri,
                            "has_crossorigin": has_crossorigin
                        })

                # Check stylesheets
                for link in soup.find_all("link", rel="stylesheet"):
                    href = link.get("href")
                    if not href:
                        continue
                    abs_url = urljoin(target_url, href)
                    parsed = urlparse(abs_url)

                    if abs_url.lower().startswith("http://"):
                        mixed_content["active"].append({"type": "stylesheet", "url": abs_url})

                    if parsed.hostname and parsed.hostname != domain and not parsed.hostname.endswith(f".{domain}"):
                        third_party_resources.append({
                            "type": "stylesheet",
                            "origin": parsed.hostname,
                            "url": abs_url,
                            "has_sri": bool(link.get("integrity")),
                            "has_crossorigin": bool(link.get("crossorigin"))
                        })

                # Check iframes (active mixed content)
                for iframe in soup.find_all("iframe"):
                    src = iframe.get("src")
                    if src and src.lower().startswith("http://"):
                        mixed_content["active"].append({"type": "iframe", "url": src})

                # Check images (passive mixed content)
                for img in soup.find_all("img"):
                    src = img.get("src")
                    if src and src.lower().startswith("http://"):
                        mixed_content["passive"].append({"type": "image", "url": src})

        except Exception:
            # Domain might not serve HTML or failed to connect
            pass

        mixed_content["total_mixed"] = len(mixed_content["active"]) + len(mixed_content["passive"])

        # Flag mixed content issues
        if mixed_content["active"]:
            issues.append({
                "id": "mixed-content-active",
                "severity": "CRITICAL",
                "title": f"Active Mixed Content Detected ({len(mixed_content['active'])} items)",
                "description": f"Page loads unencrypted HTTP scripts, stylesheets, or iframes on an HTTPS page.",
                "impact": "Browsers automatically block active mixed content, breaking website functionality. If not blocked, it enables complete code injection via network MitM."
            })

        if mixed_content["passive"]:
            issues.append({
                "id": "mixed-content-passive",
                "severity": "MEDIUM",
                "title": f"Passive Mixed Content Detected ({len(mixed_content['passive'])} items)",
                "description": "Page embeds unencrypted HTTP images or multimedia elements.",
                "impact": "Browsers display a broken padlock or 'Not Secure' alert, undermining user trust and leaking referrer query data."
            })

        # Flag missing SRI on external scripts
        scripts_without_sri = [s for s in third_party_resources if s["type"] == "script" and not s["has_sri"]]
        if len(scripts_without_sri) > 0:
            sample_origins = list(set([s["origin"] for s in scripts_without_sri]))[:3]
            issues.append({
                "id": "third-party-script-missing-sri",
                "severity": "MEDIUM",
                "title": f"External Scripts Lack Subresource Integrity (SRI) ({len(scripts_without_sri)} scripts)",
                "description": f"External scripts loaded from origins ({', '.join(sample_origins)}) do not specify an 'integrity' cryptographic hash.",
                "impact": "If the third-party CDN or provider is compromised, malicious code will execute inside your users' browsers without detection."
            })

        return {
            "mixed_content": mixed_content,
            "third_party_resources": third_party_resources[:20],
            "issues": issues
        }

    def _analyze_dns_posture(self, domain: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "caa_records": [],
            "has_caa": False,
            "dnssec_enabled": False,
            "issues": []
        }

        if dns is None:
            return info

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0

            # Query CAA
            try:
                answers = resolver.resolve(domain, "CAA")
                for rdata in answers:
                    info["caa_records"].append(str(rdata))
                if info["caa_records"]:
                    info["has_caa"] = True
            except Exception:
                info["has_caa"] = False

            if not info["has_caa"]:
                info["issues"].append({
                    "id": "dns-missing-caa",
                    "severity": "MEDIUM",
                    "title": "Missing DNS CAA (Certificate Authority Authorization) Record",
                    "description": f"Domain '{domain}' has no CAA record configured in DNS.",
                    "impact": "Any public Certificate Authority can issue SSL/TLS certificates for this domain, leaving it exposed if a rogue or compromised CA issues unauthorized certificates."
                })

            # Check DNSSEC
            try:
                dnskey_answers = resolver.resolve(domain, "DNSKEY")
                if dnskey_answers:
                    info["dnssec_enabled"] = True
            except Exception:
                info["dnssec_enabled"] = False

            if not info["dnssec_enabled"]:
                info["issues"].append({
                    "id": "dns-dnssec-disabled",
                    "severity": "LOW",
                    "title": "DNSSEC Not Enabled",
                    "description": "The domain does not have active DNSSEC cryptographic signatures on its DNS zone.",
                    "impact": "Leaves DNS responses vulnerable to DNS spoofing and cache poisoning attacks."
                })

        except Exception:
            pass

        return info

    async def _probe_subdomains(self, domain: str) -> Dict[str, Any]:
        subdomains_found = []
        issues = []

        # Check www vs apex parity
        is_www = domain.startswith("www.")
        alternate_domain = domain[4:] if is_www else f"www.{domain}"

        # Rapid DNS check for alternate
        try:
            socket.gethostbyname(alternate_domain)
            subdomains_found.append({
                "subdomain": alternate_domain,
                "status": "resolves",
                "is_parity_counterpart": True
            })
        except Exception:
            issues.append({
                "id": "subdomain-apex-www-parity",
                "severity": "LOW",
                "title": f"Subdomain Parity Missing: '{alternate_domain}' Unreachable",
                "description": f"The counterpart host '{alternate_domain}' does not resolve in DNS.",
                "impact": "Visitors who type the URL with or without 'www' will experience connection failures."
            })

        # Probe for exposed non-production environments
        apex_base = domain[4:] if domain.startswith("www.") else domain
        for sub in ["dev", "staging", "test"]:
            test_host = f"{sub}.{apex_base}"
            try:
                ip = socket.gethostbyname(test_host)
                subdomains_found.append({
                    "subdomain": test_host,
                    "ip": ip,
                    "status": "resolves",
                    "is_parity_counterpart": False
                })
                issues.append({
                    "id": f"subdomain-exposed-{sub}",
                    "severity": "MEDIUM",
                    "title": f"Non-Production Subdomain Publicly Resolvable: {test_host}",
                    "description": f"Internal environment '{test_host}' resolves to public IP {ip}.",
                    "impact": "Development or staging services should not be publicly accessible to prevent credential leaks and reconnaissance."
                })
            except Exception:
                pass

        return {
            "subdomains": subdomains_found,
            "issues": issues
        }
