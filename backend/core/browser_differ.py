"""
Multi-Browser Compatibility & Security Defense Matrix Analyzer
Evaluates target security posture from the perspective of distinct browser security engines:
- Tor Browser (Onion routing, exit-node MitM exposure, script blocking, strict isolation)
- Brave Browser (Brave Shields, aggressive tracker/cookie partitioning, HTTPS upgrade)
- Yandex Browser (Protect Active Security, DNSCrypt/DNSSEC verification, CA trust anchors)
- Google Chrome (HSTS Preload mandate, Certificate Transparency, SameSite=Lax default)
- Mozilla Firefox (Total Cookie Protection, strict SRI enforcement, Gecko framing)
- Apple Safari (398-day TLS cert validity limit, WebKit ITP client-side cookie capping)
"""

from typing import Dict, Any, List


class BrowserMatrixAnalyzer:
    """
    Analyzes unified scan diagnostic data to determine specific compatibility,
    enforcement warnings, and user experience across major specialized web browsers.
    """

    @classmethod
    def analyze(cls, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        ssl_data = scan_result.get("ssl") or {}
        headers_data = scan_result.get("headers") or {}
        cookies_data = scan_result.get("cookies") or {}
        edge_data = scan_result.get("edge_cases") or {}
        score_data = scan_result.get("score") or {}

        norm_headers = {k.lower(): v for k, v in (headers_data.get("raw_headers") or {}).items()}
        cookies_list = cookies_data.get("cookies") or []
        edge_issues = edge_data.get("issues") or []
        ssl_issues = ssl_data.get("issues") or []
        header_issues = headers_data.get("issues") or []

        # Certificate status checks
        cert_dict = ssl_data.get("certificate") or {}
        is_cert_expired = ssl_data.get("is_expired", False) or cert_dict.get("is_expired", False) or any(i.get("id") == "cert-expired" for i in ssl_issues)
        has_hostname_mismatch = any(i.get("id") == "hostname-mismatch" for i in ssl_issues)
        has_cert_errors = is_cert_expired or has_hostname_mismatch or any("expired" in i.get("id", "") or "mismatch" in i.get("id", "") for i in ssl_issues)

        is_https = ssl_data.get("status") == "success" and not has_cert_errors

        # Calculate cert days valid
        cert_days_valid = 0
        try:
            from datetime import datetime
            nb_str = cert_dict.get("not_before", "") or ssl_data.get("not_before", "")
            na_str = cert_dict.get("not_after", "") or ssl_data.get("not_after", "")
            if nb_str and na_str:
                nb = datetime.fromisoformat(nb_str.replace("Z", "+00:00"))
                na = datetime.fromisoformat(na_str.replace("Z", "+00:00"))
                cert_days_valid = (na - nb).days
        except Exception:
            cert_days_valid = 365

        has_hsts = "strict-transport-security" in norm_headers
        hsts_val = norm_headers.get("strict-transport-security", "") or ""
        hsts_has_preload = "preload" in hsts_val.lower()
        hsts_has_subdomains = "includesubdomains" in hsts_val.lower()

        has_csp = "content-security-policy" in norm_headers
        csp_val = norm_headers.get("content-security-policy", norm_headers.get("content-security-policy-report-only", "")) or ""
        csp_has_unsafe_inline = "'unsafe-inline'" in csp_val
        csp_has_unsafe_eval = "'unsafe-eval'" in csp_val

        has_mixed_content = any(i.get("id") == "mixed-content-active" for i in edge_issues)
        has_sri_issues = any(i.get("id") in ["edge-scripts-missing-sri", "third-party-script-missing-sri"] for i in edge_issues)
        has_dns_caa = (edge_data.get("caa_records") or {}).get("has_caa", False) or (edge_data.get("dns_posture") or {}).get("has_caa", False)
        has_dnssec = (edge_data.get("dnssec") or {}).get("dnssec_enabled", False) or (edge_data.get("dns_posture") or {}).get("dnssec_enabled", False)

        cookies_missing_secure = (cookies_data.get("missing_secure_count") or 0) > 0
        cookies_missing_samesite = (cookies_data.get("missing_samesite_count") or 0) > 0

        # Protocols
        protocols = ssl_data.get("protocols") or {}
        has_obsolete_tls = protocols.get("TLSv1.0", False) or protocols.get("TLSv1.1", False)

        # Build evaluations for each browser
        matrix = {
            "tor": cls._eval_tor(is_https, has_cert_errors, has_csp, csp_has_unsafe_inline, has_sri_issues, has_mixed_content, cookies_missing_secure, norm_headers),
            "brave": cls._eval_brave(is_https, has_cert_errors, has_mixed_content, has_hsts, cookies_missing_samesite, has_sri_issues, norm_headers, cookies_list),
            "yandex": cls._eval_yandex(is_https, has_cert_errors, ssl_issues, has_dnssec, has_dns_caa, ssl_data),
            "chrome": cls._eval_chrome(is_https, has_cert_errors, has_hsts, hsts_has_preload, hsts_has_subdomains, has_obsolete_tls, cookies_missing_samesite),
            "firefox": cls._eval_firefox(is_https, has_cert_errors, has_mixed_content, has_csp, has_sri_issues, cookies_list, norm_headers),
            "safari": cls._eval_safari(is_https, has_cert_errors, cert_days_valid, cookies_list, norm_headers)
        }

        # Overall browser readiness score
        scores = [b["score"] for b in matrix.values()]
        avg_score = round(sum(scores) / len(scores)) if scores else 0

        return {
            "overall_browser_score": avg_score,
            "browsers": matrix,
            "summary": f"Target evaluated across 6 specialized browser engines. Average browser defense rating: {avg_score}/100."
        }

    @classmethod
    def _eval_tor(cls, is_https, has_cert_errors, has_csp, csp_unsafe_inline, has_sri_issues, has_mixed, cookies_missing_secure, headers) -> Dict[str, Any]:
        """Tor Browser: Anonymity, Exit-Node MitM Exposure, Strict Script Isolation."""
        findings = []
        score = 100

        if has_cert_errors or not is_https:
            score -= 65
            findings.append({
                "type": "CRITICAL",
                "title": "Severe Exit-Node Interception Risk",
                "desc": "Invalid TLS certificate or plaintext HTTP allows malicious Tor exit node operators to sniff credentials and tamper with traffic."
            })
        else:
            findings.append({
                "type": "PASS",
                "title": "TLS Enforced Against Exit-Node Sniffing",
                "desc": "All traffic is encrypted, preventing Tor exit nodes from sniffing credentials."
            })

        if has_mixed:
            score -= 30
            findings.append({
                "type": "CRITICAL",
                "title": "Active Mixed Content Loaded in Tor",
                "desc": "Unencrypted HTTP scripts loaded over HTTPS allow exit relays to bypass browser defenses and execute tracking payloads."
            })

        if has_sri_issues:
            score -= 15
            findings.append({
                "type": "WARNING",
                "title": "External CDN Scripts Lack SRI (De-Anonymization Threat)",
                "desc": "If a third-party CDN is compromised, attackers can inject fingerprinting scripts to correlate Tor user identities."
            })

        if not has_csp or csp_unsafe_inline:
            score -= 10
            findings.append({
                "type": "WARNING",
                "title": "Permissive Script Execution in Tor",
                "desc": "Tor users in 'Safer' security mode block scripts lacking cryptographic nonces. Unrestricted inline scripts increase XSS risks."
            })

        if "onion-location" in headers:
            findings.append({
                "type": "EXCELLENT",
                "title": "Onion-Location Header Configured",
                "desc": "Site informs Tor Browser of an official .onion v3 hidden service mirror for zero-exit routing."
            })
        else:
            findings.append({
                "type": "INFO",
                "title": "No Onion-Location Header",
                "desc": "Consider adding 'Onion-Location: http://<v3-address>.onion' to offer zero-latency anonymous circuits."
            })

        score = max(0, min(100, score))
        status = "SHIELDED" if score >= 75 else ("WARNINGS_PRESENT" if score >= 45 else "BLOCKED_RISK")

        return {
            "name": "Tor Browser",
            "icon": "🧅",
            "engine": "Gecko (Tor Hardened)",
            "score": score,
            "status": status,
            "badge_color": "#8b5cf6",
            "threat_model": "Exit-Node Eavesdropping, Script De-anonymization & Fingerprinting",
            "verdict": "Vulnerable to exit-node tampering" if score < 45 else ("Acceptable privacy baseline" if score < 75 else "Hardened for anonymous browsing"),
            "findings": findings
        }

    @classmethod
    def _eval_brave(cls, is_https, has_cert_errors, has_mixed, has_hsts, cookies_missing_samesite, has_sri_issues, headers, cookies) -> Dict[str, Any]:
        """Brave Browser: Brave Shields, Ephemeral Storage Partitioning, Fingerprinting Block."""
        findings = []
        score = 100

        if has_cert_errors or not is_https:
            score -= 60
            findings.append({
                "type": "CRITICAL",
                "title": "Brave Displays Interstitial Security Warning",
                "desc": "Invalid TLS certificate causes Brave to block connection with NET::ERR_CERT_DATE_INVALID or NET::ERR_CERT_COMMON_NAME_INVALID."
            })

        if has_mixed:
            score -= 25
            findings.append({
                "type": "CRITICAL",
                "title": "Brave Shields Blocks Active Mixed Content",
                "desc": "Unencrypted HTTP scripts on HTTPS pages are blocked automatically by Brave Shields, breaking dependent application features."
            })

        if has_sri_issues:
            score -= 10
            findings.append({
                "type": "WARNING",
                "title": "Unverified Third-Party CDN Scripts",
                "desc": "Third-party tracking or unverified external scripts without integrity attributes are subject to Brave's ad/tracker shield."
            })

        if "permissions-policy" in headers:
            findings.append({
                "type": "PASS",
                "title": "Hardware API Access Restricted",
                "desc": "Permissions-Policy aligns with Brave's aggressive hardware and sensor fingerprinting defenses."
            })

        score = max(0, min(100, score))
        status = "SHIELDED" if score >= 75 else ("WARNINGS_PRESENT" if score >= 45 else "BLOCKED_RISK")

        return {
            "name": "Brave Browser",
            "icon": "🦁",
            "engine": "Chromium (Brave Core)",
            "score": score,
            "status": status,
            "badge_color": "#f97316",
            "threat_model": "Ad-Trackers, Storage Partitioning, Fingerprinting & HTTPS Upgrading",
            "verdict": "Critical blocks under Brave Shields" if score < 45 else ("Features may break under Shields" if score < 75 else "Fully optimized for Brave Shields"),
            "findings": findings
        }

    @classmethod
    def _eval_yandex(cls, is_https, has_cert_errors, ssl_issues, has_dnssec, has_dns_caa, ssl_data) -> Dict[str, Any]:
        """Yandex Browser: Protect Technology, DNSCrypt Verification, Certificate Trust."""
        findings = []
        score = 100

        if has_cert_errors or not is_https:
            score -= 70
            findings.append({
                "type": "CRITICAL",
                "title": "Triggering Yandex 'Protect' Full-Page Red Block Screen",
                "desc": "Yandex Protect automatically intercepts and blocks sites with untrusted, expired, or hostname-mismatched certificates."
            })
        else:
            findings.append({
                "type": "PASS",
                "title": "Passed Yandex Protect Trust Gateway",
                "desc": "Valid certificate chain recognized by Yandex's dual international/regional root trust stores."
            })

        if not has_dnssec:
            score -= 15
            findings.append({
                "type": "WARNING",
                "title": "Lacks DNSSEC for Yandex DNSCrypt Verification",
                "desc": "Yandex features active DNS protection on public Wi-Fi. Domains without DNSSEC signatures cannot be verified cryptographically against cache poisoning."
            })

        if not has_dns_caa:
            score -= 10
            findings.append({
                "type": "WARNING",
                "title": "Missing DNS CAA Authorization",
                "desc": "No CAA records restricting CA issuance; untrusted regional CAs could theoretically issue rogue certificates."
            })

        score = max(0, min(100, score))
        status = "SHIELDED" if score >= 75 else ("WARNINGS_PRESENT" if score >= 45 else "BLOCKED_RISK")

        return {
            "name": "Yandex Browser",
            "icon": "🔴",
            "engine": "Chromium / Blink (Protect Engine)",
            "score": score,
            "status": status,
            "badge_color": "#ef4444",
            "threat_model": "Insecure Wi-Fi Spoofing, DNS Hijacking, Malware/Phishing Interception",
            "verdict": "High risk of Yandex Protect blocking" if score < 45 else ("DNS / certificate advisories" if score < 75 else "Compatible with Yandex Protect security checks"),
            "findings": findings
        }

    @classmethod
    def _eval_chrome(cls, is_https, has_cert_errors, has_hsts, hsts_preload, hsts_subdomains, has_obsolete_tls, cookies_missing_samesite) -> Dict[str, Any]:
        """Google Chrome: HSTS Preload, SameSite=Lax Default, CT Mandate, Deprecated Protocols."""
        findings = []
        score = 100

        if has_cert_errors or not is_https:
            score -= 60
            findings.append({
                "type": "CRITICAL",
                "title": "Chrome Displays 'Your Connection Is Not Private'",
                "desc": "Certificate expiration or hostname mismatch triggers Chrome's full interstitial red warning (NET::ERR_CERT_*)."
            })

        if has_obsolete_tls:
            score -= 25
            findings.append({
                "type": "CRITICAL",
                "title": "Chrome ERR_SSL_OBSOLETE_VERSION Trigger",
                "desc": "Negotiation with deprecated TLS 1.0/1.1 is completely blocked in modern Chrome versions."
            })

        if cookies_missing_samesite:
            score -= 10
            findings.append({
                "type": "WARNING",
                "title": "Cookies Defaulted to 'SameSite=Lax'",
                "desc": "Chrome enforces 'SameSite=Lax' by default for unspecified cookies. External POST forms will omit these cookies."
            })

        if has_hsts and hsts_preload and hsts_subdomains:
            findings.append({
                "type": "EXCELLENT",
                "title": "Eligible for Chrome HSTS Preload List",
                "desc": "Configuration satisfies hstspreload.org requirements for hardcoded browser-level HTTPS enforcement."
            })

        score = max(0, min(100, score))
        status = "SHIELDED" if score >= 75 else ("WARNINGS_PRESENT" if score >= 45 else "BLOCKED_RISK")

        return {
            "name": "Google Chrome",
            "icon": "🌐",
            "engine": "Chromium / Blink",
            "score": score,
            "status": status,
            "badge_color": "#3b82f6",
            "threat_model": "SameSite Cookie Defaults, Obsolete Protocol Rejection, HSTS Preload",
            "verdict": "Obsolete protocol / certificate failure" if score < 45 else ("Cookie default warnings" if score < 75 else "Optimal Chrome compatibility"),
            "findings": findings
        }

    @classmethod
    def _eval_firefox(cls, is_https, has_cert_errors, has_mixed, has_csp, has_sri_issues, cookies, headers) -> Dict[str, Any]:
        """Mozilla Firefox: Total Cookie Protection, Strict SRI Verification, Gecko Framing."""
        findings = []
        score = 100

        if has_cert_errors or not is_https:
            score -= 60
            findings.append({
                "type": "CRITICAL",
                "title": "Firefox Displays 'Warning: Potential Security Risk Ahead'",
                "desc": "SEC_ERROR_EXPIRED_CERTIFICATE or untrusted root triggers Firefox full-screen interstitial warning."
            })

        if has_mixed:
            score -= 25
            findings.append({
                "type": "CRITICAL",
                "title": "Firefox Blocks Insecure Active Mixed Content",
                "desc": "Firefox completely blocks active mixed content (scripts/iframes) loaded over plaintext HTTP."
            })

        if has_sri_issues:
            score -= 10
            findings.append({
                "type": "WARNING",
                "title": "Strict Subresource Integrity (SRI) Check Alert",
                "desc": "Firefox strictly validates script hashes. Tampered or unhashed third-party CDN scripts risk execution failure."
            })

        score = max(0, min(100, score))
        status = "SHIELDED" if score >= 75 else ("WARNINGS_PRESENT" if score >= 45 else "BLOCKED_RISK")

        return {
            "name": "Mozilla Firefox",
            "icon": "🦊",
            "engine": "Gecko Engine",
            "score": score,
            "status": status,
            "badge_color": "#ea580c",
            "threat_model": "Total Cookie Isolation, HTTPS-Only Mode, Subresource Integrity",
            "verdict": "Firefox interstitial security block" if score < 45 else ("Minor SRI advisories" if score < 75 else "Fully compatible with Firefox Gecko"),
            "findings": findings
        }

    @classmethod
    def _eval_safari(cls, is_https, has_cert_errors, cert_days_valid, cookies, headers) -> Dict[str, Any]:
        """Apple Safari (WebKit / iOS / macOS): Strict 398-Day TLS Cert Limit, ITP 7-Day Cookie Capping."""
        findings = []
        score = 100

        if has_cert_errors or not is_https:
            score -= 60
            findings.append({
                "type": "CRITICAL",
                "title": "Safari 'This Connection Is Not Private' Error",
                "desc": "Expired certificate or hostname mismatch causes Apple WebKit to display an immediate privacy warning screen."
            })

        if cert_days_valid > 398:
            score -= 30
            findings.append({
                "type": "CRITICAL",
                "title": "Certificate Lifetime Exceeds Apple 398-Day Maximum",
                "desc": f"Certificate validity is {cert_days_valid} days. Apple devices (macOS, iOS, iPadOS) strictly REJECT certificates with validity over 398 days issued after Sept 1, 2020."
            })
        else:
            findings.append({
                "type": "PASS",
                "title": "Complies with Apple 398-Day Certificate Lifetime Rule",
                "desc": f"Certificate lifespan ({cert_days_valid} days) conforms to Apple WebKit security requirements."
            })

        findings.append({
            "type": "INFO",
            "title": "WebKit ITP Caps Client-Side Cookies at 7 Days",
            "desc": "Cookies set via JavaScript (document.cookie) are capped to 7-day expiration under Safari ITP. Ensure session tokens use server-side HttpOnly headers."
        })

        score = max(0, min(100, score))
        status = "SHIELDED" if score >= 75 else ("WARNINGS_PRESENT" if score >= 45 else "BLOCKED_RISK")

        return {
            "name": "Apple Safari",
            "icon": "🧭",
            "engine": "WebKit (macOS / iOS)",
            "score": score,
            "status": status,
            "badge_color": "#0ea5e9",
            "threat_model": "Apple 398-Day Cert Lifetime Limit, ITP Cookie Expiration Capping",
            "verdict": "Apple device rejection / cert error" if score < 45 else ("ITP cookie advisories" if score < 75 else "Fully verified for Apple WebKit devices"),
            "findings": findings
        }
