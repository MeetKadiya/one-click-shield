import re
from typing import Dict, Any, List, Optional


class HeadersScanner:
    """
    Evaluates HTTP Security Headers for:
    - Presence and strength (HSTS, CSP, XFO, nosniff, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP)
    - Contradictions and conflicting directives (e.g., XFO vs CSP frame-ancestors, duplicate conflicting headers)
    - Breaking changes and deprecated/dangerous directives (X-XSS-Protection, Expect-CT, HPKP)
    """

    CORE_HEADERS = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "severity_if_missing": "HIGH",
            "recommended": "max-age=31536000; includeSubDomains; preload",
            "purpose": "Enforces HTTPS connections and prevents SSL stripping attacks."
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "severity_if_missing": "HIGH",
            "recommended": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';",
            "purpose": "Restricts trusted resource origins to mitigate Cross-Site Scripting (XSS) and data injection."
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity_if_missing": "MEDIUM",
            "recommended": "nosniff",
            "purpose": "Prevents browsers from MIME-sniffing a response away from the declared content-type."
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity_if_missing": "MEDIUM",
            "recommended": "DENY",
            "purpose": "Prevents clickjacking by disabling embedding inside <iframe> or <frame> elements."
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity_if_missing": "LOW",
            "recommended": "strict-origin-when-cross-origin",
            "purpose": "Controls how much referrer information is sent with requests to external origins."
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity_if_missing": "LOW",
            "recommended": "camera=(), microphone=(), geolocation=()",
            "purpose": "Restricts browser features and hardware APIs like camera, mic, and geolocation."
        },
        "cross-origin-opener-policy": {
            "name": "Cross-Origin-Opener-Policy (COOP)",
            "severity_if_missing": "LOW",
            "recommended": "same-origin",
            "purpose": "Isolates the browsing context to defend against Spectre-like cross-origin attacks."
        },
        "cross-origin-embedder-policy": {
            "name": "Cross-Origin-Embedder-Policy (COEP)",
            "severity_if_missing": "INFO",
            "recommended": "require-corp",
            "purpose": "Prevents a document from loading cross-origin resources that do not explicitly grant permission."
        },
        "cross-origin-resource-policy": {
            "name": "Cross-Origin-Resource-Policy (CORP)",
            "severity_if_missing": "INFO",
            "recommended": "same-origin",
            "purpose": "Blocks other domains from loading this resource directly via <img> or <script>."
        }
    }

    def scan(self, headers_dict: Dict[str, str], is_https: bool = True) -> Dict[str, Any]:
        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers_dict.items()}

        results: Dict[str, Any] = {
            "raw_headers": headers_dict,
            "present_headers": {},
            "missing_headers": [],
            "contradictions": [],
            "breaking_changes": [],
            "issues": [],
            "csp_breakdown": None,
            "hsts_breakdown": None
        }

        # 1. Inspect presence of core headers
        has_csp_enforced = "content-security-policy" in norm_headers
        has_csp_report_only = "content-security-policy-report-only" in norm_headers

        for h_key, meta in self.CORE_HEADERS.items():
            if h_key in norm_headers:
                val = norm_headers[h_key]
                results["present_headers"][h_key] = {
                    "name": meta["name"],
                    "value": val,
                    "recommended": meta["recommended"],
                    "purpose": meta["purpose"]
                }
            elif h_key == "content-security-policy" and has_csp_report_only:
                # CSP is deployed in report-only mode
                val = norm_headers["content-security-policy-report-only"]
                results["present_headers"]["content-security-policy-report-only"] = {
                    "name": "Content-Security-Policy-Report-Only (Staging Mode)",
                    "value": val,
                    "recommended": "Migrate to enforcing 'Content-Security-Policy' once violation logs are verified",
                    "purpose": "Monitors and reports CSP policy violations without actively blocking resources."
                }
                results["issues"].append({
                    "id": "csp-report-only-mode",
                    "severity": "LOW",
                    "title": "CSP Running in Report-Only Mode",
                    "description": "Content-Security-Policy-Report-Only is configured. The policy is actively evaluated for violations but does not actively enforce resource blocking.",
                    "impact": "Protective rules do not block malicious XSS injections until migrated to enforce mode."
                })
            else:
                results["missing_headers"].append({
                    "header": h_key,
                    "name": meta["name"],
                    "severity": meta["severity_if_missing"],
                    "recommended": meta["recommended"],
                    "purpose": meta["purpose"]
                })
                results["issues"].append({
                    "id": f"missing-{h_key}",
                    "severity": meta["severity_if_missing"],
                    "title": f"Missing Security Header: {meta['name']}",
                    "description": f"The response is missing '{h_key}'. {meta['purpose']}",
                    "impact": f"Leaves application exposed to attacks normally mitigated by {meta['name']}."
                })

        # 2. Detailed HSTS Inspection
        if "strict-transport-security" in norm_headers:
            hsts_val = norm_headers["strict-transport-security"]
            hsts_info = self._analyze_hsts(hsts_val, is_https)
            results["hsts_breakdown"] = hsts_info
            results["issues"].extend(hsts_info.get("issues", []))

        # 3. Detailed CSP Inspection (enforced or report-only)
        csp_header_key = "content-security-policy" if has_csp_enforced else ("content-security-policy-report-only" if has_csp_report_only else None)
        if csp_header_key:
            csp_val = norm_headers[csp_header_key]
            csp_info = self._analyze_csp(csp_val)
            results["csp_breakdown"] = csp_info
            results["issues"].extend(csp_info.get("issues", []))

        # 4. Check for Contradictions & Conflicts
        contradictions = self._detect_contradictions(norm_headers)
        results["contradictions"] = contradictions
        results["issues"].extend(contradictions)

        # 5. Check for Deprecations & Breaking Changes
        deprecations = self._detect_deprecations(norm_headers)
        results["breaking_changes"] = deprecations
        results["issues"].extend(deprecations)

        # 6. Check Information Disclosure Headers
        info_leak_issues = self._check_info_disclosure(norm_headers)
        results["issues"].extend(info_leak_issues)

        return results

    def _analyze_hsts(self, hsts_value: str, is_https: bool) -> Dict[str, Any]:
        info = {
            "value": hsts_value,
            "max_age": None,
            "include_subdomains": False,
            "preload": False,
            "issues": []
        }

        # Check max-age
        match = re.search(r"max-age=(\d+)", hsts_value, re.IGNORECASE)
        if match:
            max_age = int(match.group(1))
            info["max_age"] = max_age
            # recommended min is 180 days (15552000s) or 1 year (31536000s)
            if max_age < 15552000:
                info["issues"].append({
                    "id": "hsts-short-max-age",
                    "severity": "MEDIUM",
                    "title": "HSTS Max-Age Is Too Short",
                    "description": f"HSTS max-age is set to {max_age} seconds ({max_age // 86400} days). Recommended is at least 31536000 (1 year).",
                    "impact": "Visitors who do not return within this short window are exposed to SSL stripping attacks on their next visit."
                })
        else:
            info["issues"].append({
                "id": "hsts-missing-max-age",
                "severity": "HIGH",
                "title": "HSTS Header Missing max-age Directive",
                "description": f"HSTS header '{hsts_value}' has no valid max-age directive and will be ignored by browsers.",
                "impact": "HSTS protection is completely inactive."
            })

        if "includesubdomains" in hsts_value.lower():
            info["include_subdomains"] = True
        else:
            info["issues"].append({
                "id": "hsts-missing-subdomains",
                "severity": "LOW",
                "title": "HSTS Does Not Protect Subdomains",
                "description": "HSTS does not include 'includeSubDomains'.",
                "impact": "Subdomains remain vulnerable to protocol downgrade attacks."
            })

        if "preload" in hsts_value.lower():
            info["preload"] = True

        return info

    def _analyze_csp(self, csp_value: str) -> Dict[str, Any]:
        directives: Dict[str, List[str]] = {}
        issues: List[Dict[str, Any]] = []

        parts = csp_value.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            dir_name = tokens[0].lower()
            dir_vals = tokens[1:] if len(tokens) > 1 else []
            directives[dir_name] = dir_vals

        # Check for default-src
        if "default-src" not in directives:
            issues.append({
                "id": "csp-missing-default-src",
                "severity": "MEDIUM",
                "title": "CSP Missing default-src Fallback",
                "description": "Content-Security-Policy does not define a 'default-src' directive.",
                "impact": "Unspecified resource types fall back to unconstrained loading, weakening defense-in-depth."
            })

        # Check for unsafe-inline and unsafe-eval
        script_sources = directives.get("script-src", directives.get("default-src", []))
        if "'unsafe-inline'" in script_sources:
            issues.append({
                "id": "csp-unsafe-inline",
                "severity": "HIGH",
                "title": "CSP Allows 'unsafe-inline' Scripts",
                "description": "Content-Security-Policy permits inline JavaScript execution ('unsafe-inline').",
                "impact": "Enables attackers to execute stored or reflected Cross-Site Scripting (XSS) payloads."
            })

        if "'unsafe-eval'" in script_sources:
            issues.append({
                "id": "csp-unsafe-eval",
                "severity": "MEDIUM",
                "title": "CSP Allows 'unsafe-eval'",
                "description": "Content-Security-Policy enables eval() and dynamic code generation from strings.",
                "impact": "Increases exploitability of DOM-based XSS and string-to-code vulnerabilities."
            })

        # Check for wildcard origins in script-src or default-src
        if "*" in script_sources:
            issues.append({
                "id": "csp-wildcard-source",
                "severity": "HIGH",
                "title": "CSP Allows Scripts From Any Origin (*)",
                "description": "Content-Security-Policy uses wildcard '*' for script-src, permitting scripts from all external domains.",
                "impact": "Completely negates origin-based script restrictions."
            })

        # Check object-src
        object_sources = directives.get("object-src", directives.get("default-src", []))
        if "'none'" not in object_sources:
            issues.append({
                "id": "csp-object-src-not-none",
                "severity": "LOW",
                "title": "CSP object-src Is Not 'none'",
                "description": "Plugin execution (<object>, <embed>, <applet>) is not explicitly forbidden.",
                "impact": "Legacy browser plugin vulnerabilities (Flash, Java) could be triggered."
            })

        # Check base-uri
        if "base-uri" not in directives:
            issues.append({
                "id": "csp-missing-base-uri",
                "severity": "LOW",
                "title": "CSP Missing base-uri Directive",
                "description": "Content-Security-Policy does not restrict the document base URL.",
                "impact": "Attackers may inject <base href='...'> tags to hijack relative script and asset URLs."
            })

        return {
            "directives": directives,
            "raw": csp_value,
            "issues": issues
        }

    def _detect_contradictions(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        contradictions = []

        # Contradiction 1: X-Frame-Options vs CSP frame-ancestors
        xfo = headers.get("x-frame-options", "").upper().strip()
        csp = headers.get("content-security-policy", "")
        csp_has_fa = "frame-ancestors" in csp.lower()

        if xfo and csp_has_fa:
            # Extract frame-ancestors value
            fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
            fa_val = fa_match.group(1).strip() if fa_match else ""

            # Check divergence: XFO DENY vs CSP allowing 'self' or third-parties
            if xfo == "DENY" and ("'self'" in fa_val or "http" in fa_val):
                contradictions.append({
                    "id": "contradiction-xfo-vs-csp-frame-ancestors",
                    "severity": "MEDIUM",
                    "title": "Contradictory Framing Policy: XFO vs CSP",
                    "description": f"X-Frame-Options is set to '{xfo}' (blocking all framing), but CSP 'frame-ancestors' allows '{fa_val}'.",
                    "impact": "Modern browsers follow CSP (allowing framing), whereas older browsers enforce XFO (blocking framing). This causes inconsistent framing behavior across different clients."
                })
            elif xfo == "SAMEORIGIN" and "'none'" in fa_val:
                contradictions.append({
                    "id": "contradiction-xfo-sameorigin-vs-csp-none",
                    "severity": "MEDIUM",
                    "title": "Contradictory Framing Policy: XFO SAMEORIGIN vs CSP none",
                    "description": "X-Frame-Options permits SAMEORIGIN framing, but CSP 'frame-ancestors' specifies 'none'.",
                    "impact": "Clients will behave inconsistently depending on whether they support CSP Level 2."
                })

        # Contradiction 2: CSP unsafe-inline alongside nonce or sha
        if csp:
            has_nonce_or_hash = "nonce-" in csp or "sha256-" in csp or "sha384-" in csp or "sha512-" in csp
            has_unsafe_inline = "'unsafe-inline'" in csp
            if has_nonce_or_hash and has_unsafe_inline:
                contradictions.append({
                    "id": "contradiction-csp-nonce-with-unsafe-inline",
                    "severity": "LOW",
                    "title": "CSP Redundancy / Contradiction: Nonce + unsafe-inline",
                    "description": "CSP specifies both a cryptographic nonce/hash and 'unsafe-inline' in the same directive.",
                    "impact": "In CSP Level 2+ browsers, 'unsafe-inline' is automatically ignored when a nonce/hash is present. This indicates incomplete or sloppy CSP migration."
                })

        return contradictions

    def _detect_deprecations(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        deprecations = []

        # Deprecation 1: X-XSS-Protection
        if "x-xss-protection" in headers:
            val = headers["x-xss-protection"].strip()
            if val.startswith("1"):
                deprecations.append({
                    "id": "deprecated-x-xss-protection-enabled",
                    "severity": "MEDIUM",
                    "title": "Deprecated & Risky Header: X-XSS-Protection",
                    "description": f"Header is set to '{val}'. The legacy browser XSS Auditor is deprecated across Chrome, Safari, and Edge.",
                    "impact": "In older and unpatched browsers, the auditor itself introduced client-side vulnerabilities and data leaks. Modern recommendation is to set 'X-XSS-Protection: 0' or rely strictly on CSP."
                })

        # Deprecation 2: Expect-CT
        if "expect-ct" in headers:
            deprecations.append({
                "id": "deprecated-expect-ct",
                "severity": "INFO",
                "title": "Obsolete Header: Expect-CT",
                "description": "Expect-CT was deprecated in June 2022 because Certificate Transparency is now mandatory by default in all modern browsers.",
                "impact": "No longer supported by browsers; adds unnecessary HTTP response header bloat."
            })

        # Deprecation 3: Public-Key-Pins (HPKP)
        if "public-key-pins" in headers:
            deprecations.append({
                "id": "deprecated-hpkp",
                "severity": "HIGH",
                "title": "Dangerous Deprecated Header: Public-Key-Pins (HPKP)",
                "description": "HPKP has been deprecated and removed from modern web standards due to severe denial-of-service risks (hostage pins).",
                "impact": "Accidental misconfiguration can permanently render a domain inaccessible to users."
            })

        return deprecations

    def _check_info_disclosure(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        leaks = []
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

        for h in disclosure_headers:
            if h in headers:
                val = headers[h]
                leaks.append({
                    "id": f"info-disclosure-{h}",
                    "severity": "LOW",
                    "title": f"Server Banner Information Disclosure ({h.title()})",
                    "description": f"Server exposes implementation details via '{h}: {val}'.",
                    "impact": "Assists attackers in fingerprinting server OS, web server software, and framework versions to target specific known CVEs."
                })

        return leaks
