import re
from typing import Dict, Any, List, Optional
from http.cookies import SimpleCookie


class CookiesScanner:
    """
    Audits HTTP Cookies for security attributes:
    - Missing flags: HttpOnly, Secure, SameSite, Partitioned
    - Cookie prefix standards: __Secure- and __Host- rules
    - Session identifier sensitivity and risk escalation
    - Lax/Strict/None SameSite CSRF exposure
    """

    KNOWN_SESSION_NAMES = {
        "phpsessid", "jsessionid", "aspsessionid", "connect.sid", "session",
        "sessionid", "sid", "auth", "authtoken", "token", "jwt", "access_token",
        "id_token", "remember_me", "remember_token", "laravel_session",
        "_session_id", "rack.session", "express:sess", "user_session"
    }

    def scan(self, raw_cookie_headers: List[str], url: str = "") -> Dict[str, Any]:
        cookies_list: List[Dict[str, Any]] = []
        issues: List[Dict[str, Any]] = []

        is_https = url.lower().startswith("https://") if url else True

        for header_val in raw_cookie_headers:
            cookie_data = self._parse_set_cookie(header_val)
            if not cookie_data:
                continue

            cookie_issues = self._evaluate_cookie(cookie_data, is_https)
            cookie_data["issues"] = cookie_issues
            cookies_list.append(cookie_data)
            issues.extend(cookie_issues)

        # Summary flags count
        total_cookies = len(cookies_list)
        missing_httponly_count = sum(1 for c in cookies_list if not c["httponly"])
        missing_secure_count = sum(1 for c in cookies_list if not c["secure"])
        missing_samesite_count = sum(1 for c in cookies_list if not c["samesite"])

        return {
            "total_cookies": total_cookies,
            "cookies": cookies_list,
            "missing_httponly_count": missing_httponly_count,
            "missing_secure_count": missing_secure_count,
            "missing_samesite_count": missing_samesite_count,
            "issues": issues
        }

    def _parse_set_cookie(self, header_val: str) -> Optional[Dict[str, Any]]:
        parts = [p.strip() for p in header_val.split(";")]
        if not parts:
            return None

        # First part is name=value
        first_token = parts[0]
        if "=" in first_token:
            name, value = first_token.split("=", 1)
        else:
            name = first_token
            value = ""

        name = name.strip()
        value = value.strip()

        data = {
            "name": name,
            "value": value[:15] + "..." if len(value) > 15 else value,
            "raw": header_val,
            "httponly": False,
            "secure": False,
            "samesite": None,
            "domain": None,
            "path": None,
            "max_age": None,
            "expires": None,
            "partitioned": False,
            "is_session_cookie": self._is_likely_session(name)
        }

        for attr in parts[1:]:
            attr_lower = attr.lower()
            if attr_lower == "httponly":
                data["httponly"] = True
            elif attr_lower == "secure":
                data["secure"] = True
            elif attr_lower == "partitioned":
                data["partitioned"] = True
            elif attr_lower.startswith("samesite"):
                if "=" in attr:
                    data["samesite"] = attr.split("=", 1)[1].strip()
                else:
                    data["samesite"] = "Lax"
            elif attr_lower.startswith("domain="):
                data["domain"] = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("path="):
                data["path"] = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("max-age="):
                data["max_age"] = attr.split("=", 1)[1].strip()
            elif attr_lower.startswith("expires="):
                data["expires"] = attr.split("=", 1)[1].strip()

        return data

    def _is_likely_session(self, name: str) -> bool:
        n = name.lower()
        if n in self.KNOWN_SESSION_NAMES:
            return True
        for pattern in ["sess", "auth", "token", "jwt", "login", "ticket"]:
            if pattern in n:
                return True
        return False

    def _evaluate_cookie(self, cookie: Dict[str, Any], is_https: bool) -> List[Dict[str, Any]]:
        c_issues: List[Dict[str, Any]] = []
        name = cookie["name"]
        is_sess = cookie["is_session_cookie"]

        # 1. HttpOnly Check
        if not cookie["httponly"]:
            severity = "HIGH" if is_sess else "MEDIUM"
            c_issues.append({
                "id": f"cookie-missing-httponly-{name}",
                "severity": severity,
                "title": f"Cookie '{name}' Missing HttpOnly Flag",
                "description": f"The cookie '{name}' is accessible via JavaScript (document.cookie).",
                "impact": "If the site suffers from Cross-Site Scripting (XSS), attackers can steal this cookie." +
                          (" Since this appears to be a session token, complete account takeover is possible." if is_sess else "")
            })

        # 2. Secure Flag Check
        if not cookie["secure"]:
            severity = "CRITICAL" if (is_sess and is_https) else "HIGH"
            c_issues.append({
                "id": f"cookie-missing-secure-{name}",
                "severity": severity,
                "title": f"Cookie '{name}' Missing Secure Flag",
                "description": f"The cookie '{name}' can be transmitted in cleartext over unencrypted HTTP connections.",
                "impact": "Network adversaries (e.g. on public Wi-Fi) can intercept and sniff the cookie via Man-In-The-Middle (MitM) attacks."
            })

        # 3. SameSite Flag Check
        samesite = (cookie["samesite"] or "").capitalize()
        if not samesite:
            c_issues.append({
                "id": f"cookie-missing-samesite-{name}",
                "severity": "MEDIUM",
                "title": f"Cookie '{name}' Missing SameSite Attribute",
                "description": f"The cookie '{name}' does not declare a SameSite attribute (Strict, Lax, or None).",
                "impact": "May allow the cookie to be sent on cross-site requests, increasing vulnerability to Cross-Site Request Forgery (CSRF)."
            })
        elif samesite == "None":
            if not cookie["secure"]:
                c_issues.append({
                    "id": f"cookie-samesite-none-insecure-{name}",
                    "severity": "HIGH",
                    "title": f"Cookie '{name}' Has SameSite=None Without Secure",
                    "description": "Cookies with 'SameSite=None' must also have the 'Secure' flag per RFC 6265bis.",
                    "impact": "Modern browsers reject this cookie, breaking functionality."
                })

        # 4. Cookie Prefix Compliance
        # __Secure- prefix requires Secure flag
        if name.startswith("__Secure-") and not cookie["secure"]:
            c_issues.append({
                "id": f"cookie-invalid-secure-prefix-{name}",
                "severity": "HIGH",
                "title": f"Cookie Prefix Violation: '{name}' Missing Secure Flag",
                "description": "Cookies prefixed with '__Secure-' must be declared with the 'Secure' flag.",
                "impact": "Browsers reject the cookie, resulting in authentication failures."
            })

        # __Host- prefix requires Secure flag, Path=/, and NO domain attribute
        if name.startswith("__Host-"):
            if not cookie["secure"]:
                c_issues.append({
                    "id": f"cookie-invalid-host-prefix-secure-{name}",
                    "severity": "HIGH",
                    "title": f"Cookie Prefix Violation: '{name}' Missing Secure Flag",
                    "description": "Cookies prefixed with '__Host-' must be set with the 'Secure' flag.",
                    "impact": "Browsers reject the cookie."
                })
            if cookie.get("domain"):
                c_issues.append({
                    "id": f"cookie-invalid-host-prefix-domain-{name}",
                    "severity": "HIGH",
                    "title": f"Cookie Prefix Violation: '{name}' Contains Domain Attribute",
                    "description": f"Cookies prefixed with '__Host-' must NOT include a Domain attribute (got domain='{cookie['domain']}').",
                    "impact": "Browsers reject the cookie to prevent cross-subdomain cookie manipulation."
                })
            if cookie.get("path") != "/":
                c_issues.append({
                    "id": f"cookie-invalid-host-prefix-path-{name}",
                    "severity": "MEDIUM",
                    "title": f"Cookie Prefix Violation: '{name}' Path Must Be '/'",
                    "description": f"Cookies prefixed with '__Host-' must have Path=/ (got '{cookie.get('path')}').",
                    "impact": "Browsers reject the cookie."
                })

        return c_issues
