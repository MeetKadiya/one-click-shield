from typing import Dict, Any, List


class ScoringEngine:
    """
    Calculates unified security score, letter grades, category breakdowns,
    and plain-English posture summaries.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 12,
        "MEDIUM": 6,
        "LOW": 2,
        "INFO": 0
    }

    @classmethod
    def calculate_score(
        cls,
        ssl_result: Dict[str, Any],
        headers_result: Dict[str, Any],
        cookies_result: Dict[str, Any],
        edge_cases_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Collect all issues across categories
        all_issues: List[Dict[str, Any]] = []

        for issue in ssl_result.get("issues", []):
            issue["category"] = "SSL/TLS"
            all_issues.append(issue)

        for issue in headers_result.get("issues", []):
            issue["category"] = "Security Headers"
            all_issues.append(issue)

        for issue in cookies_result.get("issues", []):
            issue["category"] = "Cookies & Session"
            all_issues.append(issue)

        for issue in edge_cases_result.get("issues", []):
            issue["category"] = "Edge Cases & DNS"
            all_issues.append(issue)

        # Count severities
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        for issue in all_issues:
            sev = issue.get("severity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate Category scores (0-100)
        def cat_score(cat_name: str) -> int:
            cat_issues = [i for i in all_issues if i.get("category") == cat_name]
            deduct = sum(cls.SEVERITY_WEIGHTS.get(i.get("severity", "INFO").upper(), 0) for i in cat_issues)
            return max(0, min(100, 100 - deduct))

        ssl_score = cat_score("SSL/TLS")
        headers_score = cat_score("Security Headers")
        cookies_score = cat_score("Cookies & Session")
        edge_score = cat_score("Edge Cases & DNS")

        # Industry-standard composite weighted scoring
        # SSL/TLS (35%), Headers (25%), Cookies (20%), Edge Cases (20%)
        overall_score = round(
            ssl_score * 0.35 +
            headers_score * 0.25 +
            cookies_score * 0.20 +
            edge_score * 0.20
        )
        overall_score = max(0, min(100, overall_score))

        # Severity Caps & Quality Gates
        if severity_counts["CRITICAL"] > 0:
            # Critical vulnerability (e.g. expired cert, plaintext HTTP) caps at D/F
            overall_score = min(overall_score, 48)
        elif severity_counts["HIGH"] >= 4:
            # 4+ high vulnerabilities caps at C
            overall_score = min(overall_score, 68)
        elif severity_counts["HIGH"] >= 2:
            # 2+ high vulnerabilities caps at B
            overall_score = min(overall_score, 82)

        # Assign Grade
        if overall_score >= 90:
            grade = "A+"
            posture_status = "Hardened Fortress"
            posture_color = "#10b981"  # Emerald
        elif overall_score >= 80:
            grade = "A"
            posture_status = "Strong Posture"
            posture_color = "#22c55e"  # Green
        elif overall_score >= 70:
            grade = "B"
            posture_status = "Adequate (Defensive Gaps Present)"
            posture_color = "#eab308"  # Yellow
        elif overall_score >= 50:
            grade = "C"
            posture_status = "Vulnerable Configuration"
            posture_color = "#f97316"  # Orange
        elif overall_score >= 30:
            grade = "D"
            posture_status = "High Risk Exposure"
            posture_color = "#ef4444"  # Red
        else:
            grade = "F"
            posture_status = "Critical Security Failure"
            posture_color = "#b91c1c"  # Dark Red

        category_breakdown = {
            "ssl_tls": {
                "score": ssl_score,
                "label": "SSL / TLS & Protocols",
                "issues_count": len([i for i in all_issues if i.get("category") == "SSL/TLS"])
            },
            "headers": {
                "score": headers_score,
                "label": "HTTP Security Headers",
                "issues_count": len([i for i in all_issues if i.get("category") == "Security Headers"])
            },
            "cookies": {
                "score": cookies_score,
                "label": "Cookie & Session Protection",
                "issues_count": len([i for i in all_issues if i.get("category") == "Cookies & Session"])
            },
            "edge_cases": {
                "score": edge_score,
                "label": "Edge Cases, Redirects & DNS",
                "issues_count": len([i for i in all_issues if i.get("category") == "Edge Cases & DNS"])
            }
        }

        # Executive summary
        summary_text = cls._generate_executive_summary(overall_score, grade, severity_counts, all_issues)

        return {
            "overall_score": overall_score,
            "grade": grade,
            "posture_status": posture_status,
            "posture_color": posture_color,
            "severity_counts": severity_counts,
            "total_issues": len(all_issues),
            "category_breakdown": category_breakdown,
            "all_issues": sorted(
                all_issues,
                key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").index(x.get("severity", "INFO").upper())
            ),
            "executive_summary": summary_text
        }

    @classmethod
    def _generate_executive_summary(
        cls,
        score: int,
        grade: str,
        counts: Dict[str, int],
        issues: List[Dict[str, Any]]
    ) -> str:
        crits = counts["CRITICAL"]
        highs = counts["HIGH"]
        meds = counts["MEDIUM"]

        if score >= 90:
            return (
                f"The target demonstrates an exceptional security posture (Grade {grade}, Score {score}/100). "
                f"Modern TLS protocols, strict cryptographic suites, and defensive headers are properly aligned. "
                f"Minor recommendations remain to ensure future-proof compliance."
            )
        elif score >= 80:
            return (
                f"The target maintains a strong security posture (Grade {grade}, Score {score}/100). "
                f"Core encryption and defensive headers are well configured, with {highs} high-priority and {meds} medium-priority suggestions for defense-in-depth."
            )
        elif score >= 70:
            return (
                f"The target maintains an acceptable baseline (Grade {grade}, Score {score}/100), but has "
                f"{highs} high-priority and {meds} medium-priority configuration oversights. "
                f"Key areas of improvement include tightening Content-Security-Policy, HSTS directives, or cookie protection flags."
            )
        elif score >= 50:
            return (
                f"The target exhibits notable security vulnerabilities (Grade {grade}, Score {score}/100). "
                f"Identified {crits} critical and {highs} high risk issues. Attackers can leverage these weaknesses "
                f"for session hijacking, downgrade attacks, or cross-site scripting."
            )
        else:
            fail_reason = f"{crits} critical security failures" if crits > 0 else f"{highs} high-priority vulnerabilities"
            return (
                f"CRITICAL WARNING: The target scored {score}/100 (Grade {grade}) with {fail_reason}. "
                f"Immediate remediation is required to prevent credential interception, man-in-the-middle attacks, "
                f"and untrusted certificate warnings in modern web browsers."
            )
