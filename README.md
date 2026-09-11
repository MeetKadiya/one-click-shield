# 🛡️ The "One-Click Shield" Unified Scanner & Auto-Remediator

> **Kalpvruksh 2.0 Mini Hackathon 2026**  
> **Problem Statement P18:** *Hidden SSL/TLS and Web Security Configuration Weaknesses*  
> **Category:** CyberSecurity (Medium)

---

## 🌟 Executive Summary

Small organizations and independent site owners often rely on default hosting configurations, plugins, or copied deployment settings. While a website may visually appear normal in web browsers, it often conceals severe architectural weaknesses:
- **Expired, expiring, or misconfigured SSL/TLS certificates** with missing intermediate certificate chains, hostname mismatches, or obsolete protocols (SSLv3, TLS 1.0, TLS 1.1).
- **Missing or contradictory security headers** (e.g. conflicting frame protection between XFO and CSP `frame-ancestors`, deprecated `X-XSS-Protection`, missing HSTS).
- **Insecure cookie attributes** (session tokens exposed without `HttpOnly`, `Secure`, or `SameSite`, and violation of `__Host-` / `__Secure-` prefix standards).
- **Subtle edge cases** (unencrypted HTTP hops in redirect chains, active/passive mixed content, external scripts lacking Subresource Integrity (SRI), missing DNS CAA records, and sensitive exposed subdomains).

**One-Click Shield** is an all-in-one defensive security solution featuring both an **interactive Web Application** and a **scriptable Local CLI Tool** (`shield.py`). It detects all weaknesses across the problem statement simultaneously and—most importantly—**automatically generates drop-in, production-grade configuration files** (Nginx, Apache, Caddy, Cloudflare, Node.js, and Docker) with a **One-Click Downloadable Remediation Pack (.zip)**.

---

## 🚀 Key Capabilities & Problem Scope Alignment

| Category | Problem Statement Requirement | One-Click Shield Engine Implementation |
| :--- | :--- | :--- |
| **SSL / TLS & Crypto** | Expiration, chains, hostnames, insecure protocols | • Computes remaining validity days & expiration warning alerts.<br>• Validates leaf, intermediate, and root certificate hierarchy; catches missing intermediates.<br>• Verifies Subject Alternative Names (SANs) and wildcard/apex matching.<br>• Probes active support for TLS 1.0, 1.1, 1.2, 1.3.<br>• Checks Perfect Forward Secrecy (PFS), cipher bit strength, and OCSP stapling. |
| **Security Headers** | Presence, contradictions, breaking changes | • Audits HSTS (max-age, subdomains, preload), CSP, X-Content-Type-Options, XFO, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.<br>• Detects contradictory policies (e.g. `X-Frame-Options: DENY` paired with CSP `frame-ancestors`).<br>• Flags deprecated/risky configurations (e.g. legacy `X-XSS-Protection` auditor bugs, obsolete `Expect-CT`, HPKP). |
| **Cookie & Session Security** | Missing flags (`HttpOnly`, `Secure`, `SameSite`) | • Flags unhardened cookies vulnerable to XSS theft or cleartext interception.<br>• Enforces cookie prefix specifications (`__Secure-` and `__Host-`).<br>• Detects sensitive authentication and session identifiers (JWT, PHPSESSID, auth tokens). |
| **Complex Edge Cases** | Redirects, embedded third-party content, subdomains | • Maps full HTTP-to-HTTPS redirect chains, permanent (301) vs temporary (302) status, and intermediate plaintext hops.<br>• Identifies active & passive mixed content (HTTP scripts/images on HTTPS).<br>• Catalogs third-party CDN dependencies and audits Subresource Integrity (SRI).<br>• Reconnoiters sensitive subdomains (`dev`, `admin`, `staging`, `api`).<br>• Queries DNS CAA (Certificate Authority Authorization) and DNSSEC. |
| **Auto-Remediator** | Actionable fixes for non-specialists | • Generates customized server configurations tailored to the detected domain: **Nginx** (`nginx-hardened.conf`), **Apache** (`.htaccess`), **Caddy** (`Caddyfile`), **Cloudflare** (`cloudflare-rules.json`), **Node.js / Express** (`security-middleware.js`), and **Docker Compose** (`docker-compose.shield.yml`).<br>• Generates **`README_FIXES.md`** plain-English deployment guide.<br>• **"Download Fix Bundle (.zip)"** one-click export. |

---

## 🛠️ System Architecture

```text
PROJECT/
├── backend/                  # FastAPI Python Scanning & Remediation Engine
│   ├── core/
│   │   ├── ssl_scanner.py         # Deep TLS handshake, certificate chains, SAN, protocols
│   │   ├── headers_scanner.py     # Header presence, contradiction & deprecation detection
│   │   ├── cookies_scanner.py     # Cookie attributes, prefix rules & session risk
│   │   ├── edge_cases_scanner.py  # Redirect chains, mixed content, SRI & DNS CAA
│   │   ├── scoring.py             # Weighted posture scoring (0-100) & Letter Grades (A+ to F)
│   │   ├── remediator.py          # Multi-platform hardened config generator & ZIP builder
│   │   └── engine.py              # Unified async orchestrator with curated demo presets
│   ├── tests/                     # Unit test suites (test_scanner.py, test_api.py)
│   ├── main.py                    # REST API server
│   └── requirements.txt
├── frontend/                 # Cyber-Shield React + Vite + Tailwind CSS Dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── SSLTab.jsx              # Interactive cert chain & protocol matrix
│   │   │   ├── HeadersTab.jsx          # Header matrix, contradictions & CSP analyzer
│   │   │   ├── CookiesTab.jsx          # Cookie security table & prefix compliance
│   │   │   ├── EdgeCasesTab.jsx        # Redirect chain visualizer & mixed content
│   │   │   ├── RemediationTab.jsx      # One-Click Auto-Remediator & ZIP pack
│   │   │   ├── AIExplainerTab.jsx      # Non-specialist plain-English advisor
│   │   │   └── AuditReportModal.jsx    # Printable & JSON audit report
│   │   ├── App.jsx
│   │   └── index.css
│   └── package.json
├── shield.py                 # Standalone Rich-powered CLI Tool
├── docker-compose.yaml       # Multi-container deployment specification
└── README.md
```

---

## ⚡ Quick Start Guide

### 1. Running the CLI Tool (Instant Assessment)

The CLI tool operates directly from the terminal with colored tables, status spinners, and automatic file generation:

```bash
# Scan a live domain
python shield.py scan example.com

# Scan the simulated vulnerable demonstration site (Problem P18 Showcase)
python shield.py scan vulnerable-demo.site --demo

# Generate and export hardened production configuration files to disk
python shield.py remediate example.com --out-dir ./fixes

# Interactive terminal mode
python shield.py
```

### 2. Running the Web Application

#### Option A: Local Development Server

**Step 1: Start the Backend (Terminal 1)**
```bash
cd backend
# Create virtual environment and install requirements
python -m venv venv
venv\Scripts\activate          # On Windows
# source venv/bin/activate     # On Linux / macOS
pip install -r requirements.txt

# Start FastAPI server
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Step 2: Start the Frontend (Terminal 2)**
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:3000`** in your browser.

#### Option B: Single-Command Docker Deployment
```bash
docker compose up --build
```
Open **`http://localhost:3000`** for the frontend, or **`http://localhost:8000/docs`** for interactive Swagger API docs.

---

## 🧪 Running Automated Tests

Run the backend unit and integration test suites:
```bash
# Unit tests for scanner modules, scoring, and remediation templates
python -m unittest discover -s backend/tests
```

All tests validate:
1. Header contradiction detection (e.g. XFO vs CSP `frame-ancestors`).
2. Deprecated `X-XSS-Protection` detection.
3. Cookie attribute and prefix rule violations (`__Host-` domain restrictions).
4. Weighted posture scoring and letter grade calculations.
5. End-to-end API scan and ZIP fix pack downloads.

---

## 🏆 Hackathon Demonstration Highlights

1. **Curated Showcase Targets**:
   - `⚠️ Vulnerable Demo (P18 Showcase)`: Simulates all flaws outlined in Problem P18 (expired certificate, hostname mismatch, obsolete TLS 1.0/1.1, missing HSTS, frame contradictions, session cookies missing `Secure` and `HttpOnly`, active mixed content script, missing DNS CAA).
   - `🛡️ Hardened Fortress (Grade A+)`: Demonstrates a hardened target with perfect TLS 1.3, strict CSP, preloaded HSTS, and compliant `__Host-` cookies.
2. **One-Click Auto-Remediator**:
   - Live syntax-highlighted code blocks for **Nginx**, **Apache**, **Caddy**, **Cloudflare**, **Node.js / Express**, and **Docker**.
   - Click **"Download Fix Bundle (.zip)"** to receive all configured files plus a `README_FIXES.md` guide customized for non-specialist website owners.
3. **Printable Executive Audit Report**:
   - Click **"Audit Report"** in the top bar to preview, print, or export a client-ready security audit in PDF or JSON format.

---

*Engineered with purpose for Kalpvruksh 2.0 Mini Hackathon 2026.*
