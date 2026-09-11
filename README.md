# 🛡️ One-Click Shield: Unified Web Security Scanner & Auto-Remediator

<div align="center">

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_18-61DAFB.svg?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Build-Vite_5-646CFF.svg?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Docker](https://img.shields.io/badge/Container-Docker-2496ED.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-11%2F11_Passing-success.svg?style=for-the-badge)](backend/tests)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

**Next-Generation Web Security Configuration Auditor, Multi-Browser Threat Engine, and Instant Auto-Remediation Synthesizer.**

*Engineered for Kalpvruksh 2.0 Mini Hackathon 2026 • Problem Statement P18: Hidden SSL/TLS and Web Security Configuration Weaknesses*

[🚀 Live Demo](#-deployment--hosting) • [✨ Key Features](#-key-features) • [🌐 Multi-Browser Matrix](#-multi-browser-compatibility--threat-matrix) • [⚡ Quick Start](#-quick-start) • [📋 Problem P18 Scope](#-problem-p18-vulnerability-matrix)

</div>

---

## 📖 Table of Contents
- [Executive Overview](#-executive-overview)
- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
- [🌐 Multi-Browser Compatibility & Threat Matrix](#-multi-browser-compatibility--threat-matrix)
- [Problem P18 Vulnerability Coverage](#-problem-p18-vulnerability-matrix)
- [🛠️ Auto-Remediation Engine (6-Stack Generation)](#️-auto-remediation-engine-6-stack-generation)
- [⚡ Quick Start & Usage](#-quick-start--usage)
  - [1. CLI Utility (`shield.py`)](#1-using-the-cli-tool-shieldpy)
  - [2. Interactive Web Dashboard](#2-running-the-web-dashboard)
  - [3. Automated Unit Testing](#3-automated-testing)
- [☁️ Free Cloud Deployment Guide (Render)](#️-free-cloud-deployment-guide-render)
- [🗄️ Database & Audit History](#️-database--audit-history)
- [👥 Team & Hackathon Context](#-team--hackathon-context)

---

## 🌟 Executive Overview

Most web developers and site administrators believe that displaying a green padlock icon in their browser address bar means their application is secure. **In reality, HTTPS is only the first line of defense.** Behind that padlock lies an intricate web of cryptographic parameters, protocol negotiations, HTTP header policies, cookie lifecycle boundaries, and domain-level trust anchors that are frequently misconfigured:
* **Obsolete Cryptographic Protocols**: TLS 1.0 and 1.1 enabled alongside modern protocols, exposing users to protocol downgrade attacks (POODLE, BEAST).
* **Missing Forward Secrecy & Broken Chains**: Static RSA key exchange and incomplete certificate chains causing client handshakes to fail.
* **Header Contradictions & Deprecations**: Discrepancies between `X-Frame-Options` and CSP `frame-ancestors`, permissive CSP (`'unsafe-inline'`), and deprecated `X-XSS-Protection` auditors.
* **Exposed Session Cookies**: Authentication tokens transmitted without `HttpOnly`, `Secure`, or `SameSite`, and violating RFC 6265bis `__Host-` / `__Secure-` prefix scoping.
* **Supply-Chain & DNS Exploits**: Active mixed content, CDN scripts lacking Subresource Integrity (SRI) hashes, and missing DNS CAA records allowing unauthorized certificate issuance.

### The Solution: One-Click Shield
**One-Click Shield** is a complete, dual-interface defensive cyber suite (Interactive Web Dashboard + Enterprise Scriptable CLI) that conducts a **simultaneous 4-pillar security audit in under 5 seconds**. Most importantly, it bridges the gap between vulnerability identification and operational remediation by **automatically synthesizing drop-in, production-grade configuration files** for **Nginx, Apache, Caddy, Cloudflare, Node.js, and Docker** with a **1-Click Downloadable ZIP Fix Pack**.

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ONE-CLICK SHIELD DEFENSE PIPELINE                               │
└────────────────────────────────────────────────────────────────────────────────────────┘
          │                                                    │
          ▼                                                    ▼
 1. CONCURRENT SCANNER PILLARS                        2. CALIBRATED SCORING & GATES
 ┌─────────────────────────────────────────┐          ┌───────────────────────────────────┐
 │ • SSLScanner: Sockets, TLS 1.0-1.3, PFS │          │ • SSL/TLS & Protocols (35%)       │
 │ • HeadersScanner: HSTS, CSP, XFO, COOP  │          │ • HTTP Security Headers (25%)     │
 │ • CookiesScanner: RFC 6265bis, __Host-  │          │ • Cookie & Session (20%)          │
 │ • EdgeCasesScanner: Redirects, SRI, CAA │          │ • Edge Cases, SRI & DNS (20%)     │
 └─────────────────────────────────────────┘          └───────────────────────────────────┘
          │                                                    │
          ▼                                                    ▼
 3. MULTI-BROWSER MATRIX ANALYZER                     4. AUTO-REMEDIATION SYNTHESIZER
 ┌─────────────────────────────────────────┐          ┌───────────────────────────────────┐
 │ • 🦁 Brave: Shields, Tracker Partition  │          │ • Nginx (nginx-hardened.conf)     │
 │ • 🧅 Tor: Exit-Node Sniffing, .onion v3 │          │ • Apache (.htaccess)              │
 │ • 🔴 Yandex: Protect Gateway & DNSSEC   │          │ • Caddy (Caddyfile)               │
 │ • 🌐 Chrome: HSTS Preload & SameSite    │          │ • Cloudflare (rules.json)         │
 │ • 🦊 Firefox: Total Cookie & Strict SRI │          │ • Node.js (security-middleware.js)│
 │ • 🧭 Safari: Apple 398-Day Cert Limit   │          │ • Docker (docker-compose.shield)  │
 └─────────────────────────────────────────┘          └───────────────────────────────────┘
```

---

## ✨ Key Features

- ⚡ **Sub-5-Second Asynchronous Audit**: Python `asyncio.gather` orchestrates real cryptographic socket probes, HTTP header inspections, DOM scraping, and DNS CAA queries concurrently.
- 🎯 **Zero False-Positive Quality Gates**:
  - Distinguishes modern RFC 8446 TLS 1.3 ciphers (which inherently enforce Forward Secrecy) from legacy ciphers.
  - Recognizes staging environments utilizing CSP `Content-Security-Policy-Report-Only` without unfairly penalizing scores.
  - Safely treats benign apex-to-www canonical redirects without misclassifying them as downgrade hops.
- 🌐 **Multi-Browser Threat Differentiation**: Evaluates targets across **6 distinct browser engines** (Brave, Tor, Yandex, Chrome, Firefox, Safari) rather than assuming a single monolithic browser client.
- 🛠️ **Instant 1-Click Fix Pack (.ZIP)**: Synthesizes syntactically verified, production-ready configuration files tailored to the target domain, complete with a plain-English `README_FIXES.md` deployment guide.
- 🗄️ **Persistent Audit Logging**: SQLite-backed database (`shield.db`) tracks historical scan scores, issue breakdowns, and posture trends across recurring audits.
- 📄 **Executive Client-Ready Reports**: In-browser printable PDF export and structured JSON download for compliance officers and security auditors.

---

## 🌐 Multi-Browser Compatibility & Threat Matrix

Different browsers enforce security boundaries differently. One-Click Shield audits target configurations against the unique threat models and enforcement behaviors of specialized browsers:

| Browser Engine | Core Engine | Unique Threat Vector & Defense Enforcement Audited |
| :--- | :--- | :--- |
| 🦁 **Brave Browser** | Chromium (Brave Core) | • **Brave Shields**: Flags unverified external CDN scripts subject to shield blocking.<br>• **Storage Partitioning**: Audits third-party tracker storage isolation.<br>• **Fingerprint Defense**: Audits `Permissions-Policy` hardware sensor locks. |
| 🧅 **Tor Browser** | Gecko (Tor Hardened) | • **Exit-Node Sniffing**: Identifies unencrypted plaintext HTTP traffic and mixed content readable by malicious exit relays.<br>• **SRI De-Anonymization**: Verifies script hashes to prevent CDN identity correlation.<br>• **Onion-Location**: Detects `.onion v3` hidden service discovery headers. |
| 🔴 **Yandex Browser** | Blink (Protect Engine) | • **Yandex Protect Gateway**: Flags untrusted/mismatched certs that trigger full-screen Red Block screens.<br>• **Wi-Fi DNS Hijacking**: Verifies DNSSEC cryptographic signatures for DNSCrypt protection on public Wi-Fi.<br>• **DNS CAA Authorization**: Restricts rogue CA issuance. |
| 🌐 **Google Chrome** | Chromium / Blink | • **HSTS Preload**: Verifies eligibility for hardcoded browser preload lists (`hstspreload.org`).<br>• **SameSite Defaults**: Audits cookies against Chrome's strict `SameSite=Lax` default policy.<br>• **Obsolete TLS Rejection**: Flags legacy protocols triggering `ERR_SSL_OBSOLETE_VERSION`. |
| 🦊 **Mozilla Firefox** | Gecko Engine | • **Total Cookie Protection**: Evaluates dCookie per-origin cookie jar isolation.<br>• **Strict SRI**: Flags tampered or unhashed scripts failing Gecko execution checks.<br>• **Mixed Active Content**: Rejects unencrypted script execution on HTTPS pages. |
| 🧭 **Apple Safari** | WebKit (macOS / iOS) | • **Apple 398-Day Rule**: Strictly enforces Apple's mandate rejecting certificates with validity > 398 days issued after Sept 1, 2020.<br>• **WebKit ITP**: Flags client-side JavaScript cookies (`document.cookie`) capped to 7-day expiration under Intelligent Tracking Prevention. |

---

## 📋 Problem P18 Vulnerability Matrix

One-Click Shield provides exhaustive diagnostic coverage across all **36 vulnerability classes** specified in Problem Track P18:

| Pillar | Vulnerabilities Audited | Real-World Attack Mitigated |
| :--- | :--- | :--- |
| **SSL / TLS & Crypto** | • TLS 1.0 & 1.1 active support<br>• Expired / Expiring (< 30 days) certs<br>• Hostname / SAN apex mismatch<br>• Missing intermediate CA chain<br>• Non-PFS cipher suites<br>• Missing OCSP stapling | Prevents POODLE, BEAST, SSL Stripping, MITM eavesdropping, and retroactive decryption of recorded network traffic. |
| **Security Headers** | • Missing or sub-year HSTS (`preload`)<br>• Missing or unsafe CSP (`'unsafe-inline'`, `'unsafe-eval'`)<br>• XFO vs CSP `frame-ancestors` conflicts<br>• Missing X-Content-Type-Options (`nosniff`)<br>• Deprecated `X-XSS-Protection` bugs<br>• Missing Referrer-Policy & COOP/COEP/CORP | Eliminates Cross-Site Scripting (XSS), Clickjacking, MIME-sniffing exploits, Spectre side-channel data leaks, and referer credential leakage. |
| **Cookie & Session** | • Missing `HttpOnly` flag on session tokens<br>• Missing `Secure` flag on HTTPS cookies<br>• Missing or permissive `SameSite` flags<br>• RFC 6265bis `__Host-` prefix violations<br>• RFC 6265bis `__Secure-` prefix violations | Stops Session Hijacking via DOM XSS, plaintext credential theft on public Wi-Fi, and Cross-Site Request Forgery (CSRF). |
| **Edge Cases & DNS** | • Insecure intermediate redirect hops<br>• Active & passive mixed content assets<br>• External CDN scripts lacking SRI hashes<br>• Missing DNS CAA (Certificate Authority Authorization)<br>• Missing DNSSEC validation<br>• Exposed staging/dev subdomains | Thwarts supply-chain CDN tampering, rogue certificate issuance by compromised regional CAs, DNS cache poisoning, and infrastructure recon. |

---

## 🛠️ Auto-Remediation Engine (6-Stack Generation)

One-Click Shield doesn't just list vulnerabilities—it generates **syntactically verified, production-ready configurations** for 6 major deployment stacks:

```
shield-fixes/
├── nginx-hardened.conf          # TLS 1.2/1.3, PFS ciphers, HSTS Preload, strict CSP, security headers
├── .htaccess                    # Apache mod_headers, mod_rewrite, and TLS hardening directives
├── Caddyfile                    # Caddy automatic HTTPS, modern TLS, and header injection
├── cloudflare-rules.json        # Cloudflare Edge Transformation Rules & WAF configurations
├── security-middleware.js       # Node.js Express Helmet and session cookie security middleware
├── docker-compose.shield.yml    # Drop-in Nginx reverse proxy wrapper for existing container workloads
└── README_FIXES.md              # Plain-English step-by-step deployment guide for system administrators
```

---

## ⚡ Quick Start & Usage

### 1. Using the CLI Tool (`shield.py`)

The CLI provides colored tables, real-time spinners, and deep browser engine diagnostics:

```bash
# Scan any domain directly (no prefix required)
python shield.py google.com

# Scan full URLs
python shield.py https://github.com

# Filter to a specific browser engine (e.g., Tor, Brave, Yandex)
python shield.py google.com --browser tor
python shield.py github.com --browser brave

# Run the simulated 36-vulnerability demonstration target (Offline)
python shield.py --demo

# Generate and export 6-stack auto-remediation configs to disk
python shield.py remediate badssl.com --out-dir ./fixes

# Export machine-readable JSON for CI/CD pipelines
python shield.py google.com --format json --output audit-report.json
```

### 2. Running the Web Dashboard

#### Option A: Single-Command Docker (Recommended)
```bash
docker compose up --build
```
* **Frontend Web Dashboard**: `http://localhost:3000`
* **Backend API & Swagger Docs**: `http://localhost:8000/docs`

#### Option B: Local Python + Node.js Environment

**Terminal 1 — Backend (FastAPI)**
```bash
cd backend
python -m venv venv
venv\Scripts\activate            # Windows (or: source venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend (React 18 + Vite)**
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:3000`.

### 3. Automated Testing
Run the complete automated unit and integration test suite:
```bash
python -m unittest discover -s backend/tests
```
```
...........
----------------------------------------------------------------------
Ran 11 tests in 25.027s

OK
```

---

## ☁️ Free Cloud Deployment Guide (Render)

One-Click Shield includes a root **multi-stage `Dockerfile`** that builds both the React frontend and FastAPI backend into a single container that runs **100% Free** on [Render](https://render.com):

1. Push this repository to GitHub:
   ```bash
   git branch -M main
   git add .
   git commit -m "feat: One-Click Shield production release"
   git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO>.git
   git push -u origin main
   ```
2. In [Render Dashboard](https://dashboard.render.com), click **New +** → **Web Service**.
3. Connect your GitHub repository.
4. Set:
   * **Runtime**: `Docker` *(Render automatically picks up the root `Dockerfile`)*
   * **Instance Type**: `Free` (`$0/month`)
   * **Environment Variables**: *Leave completely blank (zero secrets required!)*
5. Click **Create Web Service**. Your live web application will be accessible at:
   `https://<your-service-name>.onrender.com`

---

## 🗄️ Database & Audit History

All scan audits are automatically persisted in a local SQLite database (`backend/shield.db`). You can inspect recent audit logs using the included database utility:

```bash
# View recent 20 audits in terminal
python query_db.py

# Filter audits for a specific target
python query_db.py --target google.com --limit 5
```

---

## 👥 Team & Hackathon Context

* **Event**: Kalpvruksh 2.0 Mini Hackathon 2026
* **Problem Track**: Problem P18 — Hidden SSL/TLS and Web Security Configuration Weaknesses
* **Category**: CyberSecurity (Medium Track)
* **Goal**: Equip small organizations and independent web deployments with enterprise-grade cryptographic auditing, multi-browser defense analysis, and 1-click remediation.

---

<div align="center">
  <b>Built with ❤️ and engineered for a safer web.</b><br>
  <sub>Licensed under the MIT License.</sub>
</div>
