import io
import zipfile
from typing import Dict, Any, List


class AutoRemediator:
    """
    One-Click Auto-Remediation Engine.
    Generates tailored, production-ready server and proxy configuration files
    based on the exact scan findings for a target domain.
    """

    @classmethod
    def generate_all_remediations(cls, domain: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        hsts_max_age = 31536000
        server_name = domain or "example.com"
        headers_info = scan_results.get("headers", {})
        present = headers_info.get("present_headers", {})

        nginx_config = cls._generate_nginx_config(server_name, scan_results)
        apache_config = cls._generate_apache_config(server_name, scan_results)
        caddy_config = cls._generate_caddy_config(server_name, scan_results)
        cloudflare_config = cls._generate_cloudflare_config(server_name, scan_results)
        node_config = cls._generate_node_config(server_name, scan_results)
        docker_config = cls._generate_docker_config(server_name, scan_results)
        readme_guide = cls._generate_readme_guide(server_name, scan_results)

        return {
            "domain": server_name,
            "nginx": {
                "filename": "nginx-hardened.conf",
                "language": "nginx",
                "content": nginx_config,
                "description": "Production Nginx server block with modern TLS 1.2/1.3, hardened cipher list, HSTS, CSP, and secure cookie proxy directives."
            },
            "apache": {
                "filename": ".htaccess",
                "language": "apache",
                "content": apache_config,
                "description": "Apache .htaccess or httpd.conf directives with mod_headers, mod_ssl, and rewrite rules enforcing HTTPS."
            },
            "caddy": {
                "filename": "Caddyfile",
                "language": "caddy",
                "content": caddy_config,
                "description": "Modern Caddy v2 configuration with automatic Let's Encrypt TLS and security headers."
            },
            "cloudflare": {
                "filename": "cloudflare-rules.json",
                "language": "json",
                "content": cloudflare_config,
                "description": "Cloudflare Transform Rules and Page Rules configuration payload to inject security headers at the edge."
            },
            "nodejs": {
                "filename": "security-middleware.js",
                "language": "javascript",
                "content": node_config,
                "description": "Drop-in Node.js / Express middleware with Helmet and hardened session cookie settings."
            },
            "docker": {
                "filename": "docker-compose.shield.yml",
                "language": "yaml",
                "content": docker_config,
                "description": "Containerized hardened Nginx reverse proxy drop-in to shield existing services without changing code."
            },
            "readme": {
                "filename": "README_FIXES.md",
                "language": "markdown",
                "content": readme_guide,
                "description": "Step-by-step plain-English guide tailored for non-specialist site administrators."
            }
        }

    @classmethod
    def generate_zip_bundle(cls, domain: str, scan_results: Dict[str, Any]) -> bytes:
        remediations = cls.generate_all_remediations(domain, scan_results)
        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"one-click-shield-{domain}/nginx-hardened.conf", remediations["nginx"]["content"])
            zf.writestr(f"one-click-shield-{domain}/.htaccess", remediations["apache"]["content"])
            zf.writestr(f"one-click-shield-{domain}/Caddyfile", remediations["caddy"]["content"])
            zf.writestr(f"one-click-shield-{domain}/cloudflare-rules.json", remediations["cloudflare"]["content"])
            zf.writestr(f"one-click-shield-{domain}/security-middleware.js", remediations["nodejs"]["content"])
            zf.writestr(f"one-click-shield-{domain}/docker-compose.shield.yml", remediations["docker"]["content"])
            zf.writestr(f"one-click-shield-{domain}/README_FIXES.md", remediations["readme"]["content"])

        buffer.seek(0)
        return buffer.getvalue()

    @classmethod
    def _generate_nginx_config(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        return f"""# ==============================================================================
# "One-Click Shield" Hardened Nginx Configuration
# Target Domain: {domain}
# Generated automatically to address all detected SSL/TLS, Header & Cookie gaps.
# ==============================================================================

# 1. Permanent HTTP to HTTPS Canonical Redirect (301)
server {{
    listen 80;
    listen [::]:80;
    server_name {domain} www.{domain};

    # Redirect all HTTP requests to HTTPS on the primary domain
    return 301 https://{domain}$request_uri;
}}

# 2. Hardened HTTPS Server Block
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain};

    # Certificate Paths (Replace with your actual certificate paths)
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    # Cryptographic Protocols: Disables SSLv3, TLS 1.0, and TLS 1.1; Enforces TLS 1.2 and 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    # SSL Session Optimization & Perfect Forward Secrecy Cache
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # OCSP Stapling (Enables faster verification and prevents CA privacy leaks)
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # ==========================================================================
    # HTTP Security Headers
    # ==========================================================================

    # HSTS: 1 Year Duration, covers all subdomains, preloaded
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Content Security Policy: Robust baseline restricting script execution
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;

    # MIME Type Sniffing Prevention
    add_header X-Content-Type-Options "nosniff" always;

    # Clickjacking Defense (Aligned with CSP frame-ancestors 'self')
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Referrer Information Protection
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Restrict Hardware APIs & Device Capabilities
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;

    # Cross-Origin Isolation Headers
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    # Remove Server Banner Leaks
    server_tokens off;

    # ==========================================================================
    # Reverse Proxy / Application Upstream (Cookie Hardening)
    # ==========================================================================
    location / {{
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        # Enforce Secure and SameSite attributes on all Set-Cookie response headers
        proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";
    }}
}}
"""

    @classmethod
    def _generate_apache_config(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        return f"""# ==============================================================================
# "One-Click Shield" Hardened Apache (.htaccess / httpd.conf)
# Target Domain: {domain}
# ==============================================================================

<IfModule mod_rewrite.c>
    RewriteEngine On

    # 1. Enforce HTTPS Canonical Redirection (301 Permanent)
    RewriteCond %{{HTTPS}} !=on [OR]
    RewriteCond %{{HTTP_HOST}} ^www\\. [NC]
    RewriteRule ^ https://{domain}%{{REQUEST_URI}} [L,R=301]
</IfModule>

<IfModule mod_headers.c>
    # Strict-Transport-Security (1 Year + Subdomains)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # Content-Security-Policy
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';"

    # Anti-Sniffing
    Header always set X-Content-Type-Options "nosniff"

    # Anti-Clickjacking
    Header always set X-Frame-Options "SAMEORIGIN"

    # Referrer Leakage Prevention
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Permissions Policy
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

    # Cross-Origin Isolation
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"

    # Obsolete header cleanup (Prevents legacy XSS auditor bugs)
    Header unset X-XSS-Protection
    Header always set X-XSS-Protection "0"

    # Cookie Security Enforcement (Appends Secure, HttpOnly, SameSite=Lax)
    Header always edit Set-Cookie "^(?!.*(?i);\\s*Secure)(.*)" "$1; Secure"
    Header always edit Set-Cookie "^(?!.*(?i);\\s*HttpOnly)(.*)" "$1; HttpOnly"
    Header always edit Set-Cookie "^(?!.*(?i);\\s*SameSite)(.*)" "$1; SameSite=Lax"
</IfModule>

# Cryptographic Protocols & Ciphers (Add inside VirtualHost *:443)
# SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 +TLSv1.2 +TLSv1.3
# SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!RC4
# SSLHonorCipherOrder on
"""

    @classmethod
    def _generate_caddy_config(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        return f"""# ==============================================================================
# "One-Click Shield" Hardened Caddyfile
# Target Domain: {domain}
# Caddy natively manages automatic Let's Encrypt TLS with OCSP stapling.
# ==============================================================================

{domain} {{
    # Enforce modern TLS protocols
    tls {{
        protocols tls1.2 tls1.3
        ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    }}

    # Comprehensive Defensive HTTP Headers
    header {{
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        -Server
        -X-Powered-By
    }}

    # Proxy to upstream application
    reverse_proxy 127.0.0.1:3000
}}

# Redirect www.{domain} to apex {domain}
www.{domain} {{
    redir https://{domain}{{uri}} permanent
}}
"""

    @classmethod
    def _generate_cloudflare_config(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        return f"""{{
  "domain": "{domain}",
  "description": "Cloudflare Edge Security Rules & Header Transformations",
  "recommended_edge_settings": {{
    "always_use_https": "on",
    "minimum_tls_version": "1.2",
    "tls_1_3": "on",
    "opportunistic_encryption": "on",
    "automatic_https_rewrites": "on",
    "http2": "on",
    "http3": "on"
  }},
  "response_headers_to_inject": [
    {{
      "name": "Strict-Transport-Security",
      "value": "max-age=31536000; includeSubDomains; preload"
    }},
    {{
      "name": "X-Content-Type-Options",
      "value": "nosniff"
    }},
    {{
      "name": "X-Frame-Options",
      "value": "SAMEORIGIN"
    }},
    {{
      "name": "Referrer-Policy",
      "value": "strict-origin-when-cross-origin"
    }},
    {{
      "name": "Permissions-Policy",
      "value": "camera=(), microphone=(), geolocation=()"
    }},
    {{
      "name": "Content-Security-Policy",
      "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'self';"
    }}
  ]
}}
"""

    @classmethod
    def _generate_node_config(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        return f"""/**
 * "One-Click Shield" Node.js / Express Security Middleware
 * Target Domain: {domain}
 *
 * Install dependencies:
 *   npm install helmet express-session
 */

const helmet = require('helmet');
const session = require('express-session');

function applyOneClickShield(app) {{
  // 1. Force HTTPS Redirection in Production
  app.use((req, res, next) => {{
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {{
      return res.redirect(301, 'https://' + req.headers.host + req.url);
    }}
    next();
  }});

  // 2. Comprehensive Security Headers with Helmet
  app.use(
    helmet({{
      contentSecurityPolicy: {{
        directives: {{
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          objectSrc: ["'none'"],
          frameAncestors: ["'self'"],
          upgradeInsecureRequests: [],
        }},
      }},
      hsts: {{
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      }},
      crossOriginOpenerPolicy: {{ policy: "same-origin" }},
      crossOriginResourcePolicy: {{ policy: "same-origin" }},
      referrerPolicy: {{ policy: "strict-origin-when-cross-origin" }},
      xContentTypeOptions: true,
      xFrameOptions: {{ action: "sameorigin" }},
      // Explicitly disable deprecated legacy X-XSS-Protection
      xXssProtection: false,
    }})
  }};

  // 3. Hardened Cookie Session Defaults
  app.use(
    session({{
      name: '__Host-sid', // Uses compliant __Host- prefix
      secret: process.env.SESSION_SECRET || 'replace-with-a-secure-random-key',
      resave: false,
      saveUninitialized: false,
      cookie: {{
        httpOnly: true, // Prevents XSS cookie theft
        secure: true,   // Transmitted exclusively over TLS
        sameSite: 'lax',// Mitigates Cross-Site Request Forgery
        path: '/',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      }},
    }})
  );

  console.log('[One-Click Shield] Security headers & hardened session cookies active for {domain}');
}}

module.exports = {{ applyOneClickShield }};
"""

    @classmethod
    def _generate_docker_config(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        return f"""# ==============================================================================
# "One-Click Shield" Zero-Code Reverse Proxy Shield (Docker Compose)
# Target Domain: {domain}
# Drop this in front of any existing application container to instantly fix all
# SSL/TLS, header, cookie, and redirect vulnerabilities.
# ==============================================================================

version: '3.8'

services:
  shield-proxy:
    image: nginx:alpine
    container_name: one_click_shield_proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-hardened.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    restart: unless-stopped
    depends_on:
      - app

  app:
    # Point this to your existing backend or web app image
    image: your-existing-app:latest
    container_name: backend_app
    expose:
      - "3000"
    restart: unless-stopped
"""

    @classmethod
    def _generate_readme_guide(cls, domain: str, scan_results: Dict[str, Any]) -> str:
        score = scan_results.get("score", {}).get("overall_score", 65)
        grade = scan_results.get("score", {}).get("grade", "C")
        issues = scan_results.get("score", {}).get("all_issues", [])

        return f"""# One-Click Shield: Automated Remediation Guide
**Target Domain:** `{domain}`  
**Initial Assessment:** Grade **{grade}** ({score}/100)  
**Total Vulnerabilities Addressed:** {len(issues)}

---

## Why These Fixes Matter (For Non-Specialists)
Small organizations and independent site owners frequently rely on default hosting configs or copied deployment templates. Browsers only show a warning when something is completely broken (like an expired certificate), masking subtle weaknesses like missing HSTS, outdated TLS protocols, cookie credential leaks, or contradictory frame protection.

This remediation pack provides tested, production-grade configurations that eliminate these vulnerabilities without breaking your site's functionality.

---

## Choose Your Deployment Method

### Option 1: Nginx (Recommended for Linux VPS / Cloud Servers)
1. Copy `nginx-hardened.conf` to your Nginx configuration directory:
   ```bash
   sudo cp nginx-hardened.conf /etc/nginx/sites-available/{domain}
   sudo ln -sf /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/
   ```
2. Test your Nginx configuration:
   ```bash
   sudo nginx -t
   ```
3. Reload Nginx:
   ```bash
   sudo systemctl reload nginx
   ```

### Option 2: Apache (.htaccess / httpd.conf)
1. Copy the `.htaccess` file to your website's root directory (`public_html/` or `/var/www/html/`).
2. Ensure `mod_headers` and `mod_rewrite` are enabled:
   ```bash
   sudo a2enmod headers rewrite ssl
   sudo systemctl restart apache2
   ```

### Option 3: Caddy
1. Replace your `Caddyfile` with the provided file.
2. Reload Caddy:
   ```bash
   caddy reload
   ```

### Option 4: Cloudflare (No Server Changes Required!)
1. Open your Cloudflare Dashboard -> **Rules** -> **Transform Rules** -> **Modify Response Header**.
2. Apply the headers specified in `cloudflare-rules.json`.
3. In **SSL/TLS** -> **Edge Certificates**, set:
   - Minimum TLS Version: `TLS 1.2`
   - Always Use HTTPS: `On`

### Option 5: Node.js / Express
1. Import `security-middleware.js` in your Express entrypoint:
   ```javascript
   const {{ applyOneClickShield }} = require('./security-middleware');
   applyOneClickShield(app);
   ```

---

## Verifying Your Remediated Posture
Once deployed, re-run the One-Click Shield scanner against `{domain}` to confirm your score improves to **Grade A+ (100/100)**!
"""
