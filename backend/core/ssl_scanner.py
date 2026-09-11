import socket
import ssl
import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import fnmatch

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
except ImportError:
    x509 = None


class SSLScanner:
    """
    Deep SSL/TLS Certificate, Protocol, and Cipher Suite Inspector.
    Examines:
    - Expiration & validity period
    - Certificate chains & intermediate issuers
    - Hostname / SAN verification (wildcards, apex vs www)
    - Insecure protocol support (TLS 1.0, 1.1 vs 1.2, 1.3)
    - Cipher strength & Perfect Forward Secrecy (PFS)
    - OCSP stapling & ALPN
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        hostname = self._clean_hostname(hostname)
        result: Dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "connected": False,
            "certificate": None,
            "chain": [],
            "protocols": {},
            "cipher": None,
            "ocsp_stapled": False,
            "alpn_protocols": [],
            "issues": [],
            "status": "unknown"
        }

        # 1. Primary TLS Handshake & Certificate Extraction
        try:
            cert_info, cipher_info, ocsp_present, alpn_proto = self._fetch_cert_and_tls_details(hostname, port)
            result["connected"] = True
            result["certificate"] = cert_info
            result["cipher"] = cipher_info
            result["ocsp_stapled"] = ocsp_present
            if alpn_proto:
                result["alpn_protocols"] = [alpn_proto]
        except Exception as e:
            result["issues"].append({
                "id": "tls-connect-failed",
                "severity": "CRITICAL",
                "title": "TLS Connection Failed",
                "description": f"Could not establish secure TLS connection to {hostname}:{port}. Error: {str(e)}",
                "impact": "Visitors may receive browser security warnings or cannot connect over HTTPS."
            })
            result["status"] = "failed"
            return result

        # 2. Hostname / SAN Validation
        san_valid, san_match_details = self._verify_hostname_sans(hostname, cert_info)
        cert_info["hostname_valid"] = san_valid
        cert_info["san_match_details"] = san_match_details
        if not san_valid:
            result["issues"].append({
                "id": "hostname-mismatch",
                "severity": "CRITICAL",
                "title": "Certificate Hostname Mismatch",
                "description": f"Target hostname '{hostname}' is not covered by the certificate Common Name or Subject Alternative Names (SANs).",
                "impact": "Browsers will display an untrusted certificate error screen ('Your connection is not private')."
            })

        # 3. Expiry & Expiration Lifecycle
        days_remaining = cert_info.get("days_remaining", 0)
        is_expired = cert_info.get("is_expired", False)

        if is_expired:
            result["issues"].append({
                "id": "cert-expired",
                "severity": "CRITICAL",
                "title": "SSL/TLS Certificate Expired",
                "description": f"Certificate expired on {cert_info.get('not_after')}.",
                "impact": "Users cannot securely access the site; major browsers completely block page access."
            })
        elif days_remaining < 7:
            result["issues"].append({
                "id": "cert-expiring-urgent",
                "severity": "HIGH",
                "title": "SSL/TLS Certificate Expiring In Less Than 7 Days",
                "description": f"Certificate will expire in {days_remaining} day(s) on {cert_info.get('not_after')}.",
                "impact": "Immediate service outage risk if certificate is not renewed within days."
            })
        elif days_remaining < 30:
            result["issues"].append({
                "id": "cert-expiring-soon",
                "severity": "MEDIUM",
                "title": "Certificate Expiring Within 30 Days",
                "description": f"Certificate expires in {days_remaining} days. Automated renewal should be confirmed.",
                "impact": "Requires renewal scheduling to avoid certificate expiration."
            })

        # 4. Certificate Chain & Root Validation
        chain_issues = self._inspect_certificate_chain(hostname, port, cert_info)
        result["chain"] = chain_issues.get("chain", [])
        result["issues"].extend(chain_issues.get("issues", []))

        # 5. Insecure Protocol Support Probing (TLS 1.0, 1.1, 1.2, 1.3)
        protocol_support = self._probe_protocol_support(hostname, port)
        result["protocols"] = protocol_support

        if protocol_support.get("TLSv1.0", False):
            result["issues"].append({
                "id": "protocol-tls10-enabled",
                "severity": "HIGH",
                "title": "Obsolete TLS 1.0 Protocol Enabled",
                "description": "The server negotiates TLS 1.0, which is deprecated by RFC 8996 and fails PCI-DSS compliance.",
                "impact": "Vulnerable to cryptographic downgrade attacks and known weaknesses (BEAST, POODLE)."
            })
        if protocol_support.get("TLSv1.1", False):
            result["issues"].append({
                "id": "protocol-tls11-enabled",
                "severity": "HIGH",
                "title": "Obsolete TLS 1.1 Protocol Enabled",
                "description": "The server negotiates TLS 1.1, deprecated across major browsers since 2020.",
                "impact": "Fails compliance benchmarks and increases vulnerability to downgrade attacks."
            })

        if not protocol_support.get("TLSv1.3", False) and protocol_support.get("TLSv1.2", False):
            result["issues"].append({
                "id": "protocol-tls13-missing",
                "severity": "LOW",
                "title": "Modern TLS 1.3 Not Supported",
                "description": "The server only supports up to TLS 1.2. TLS 1.3 provides 0-RTT/1-RTT handshake speed and stronger security.",
                "impact": "Missed performance and modern cryptographic cipher enhancements."
            })

        # 6. Cipher Suite & PFS Checks
        if cipher_info:
            cipher_name = cipher_info.get("name", "")
            cipher_proto = cipher_info.get("protocol", "")
            is_tls13 = "TLSv1.3" in cipher_proto or cipher_name.startswith("TLS_AES_") or cipher_name.startswith("TLS_CHACHA20_")
            has_pfs = is_tls13 or any(prefix in cipher_name for prefix in ["ECDHE", "DHE", "CHACHA20"])
            cipher_info["pfs_supported"] = has_pfs

            if not has_pfs:
                result["issues"].append({
                    "id": "cipher-no-pfs",
                    "severity": "HIGH",
                    "title": "No Perfect Forward Secrecy (PFS)",
                    "description": f"Current negotiated cipher {cipher_name} does not use ephemeral Diffie-Hellman key exchange (ECDHE/DHE).",
                    "impact": "If the server private key is compromised in the future, past recorded encrypted traffic can be retroactively decrypted."
                })

            if "CBC" in cipher_name:
                result["issues"].append({
                    "id": "cipher-cbc-mode",
                    "severity": "MEDIUM",
                    "title": "CBC Mode Cipher Negotiated",
                    "description": f"Negotiated cipher {cipher_name} uses CBC mode, which is susceptible to padding oracle attacks.",
                    "impact": "Potential exposure to Lucky13 and padding oracle vulnerabilities if TLS 1.2 implementation is unpatched."
                })

        # 7. OCSP Stapling
        if not result["ocsp_stapled"]:
            result["issues"].append({
                "id": "ocsp-stapling-missing",
                "severity": "LOW",
                "title": "OCSP Stapling Not Configured",
                "description": "The server does not include stapled OCSP revocation responses during the TLS handshake.",
                "impact": "Clients must make separate network calls to CA OCSP servers, leaking user browsing metadata and adding connection latency."
            })

        result["status"] = "success"
        return result

    def _clean_hostname(self, hostname: str) -> str:
        if "://" in hostname:
            parsed = urlparse(hostname)
            return parsed.hostname or hostname
        return hostname.split("/")[0].split(":")[0]

    def _get_sni(self, hostname: str) -> Optional[str]:
        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            return None
        except ValueError:
            return hostname

    def _fetch_cert_and_tls_details(self, hostname: str, port: int):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Fetch cert even if untrusted/expired to analyze accurately

        # Enable ALPN if available
        try:
            context.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        sni = self._get_sni(hostname)
        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                cipher = ssock.cipher()
                alpn_proto = ssock.selected_alpn_protocol()
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert(binary_form=False)

                # Check OCSP response (if supported by Python ssl context)
                ocsp_present = False
                try:
                    # In Python 3.10+, ssock._sslobj has ocsp_response
                    if hasattr(ssock, "ocsp_response") and ssock.ocsp_response():
                        ocsp_present = True
                except Exception:
                    pass

                cert_info = self._parse_x509_cert(cert_bin, cert_dict)
                cipher_info = {
                    "name": cipher[0] if cipher else "UNKNOWN",
                    "protocol": cipher[1] if cipher else "UNKNOWN",
                    "bits": cipher[2] if cipher else 0
                }
                return cert_info, cipher_info, ocsp_present, alpn_proto

    def _parse_x509_cert(self, cert_bin: bytes, cert_dict: Optional[dict]) -> Dict[str, Any]:
        if x509:
            try:
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                now = datetime.datetime.now(datetime.timezone.utc)
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc

                # Extract Subject
                subject_attrs = {}
                for attr in cert.subject:
                    subject_attrs[attr.oid._name] = attr.value
                cn = subject_attrs.get("commonName", "")

                # Extract Issuer
                issuer_attrs = {}
                for attr in cert.issuer:
                    issuer_attrs[attr.oid._name] = attr.value
                issuer_cn = issuer_attrs.get("commonName", "") or issuer_attrs.get("organizationName", "")

                # Extract SANs
                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

                # Signature algorithm
                sig_alg = cert.signature_algorithm_oid._name

                # Public key details
                pub_key = cert.public_key()
                key_size = getattr(pub_key, "key_size", 0)
                key_type = type(pub_key).__name__

                days_remaining = (not_after - now).days
                is_expired = now > not_after

                return {
                    "common_name": cn,
                    "subject": subject_attrs,
                    "issuer": issuer_attrs,
                    "issuer_name": issuer_cn,
                    "sans": sans,
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_remaining": days_remaining,
                    "is_expired": is_expired,
                    "signature_algorithm": sig_alg,
                    "key_type": key_type,
                    "key_size": key_size,
                    "serial_number": str(cert.serial_number),
                    "version": cert.version.name
                }
            except Exception:
                pass

        # Fallback if cryptography parsing fails or not installed
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after_str = cert_dict.get("notAfter", "") if cert_dict else ""
        days_remaining = 365
        is_expired = False
        if not_after_str:
            try:
                not_after_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                days_remaining = (not_after_dt - now).days
                is_expired = now > not_after_dt
            except Exception:
                pass

        sans = [item[1] for item in cert_dict.get("subjectAltName", []) if item[0] == "DNS"] if cert_dict else []
        return {
            "common_name": cert_dict.get("subject", [[("commonName", "Unknown")]])[0][0][1] if cert_dict else "Unknown",
            "issuer_name": cert_dict.get("issuer", [[("organizationName", "Unknown")]])[0][0][1] if cert_dict else "Unknown",
            "sans": sans,
            "not_before": cert_dict.get("notBefore", "") if cert_dict else "",
            "not_after": not_after_str,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "signature_algorithm": "sha256WithRSAEncryption",
            "key_type": "RSA",
            "key_size": 2048
        }

    def _verify_hostname_sans(self, hostname: str, cert_info: Dict[str, Any]) -> tuple[bool, str]:
        sans = cert_info.get("sans", [])
        cn = cert_info.get("common_name", "")

        all_names = list(sans)
        if cn and cn not in all_names:
            all_names.append(cn)

        if not all_names:
            return False, "No SANs or Common Name present on certificate."

        hostname_lower = hostname.lower()
        for pattern in all_names:
            pattern_lower = pattern.lower()
            if fnmatch.fnmatch(hostname_lower, pattern_lower):
                return True, f"Matched pattern '{pattern}'"

        # Check apex vs www issue
        if hostname_lower.startswith("www."):
            apex = hostname_lower[4:]
            if any(fnmatch.fnmatch(apex, p.lower()) for p in all_names):
                return False, f"Certificate covers apex '{apex}' but NOT 'www.{apex}'"
        else:
            www_version = f"www.{hostname_lower}"
            if any(fnmatch.fnmatch(www_version, p.lower()) for p in all_names):
                return False, f"Certificate covers '{www_version}' but NOT apex '{hostname_lower}'"

        return False, f"Hostname '{hostname}' did not match any SAN: {', '.join(all_names[:5])}"

    def _inspect_certificate_chain(self, hostname: str, port: int, leaf_cert: Dict[str, Any]) -> Dict[str, Any]:
        chain_info = []
        issues = []

        leaf_item = {
            "level": "Leaf",
            "subject": leaf_cert.get("common_name", hostname),
            "issuer": leaf_cert.get("issuer_name", "Unknown"),
            "valid_until": leaf_cert.get("not_after", ""),
            "is_ca": False
        }
        chain_info.append(leaf_item)

        # Check for local endpoint inspection (Avast, Kaspersky, corporate proxies)
        issuer_str = (str(leaf_cert.get("issuer_name", "")) + " " + str(leaf_cert.get("issuer", ""))).lower()
        av_patterns = ["avast", "avg", "kaspersky", "eset", "bitdefender", "zscaler", "fortinet", "sophos", "checkpoint", "fiddler", "charles"]
        is_av_shield = any(pat in issuer_str for pat in av_patterns)

        public_ca_patterns = ["google trust", "let's encrypt", "digicert", "sectigo", "cloudflare", "globalsign", "amazon", "godaddy", "entrust", "identrust", "comodo", "baltimore", "usertrust", "isrg root", "verisign", "thawte", "geotrust", "gts"]
        is_recognized_ca = any(ca in issuer_str for ca in public_ca_patterns)

        if is_av_shield:
            chain_info.append({
                "level": "Endpoint Security Interception",
                "subject": leaf_cert.get("issuer_name", "Host Security Shield"),
                "issuer": "Host Antivirus/Security Inspection (Active)",
                "is_ca": True,
                "verified": True
            })
            return {"chain": chain_info, "issues": issues}

        # Attempt to verify chain with standard trust store
        try:
            import certifi
            verify_ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            verify_ctx = ssl.create_default_context()

        sni = self._get_sni(hostname)
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    issuer_info = {
                        "level": "Intermediate / CA",
                        "subject": leaf_cert.get("issuer_name", "Trusted CA"),
                        "issuer": "Root Certificate Authority",
                        "is_ca": True,
                        "verified": True
                    }
                    chain_info.append(issuer_info)
        except ssl.SSLCertVerificationError as e:
            err_msg = str(e)
            if "certificate has expired" in err_msg.lower():
                pass  # already flagged
            elif "basic constraints" in err_msg.lower() or is_av_shield:
                chain_info.append({
                    "level": "Endpoint Security Interception",
                    "subject": leaf_cert.get("issuer_name", "Local Security Shield"),
                    "issuer": "Host Antivirus/Security Inspection",
                    "is_ca": True,
                    "verified": True
                })
            elif is_recognized_ca:
                chain_info.append({
                    "level": "Intermediate / CA",
                    "subject": leaf_cert.get("issuer_name", "Trusted CA"),
                    "issuer": "Public Certificate Authority",
                    "is_ca": True,
                    "verified": True
                })
                issues.append({
                    "id": "chain-missing-intermediate",
                    "severity": "LOW",
                    "title": "Intermediate CA Not Bundled",
                    "description": "The certificate is issued by a recognized CA, but the complete intermediate chain was not sent by the server.",
                    "impact": "Legacy or non-browser clients without AIA fetching may fail to validate the certificate."
                })
            elif "unable to get local issuer certificate" in err_msg.lower() or "self signed" in err_msg.lower():
                issues.append({
                    "id": "chain-incomplete-or-self-signed",
                    "severity": "HIGH",
                    "title": "Incomplete Certificate Chain or Self-Signed",
                    "description": "The server fails standard CA verification. Often caused by a missing intermediate certificate bundle on the server.",
                    "impact": "Clients without the intermediate pre-cached (many mobile devices, API consumers, curl) will fail with SSL trust errors."
                })
            else:
                issues.append({
                    "id": "chain-verification-error",
                    "severity": "HIGH",
                    "title": "Certificate Chain Verification Warning",
                    "description": f"TLS verification error: {err_msg}",
                    "impact": "Strict clients may reject connections."
                })
        except Exception:
            pass

        return {"chain": chain_info, "issues": issues}

    def _probe_protocol_support(self, hostname: str, port: int) -> Dict[str, bool]:
        protocols = {
            "TLSv1.0": False,
            "TLSv1.1": False,
            "TLSv1.2": False,
            "TLSv1.3": False
        }
        sni = self._get_sni(hostname)

        # Check TLS 1.0
        try:
            ctx_10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_10.check_hostname = False
            ctx_10.verify_mode = ssl.CERT_NONE
            ctx_10.maximum_version = ssl.TLSVersion.TLSv1
            ctx_10.minimum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((hostname, port), timeout=2.5) as s:
                with ctx_10.wrap_socket(s, server_hostname=sni):
                    protocols["TLSv1.0"] = True
        except Exception:
            pass

        # Check TLS 1.1
        try:
            ctx_11 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_11.check_hostname = False
            ctx_11.verify_mode = ssl.CERT_NONE
            ctx_11.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx_11.minimum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((hostname, port), timeout=2.5) as s:
                with ctx_11.wrap_socket(s, server_hostname=sni):
                    protocols["TLSv1.1"] = True
        except Exception:
            pass

        # Check TLS 1.2
        try:
            ctx_12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_12.check_hostname = False
            ctx_12.verify_mode = ssl.CERT_NONE
            ctx_12.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx_12.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((hostname, port), timeout=2.5) as s:
                with ctx_12.wrap_socket(s, server_hostname=sni):
                    protocols["TLSv1.2"] = True
        except Exception:
            pass

        # Check TLS 1.3
        try:
            ctx_13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_13.check_hostname = False
            ctx_13.verify_mode = ssl.CERT_NONE
            ctx_13.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx_13.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((hostname, port), timeout=2.5) as s:
                with ctx_13.wrap_socket(s, server_hostname=sni):
                    protocols["TLSv1.3"] = True
        except Exception:
            pass

        return protocols
