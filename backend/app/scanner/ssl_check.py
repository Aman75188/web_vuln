"""Basic SSL/TLS checks: certificate validity, expiry, and HTTP->HTTPS redirect."""
import socket
import ssl
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

import httpx
from app.models import Finding, Severity


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme == "http":
        # Check if HTTPS is available and whether HTTP redirects to it
        try:
            https_resp = await client.get(f"https://{host}", timeout=6.0)
            findings.append(
                Finding(
                    module="ssl_tls",
                    title="Site reachable over HTTP; HTTPS also available",
                    severity=Severity.MEDIUM,
                    description=(
                        "The target was scanned over plain HTTP. HTTPS appears to be available too, "
                        "but you're testing the unencrypted endpoint — verify HTTP redirects to HTTPS in production."
                    ),
                    recommendation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
                    url=target_url,
                )
            )
        except httpx.RequestError:
            findings.append(
                Finding(
                    module="ssl_tls",
                    title="No HTTPS detected",
                    severity=Severity.HIGH,
                    description="The target does not appear to serve HTTPS at all. All traffic (including credentials) is sent in plaintext.",
                    recommendation="Deploy TLS (e.g. via Let's Encrypt) and redirect HTTP to HTTPS.",
                    url=target_url,
                )
            )
        return findings

    # HTTPS target: inspect certificate
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(
                        Finding(
                            module="ssl_tls",
                            title="TLS certificate has expired",
                            severity=Severity.CRITICAL,
                            description=f"Certificate expired on {not_after}.",
                            recommendation="Renew the TLS certificate immediately.",
                            url=target_url,
                        )
                    )
                elif days_left < 15:
                    findings.append(
                        Finding(
                            module="ssl_tls",
                            title="TLS certificate expiring soon",
                            severity=Severity.MEDIUM,
                            description=f"Certificate expires in {days_left} day(s) ({not_after}).",
                            recommendation="Renew the certificate before it expires.",
                            url=target_url,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            module="ssl_tls",
                            title="TLS certificate valid",
                            severity=Severity.INFO,
                            description=f"Certificate is valid, expires in {days_left} day(s) ({not_after}).",
                            url=target_url,
                        )
                    )

                proto = ssock.version()
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(
                        Finding(
                            module="ssl_tls",
                            title=f"Outdated TLS protocol negotiated: {proto}",
                            severity=Severity.HIGH,
                            description=f"The connection negotiated {proto}, which is deprecated and considered insecure.",
                            recommendation="Disable protocols below TLS 1.2 on the server.",
                            url=target_url,
                        )
                    )
    except ssl.SSLCertVerificationError as e:
        findings.append(
            Finding(
                module="ssl_tls",
                title="Certificate verification failed",
                severity=Severity.HIGH,
                description=f"The certificate could not be verified: {e}. It may be self-signed, expired, or for the wrong hostname.",
                recommendation="Use a certificate from a trusted CA that matches the hostname.",
                url=target_url,
            )
        )
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append(
            Finding(
                module="ssl_tls",
                title="Could not establish TLS connection",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        )

    return findings
