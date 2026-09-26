import ipaddress
import socket
from urllib.parse import urlparse

import httpx

# Basic SSRF / scope guard: block scanning of private, loopback, and link-local
# ranges unless explicitly allowed. This keeps the tool honest as an
# "authorized target only" scanner for a college project / lab environment.
ALLOWED_PRIVATE_TARGETS = {"127.0.0.1", "localhost", "::1"}


def is_target_allowed(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Only http:// and https:// URLs are supported."
        host = parsed.hostname
        if not host:
            return False, "Could not parse a hostname from the target URL."
        if host in ALLOWED_PRIVATE_TARGETS:
            return True, ""
        try:
            ip = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback:
                return True, ""
            if ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved:
                return False, (
                    f"'{host}' resolves to a private/internal IP ({ip}). "
                    "Scan it directly via localhost/lab network only, not through this guard."
                )
        except (socket.gaierror, ValueError):
            # DNS failure is reported later when the scan itself runs
            pass
        return True, ""
    except Exception as e:  # noqa: BLE001
        return False, f"URL validation error: {e}"


async def get_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=True,
        headers={"User-Agent": "CollegeVulnScanner/1.0 (authorized-testing-tool)"},
        verify=False,  # scanning self-signed lab targets is common; flagged in report
    )
