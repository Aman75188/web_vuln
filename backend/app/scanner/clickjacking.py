"""Checks whether the target can be framed (clickjacking)."""
from typing import List
import httpx
from app.models import Finding, Severity


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    try:
        resp = await client.get(target_url)
    except httpx.RequestError as e:
        return [
            Finding(
                module="clickjacking",
                title="Could not connect to target",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        ]

    xfo = resp.headers.get("X-Frame-Options", "")
    csp = resp.headers.get("Content-Security-Policy", "")

    protected = bool(xfo) or "frame-ancestors" in csp.lower()

    if protected:
        return [
            Finding(
                module="clickjacking",
                title="Framing is restricted",
                severity=Severity.INFO,
                description=f"Page sets X-Frame-Options='{xfo}' or a CSP frame-ancestors directive, which prevents clickjacking via iframes.",
                url=target_url,
            )
        ]

    return [
        Finding(
            module="clickjacking",
            title="Page can likely be framed (clickjacking risk)",
            severity=Severity.MEDIUM,
            description=(
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was found. "
                "An attacker could embed this page in a hidden iframe on a malicious site "
                "and trick users into clicking real UI elements (clickjacking)."
            ),
            recommendation="Set `X-Frame-Options: DENY`/`SAMEORIGIN` or CSP `frame-ancestors 'self'`.",
            url=target_url,
        )
    ]
