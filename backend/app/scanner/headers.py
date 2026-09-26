"""Checks for missing/misconfigured security-relevant HTTP response headers."""
from typing import List
import httpx
from app.models import Finding, Severity

CHECKS = [
    {
        "header": "Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "desc": "No Content-Security-Policy header found. CSP mitigates XSS and data-injection attacks by restricting sources of executable content.",
        "rec": "Add a CSP header, e.g. `default-src 'self'`, and tighten it per the resources your app actually needs.",
    },
    {
        "header": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "desc": "No X-Frame-Options header found. The page may be embeddable in an iframe, enabling clickjacking.",
        "rec": "Set `X-Frame-Options: DENY` or `SAMEORIGIN`, or use CSP `frame-ancestors`.",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "desc": "No X-Content-Type-Options header found. Browsers may MIME-sniff responses, which can enable content-type confusion attacks.",
        "rec": "Set `X-Content-Type-Options: nosniff`.",
    },
    {
        "header": "Strict-Transport-Security",
        "severity": Severity.MEDIUM,
        "desc": "No Strict-Transport-Security (HSTS) header found. Users could be downgraded to plain HTTP by a network attacker.",
        "rec": "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
    },
    {
        "header": "Referrer-Policy",
        "severity": Severity.INFO,
        "desc": "No Referrer-Policy header found. Full URLs (possibly with sensitive query params) may leak to third parties via the Referer header.",
        "rec": "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
    },
    {
        "header": "Permissions-Policy",
        "severity": Severity.INFO,
        "desc": "No Permissions-Policy header found. Browser features (camera, geolocation, etc.) are not explicitly restricted.",
        "rec": "Set a Permissions-Policy restricting features the app does not use.",
    },
]

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        resp = await client.get(target_url)
    except httpx.RequestError as e:
        return [
            Finding(
                module="headers",
                title="Could not connect to target",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        ]

    headers = resp.headers
    for check in CHECKS:
        if check["header"] not in headers:
            findings.append(
                Finding(
                    module="headers",
                    title=f"Missing {check['header']} header",
                    severity=check["severity"],
                    description=check["desc"],
                    recommendation=check["rec"],
                    url=target_url,
                )
            )

    for leaky in LEAKY_HEADERS:
        if leaky in headers:
            findings.append(
                Finding(
                    module="headers",
                    title=f"Information disclosure via {leaky} header",
                    severity=Severity.LOW,
                    description=f"The response reveals server/framework details: {leaky}: {headers[leaky]}",
                    evidence=f"{leaky}: {headers[leaky]}",
                    recommendation=f"Remove or mask the {leaky} header at the server/proxy level.",
                    url=target_url,
                )
            )

    if not findings:
        findings.append(
            Finding(
                module="headers",
                title="Security headers look reasonable",
                severity=Severity.INFO,
                description="No missing critical security headers were detected in this basic check.",
                url=target_url,
            )
        )
    return findings
