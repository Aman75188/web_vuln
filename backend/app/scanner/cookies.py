"""Checks Set-Cookie headers for Secure / HttpOnly / SameSite flags."""
from typing import List
import httpx
from app.models import Finding, Severity


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        resp = await client.get(target_url)
    except httpx.RequestError as e:
        return [
            Finding(
                module="cookies",
                title="Could not connect to target",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        ]

    raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not raw_cookies:
        raw_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"] if hasattr(resp.headers, "multi_items") else []

    if not raw_cookies:
        findings.append(
            Finding(
                module="cookies",
                title="No cookies observed",
                severity=Severity.INFO,
                description="The target did not set any cookies on this request; cookie-flag checks are not applicable.",
                url=target_url,
            )
        )
        return findings

    for cookie_str in raw_cookies:
        name = cookie_str.split("=", 1)[0].strip()
        lower = cookie_str.lower()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")

        if missing:
            findings.append(
                Finding(
                    module="cookies",
                    title=f"Cookie '{name}' missing flag(s): {', '.join(missing)}",
                    severity=Severity.MEDIUM if "HttpOnly" in missing or "Secure" in missing else Severity.LOW,
                    description=(
                        f"Cookie '{name}' is missing: {', '.join(missing)}. "
                        "Missing HttpOnly allows JS (e.g. via XSS) to read the cookie; "
                        "missing Secure allows it over plain HTTP; missing SameSite weakens CSRF defenses."
                    ),
                    evidence=cookie_str,
                    recommendation=f"Set {', '.join(missing)} on the '{name}' cookie.",
                    url=target_url,
                )
            )
        else:
            findings.append(
                Finding(
                    module="cookies",
                    title=f"Cookie '{name}' has recommended flags",
                    severity=Severity.INFO,
                    description=f"Cookie '{name}' correctly sets Secure, HttpOnly, and SameSite.",
                    url=target_url,
                )
            )

    return findings
