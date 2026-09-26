"""Checks HTML forms for anti-CSRF tokens and SameSite cookie protection."""
from typing import List
import httpx
from bs4 import BeautifulSoup
from app.models import Finding, Severity

TOKEN_NAME_HINTS = ["csrf", "_token", "authenticity_token", "xsrf", "nonce"]


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    try:
        resp = await client.get(target_url)
    except httpx.RequestError as e:
        return [
            Finding(
                module="csrf",
                title="Could not connect to target",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        ]

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")

    if not forms:
        return [
            Finding(
                module="csrf",
                title="No HTML forms found on this page",
                severity=Severity.INFO,
                description="CSRF token checks apply to forms; none were found on this page (app may be a JS/SPA using API calls instead).",
                url=target_url,
            )
        ]

    findings: List[Finding] = []
    for i, form in enumerate(forms):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or target_url
        if method == "get":
            continue  # GET forms shouldn't mutate state; CSRF risk is for state-changing (POST) forms

        hidden_inputs = form.find_all("input", attrs={"type": "hidden"})
        has_token = any(
            any(hint in (inp.get("name") or "").lower() for hint in TOKEN_NAME_HINTS)
            for inp in hidden_inputs
        )

        if has_token:
            findings.append(
                Finding(
                    module="csrf",
                    title=f"Form #{i+1} ({action}) includes a likely CSRF token",
                    severity=Severity.INFO,
                    description="A hidden input with a token-like name was found in this POST form.",
                    url=target_url,
                )
            )
        else:
            findings.append(
                Finding(
                    module="csrf",
                    title=f"Form #{i+1} ({action}) has no visible CSRF token",
                    severity=Severity.MEDIUM,
                    description=(
                        f"This POST form has no hidden field resembling a CSRF token. "
                        "If the app relies only on cookies for auth, it may be vulnerable to cross-site "
                        "request forgery unless SameSite cookies or another CSRF defense is in place."
                    ),
                    recommendation="Add a per-session/per-request CSRF token validated server-side, and set cookies with SameSite=Lax/Strict.",
                    url=target_url,
                )
            )

    return findings
