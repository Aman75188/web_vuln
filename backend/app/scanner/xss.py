"""Probes GET forms/query params for reflected XSS using a benign, unique marker payload.

Non-destructive: the payload does not execute anything (no real <script> alert),
it only checks whether a unique canary string comes back un-encoded in the HTML,
which indicates the app is not escaping output.
"""
import uuid
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup
from app.models import Finding, Severity


def _build_marker() -> tuple[str, str]:
    canary = uuid.uuid4().hex[:8]
    payload = f"<xss-{canary}>"
    return canary, payload


async def _test_url_params(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings = []
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)
    if not qs:
        return findings

    for param in qs:
        canary, payload = _build_marker()
        new_qs = {k: (payload if k == param else v[0]) for k, v in qs.items()}
        test_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
        try:
            resp = await client.get(test_url)
        except httpx.RequestError:
            continue
        if payload in resp.text:
            findings.append(
                Finding(
                    module="xss",
                    title=f"Possible reflected XSS in query param '{param}'",
                    severity=Severity.HIGH,
                    description=(
                        f"A marker value injected into the '{param}' query parameter was reflected "
                        "back in the response HTML without encoding, suggesting the app does not "
                        "sanitize this input before rendering it."
                    ),
                    evidence=f"Requested {param}={payload!r}, found unescaped in response body.",
                    recommendation="HTML-encode all user-controlled output, or use a templating engine with autoescaping enabled.",
                    url=test_url,
                )
            )
    return findings


async def _test_forms(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings = []
    try:
        resp = await client.get(target_url)
    except httpx.RequestError:
        return findings

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")

    for form in forms:
        method = (form.get("method") or "get").lower()
        if method != "get":
            continue  # keep this module non-destructive: skip POST forms (could mutate data)

        action = form.get("action") or target_url
        inputs = form.find_all(["input", "textarea"])
        text_inputs = [
            inp for inp in inputs
            if (inp.get("type") or "text").lower() in ("text", "search", "url", "email", "")
            and inp.get("name")
        ]
        if not text_inputs:
            continue

        canary, payload = _build_marker()
        data = {inp.get("name"): payload for inp in text_inputs}
        target = action if action.startswith("http") else target_url

        try:
            test_resp = await client.get(target, params=data)
        except httpx.RequestError:
            continue

        if payload in test_resp.text:
            findings.append(
                Finding(
                    module="xss",
                    title=f"Possible reflected XSS via GET form targeting {action}",
                    severity=Severity.HIGH,
                    description="A marker value submitted through a GET form field was reflected unescaped in the response.",
                    evidence=f"Fields: {list(data.keys())}",
                    recommendation="HTML-encode all user-controlled output before rendering.",
                    url=str(test_resp.url),
                )
            )
    return findings


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    findings += await _test_url_params(client, target_url)
    findings += await _test_forms(client, target_url)

    if not findings:
        findings.append(
            Finding(
                module="xss",
                title="No reflected XSS found in this pass",
                severity=Severity.INFO,
                description=(
                    "No un-encoded reflection of the test marker was found in URL query params or GET forms. "
                    "This only covers reflected XSS in simple GET-based inputs — stored XSS, DOM XSS, and "
                    "POST-based inputs are not tested by this module."
                ),
                url=target_url,
            )
        )
    return findings
