"""Lightweight technology fingerprinting from headers, HTML meta tags, and common file paths."""
import re
from typing import List
import httpx
from app.models import Finding, Severity

# (regex over html/headers, human label)
SIGNATURES = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"jquery[.-]?(\d+\.\d+\.\d+)", "jQuery (version-tagged)"),
    (r"Drupal", "Drupal"),
    (r"Joomla", "Joomla"),
    (r"laravel_session", "Laravel"),
    (r"X-Powered-By: PHP/(\d+\.\d+)", "PHP (version-tagged)"),
    (r"django", "Django"),
    (r"express", "Express.js"),
]

KNOWN_OLD_JQUERY = re.compile(r"jquery[.-](1\.[0-9]|2\.[01])\.\d+")


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        resp = await client.get(target_url)
    except httpx.RequestError as e:
        return [
            Finding(
                module="tech_detect",
                title="Could not connect to target",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        ]

    body = resp.text
    header_blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
    haystack = body + " " + header_blob

    detected = []
    for pattern, label in SIGNATURES:
        if re.search(pattern, haystack, re.IGNORECASE):
            detected.append(label)

    if detected:
        findings.append(
            Finding(
                module="tech_detect",
                title="Technologies detected",
                severity=Severity.INFO,
                description="Fingerprinting suggests this stack is in use: " + ", ".join(sorted(set(detected))),
                recommendation="Verify these components are on current, patched versions.",
                url=target_url,
            )
        )

    old_jquery = KNOWN_OLD_JQUERY.search(body)
    if old_jquery:
        findings.append(
            Finding(
                module="tech_detect",
                title="Outdated jQuery version referenced",
                severity=Severity.MEDIUM,
                description=f"Found a reference to an old jQuery version: {old_jquery.group(0)}. Old jQuery releases have known XSS issues.",
                evidence=old_jquery.group(0),
                recommendation="Upgrade jQuery to a current 3.x release.",
                url=target_url,
            )
        )

    if not findings:
        findings.append(
            Finding(
                module="tech_detect",
                title="No obvious technology fingerprints found",
                severity=Severity.INFO,
                description="This basic fingerprinting pass did not match known signatures. This does not mean the stack is secure — just that this shallow check found nothing.",
                url=target_url,
            )
        )

    return findings
