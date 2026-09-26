"""Basic error-based SQL injection detection on GET query parameters.

Sends a small set of benign syntax-breaking characters (', ", --) into each
query parameter and looks for known DB error signatures in the response.
This is intentionally shallow (no time-based/blind SQLi, no data extraction)
to stay non-destructive and appropriate for a college-project scanner.
"""
import re
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx
from app.models import Finding, Severity

PAYLOADS = ["'", "\"", "' OR '1'='1", "1' -- -"]

ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"pg_query\(\)|postgresql.*error", "PostgreSQL"),
    (r"sqlite3\.OperationalError|sqlite_error", "SQLite"),
    (r"ORA-\d{5}", "Oracle"),
    (r"SQLSTATE\[\d+\]", "Generic SQL (PDO)"),
]


def _detect_error(body: str) -> str | None:
    lowered = body.lower()
    for pattern, dbms in ERROR_SIGNATURES:
        if re.search(pattern, lowered, re.IGNORECASE):
            return dbms
    return None


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)

    if not qs:
        return [
            Finding(
                module="sqli",
                title="No query parameters to test",
                severity=Severity.INFO,
                description="This module only tests GET query-string parameters; none were found on the target URL.",
                url=target_url,
            )
        ]

    # Baseline response, to compare against
    try:
        baseline = await client.get(target_url)
    except httpx.RequestError as e:
        return [
            Finding(
                module="sqli",
                title="Could not connect to target",
                severity=Severity.INFO,
                description=str(e),
                url=target_url,
            )
        ]

    for param in qs:
        for payload in PAYLOADS:
            new_qs = {k: (payload if k == param else v[0]) for k, v in qs.items()}
            test_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            try:
                resp = await client.get(test_url)
            except httpx.RequestError:
                continue

            dbms = _detect_error(resp.text)
            if dbms and not _detect_error(baseline.text):
                findings.append(
                    Finding(
                        module="sqli",
                        title=f"Possible SQL injection in parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Injecting {payload!r} into '{param}' produced a response containing what looks "
                            f"like a {dbms} error message, which the baseline request did not show. This "
                            "suggests unsanitized input is being concatenated into a SQL query."
                        ),
                        evidence=f"Payload: {payload} | Suspected DBMS: {dbms}",
                        recommendation="Use parameterized queries / prepared statements everywhere; never concatenate user input into SQL.",
                        url=test_url,
                    )
                )
                break  # one confirmed finding per param is enough

    if not findings:
        findings.append(
            Finding(
                module="sqli",
                title="No error-based SQLi indicators found",
                severity=Severity.INFO,
                description=(
                    "No SQL error signatures were triggered by basic syntax-breaking payloads. "
                    "This does NOT rule out blind, time-based, or second-order SQL injection, which "
                    "this lightweight module does not test."
                ),
                url=target_url,
            )
        )
    return findings
