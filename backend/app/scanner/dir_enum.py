"""Probes for commonly-exposed sensitive files/directories using a small wordlist."""
import asyncio
import os
from typing import List
from urllib.parse import urljoin

import httpx
from app.models import Finding, Severity

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "common_dirs.txt")

SENSITIVE_HINTS = {".env", "config.php", "config.bak", ".git", "backup", ".sql", "dump", "phpinfo", ".htpasswd"}

CONCURRENCY = 8


async def _check_path(client: httpx.AsyncClient, base_url: str, path: str) -> Finding | None:
    url = urljoin(base_url.rstrip("/") + "/", path)
    try:
        resp = await client.get(url)
    except httpx.RequestError:
        return None

    if resp.status_code == 200:
        is_sensitive = any(hint in path.lower() for hint in SENSITIVE_HINTS)
        return Finding(
            module="dir_enum",
            title=f"Exposed path found: /{path}",
            severity=Severity.HIGH if is_sensitive else Severity.LOW,
            description=(
                f"'/{path}' returned HTTP 200. "
                + ("This looks like a sensitive file/config that should not be public." if is_sensitive
                   else "Verify this path is meant to be publicly accessible.")
            ),
            evidence=f"GET {url} -> {resp.status_code}",
            recommendation="Remove public access to this path or restrict it via server config / auth.",
            url=url,
        )
    return None


async def run(client: httpx.AsyncClient, target_url: str) -> List[Finding]:
    try:
        with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
            words = [w.strip() for w in f if w.strip()]
    except OSError:
        return [
            Finding(
                module="dir_enum",
                title="Wordlist not found",
                severity=Severity.INFO,
                description="Could not load the directory wordlist file.",
                url=target_url,
            )
        ]

    sem = asyncio.Semaphore(CONCURRENCY)

    async def bounded_check(word: str):
        async with sem:
            return await _check_path(client, target_url, word)

    results = await asyncio.gather(*(bounded_check(w) for w in words))
    findings = [f for f in results if f is not None]

    if not findings:
        findings.append(
            Finding(
                module="dir_enum",
                title="No commonly-exposed paths found",
                severity=Severity.INFO,
                description=f"None of {len(words)} common sensitive paths returned HTTP 200.",
                url=target_url,
            )
        )
    return findings
