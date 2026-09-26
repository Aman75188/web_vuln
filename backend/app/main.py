import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import ScanRequest, ScanResult, Finding, Severity
from app.scanner import MODULE_REGISTRY
from app.utils import get_client, is_target_allowed

app = FastAPI(
    title="Web Vulnerability Scanner API",
    description="College project: a modular, authorized-target web vulnerability scanner.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for real deployments
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store (fine for a college project / single-user demo).
SCANS: dict[str, ScanResult] = {}


@app.get("/api/modules")
async def list_modules():
    return {"modules": list(MODULE_REGISTRY.keys())}


@app.post("/api/scan", response_model=ScanResult)
async def run_scan(req: ScanRequest):
    if not req.confirm_authorized:
        raise HTTPException(
            status_code=400,
            detail="You must confirm you own or are authorized to test this target before scanning.",
        )

    allowed, reason = is_target_allowed(req.target_url)
    if not allowed:
        raise HTTPException(status_code=400, detail=reason)

    modules_to_run = req.modules or list(MODULE_REGISTRY.keys())
    unknown = [m for m in modules_to_run if m not in MODULE_REGISTRY]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown module(s): {unknown}")

    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    findings: list[Finding] = []
    errors: list[str] = []

    async with await get_client() as client:
        tasks = {name: MODULE_REGISTRY[name](client, req.target_url) for name in modules_to_run}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                errors.append(f"Module '{name}' failed: {result}")
                continue
            findings.extend(result)

    finished_at = datetime.now(timezone.utc).isoformat()

    summary = {sev.value: 0 for sev in Severity}
    for f in findings:
        summary[f.severity.value] += 1

    result = ScanResult(
        scan_id=scan_id,
        target_url=req.target_url,
        started_at=started_at,
        finished_at=finished_at,
        findings=findings,
        summary=summary,
        errors=errors,
    )
    SCANS[scan_id] = result
    return result


@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    result = SCANS.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/api/scans")
async def list_scans():
    return {
        "scans": [
            {"scan_id": s.scan_id, "target_url": s.target_url, "started_at": s.started_at, "summary": s.summary}
            for s in SCANS.values()
        ]
    }


@app.get("/api/health")
async def health():
    return {"status": "ok"}
