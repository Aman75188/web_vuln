from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Full URL of the target, e.g. http://localhost:3000")
    confirm_authorized: bool = Field(
        ..., description="User must confirm they own/are authorized to test this target"
    )
    modules: Optional[List[str]] = Field(
        default=None,
        description="Subset of module names to run. If omitted, all modules run.",
    )


class Finding(BaseModel):
    module: str
    title: str
    severity: Severity
    description: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    url: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    started_at: str
    finished_at: str
    findings: List[Finding]
    summary: dict
    errors: List[str] = []
