"""Pydantic models for aumai-agentcve."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class CVESeverity(str, Enum):
    """CVSS-aligned severity classification."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class CVERecord(BaseModel):
    """Represents a single CVE record from NVD or GitHub Advisory."""

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    description: str = Field(..., description="Human-readable vulnerability description")
    severity: CVESeverity = Field(default=CVESeverity.unknown)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    published_date: datetime
    affected_packages: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        """Ensure CVE ID has expected format or GHSA prefix."""
        value = value.strip().upper()
        if not (value.startswith("CVE-") or value.startswith("GHSA-")):
            raise ValueError(f"Invalid CVE ID format: {value!r}")
        return value


class DependencyInfo(BaseModel):
    """Represents a Python package dependency."""

    name: str = Field(..., description="Package name (normalized, lowercase)")
    version: str = Field(..., description="Installed version string")
    source: str = Field(default="pypi")

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        """Normalize package name to lowercase with hyphens."""
        return value.strip().lower().replace("_", "-")


class VulnerabilityMatch(BaseModel):
    """A matched vulnerability between a CVE and a dependency."""

    cve: CVERecord
    dependency: DependencyInfo
    match_confidence: float = Field(..., ge=0.0, le=1.0)


class VulnerabilityReport(BaseModel):
    """Full vulnerability scan report for a project."""

    scan_id: str
    timestamp: datetime
    project_name: str
    total_dependencies: int = Field(ge=0)
    vulnerable_dependencies: int = Field(ge=0)
    matches: list[VulnerabilityMatch] = Field(default_factory=list)
    summary: str = ""


__all__ = [
    "CVESeverity",
    "CVERecord",
    "DependencyInfo",
    "VulnerabilityMatch",
    "VulnerabilityReport",
]
