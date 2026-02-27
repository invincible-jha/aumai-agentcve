"""Shared test fixtures for aumai-agentcve test suite."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aumai_agentcve.models import (
    CVERecord,
    CVESeverity,
    DependencyInfo,
    VulnerabilityMatch,
    VulnerabilityReport,
)

# ---------------------------------------------------------------------------
# Datetime helpers
# ---------------------------------------------------------------------------

FIXED_TS = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# CVERecord fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def cve_critical() -> CVERecord:
    """A CRITICAL severity CVE affecting langchain-core."""
    return CVERecord(
        cve_id="CVE-2024-10001",
        description="Remote code execution in langchain-core prompt handling.",
        severity=CVESeverity.critical,
        cvss_score=9.8,
        published_date=FIXED_TS,
        affected_packages=["langchain-core"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-10001"],
    )


@pytest.fixture()
def cve_high() -> CVERecord:
    """A HIGH severity CVE affecting requests."""
    return CVERecord(
        cve_id="CVE-2024-20002",
        description="SSRF vulnerability in requests library.",
        severity=CVESeverity.high,
        cvss_score=7.5,
        published_date=FIXED_TS,
        affected_packages=["requests<2.32.0"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-20002"],
    )


@pytest.fixture()
def cve_medium() -> CVERecord:
    """A MEDIUM severity CVE affecting pydantic."""
    return CVERecord(
        cve_id="CVE-2024-30003",
        description="DoS via crafted model inputs in pydantic.",
        severity=CVESeverity.medium,
        cvss_score=5.3,
        published_date=FIXED_TS,
        affected_packages=["pydantic>=1.0,<2.0"],
        references=[],
    )


@pytest.fixture()
def cve_no_packages() -> CVERecord:
    """A CVE with no affected packages listed."""
    return CVERecord(
        cve_id="CVE-2024-99999",
        description="Generic vulnerability with no package info.",
        severity=CVESeverity.low,
        cvss_score=2.1,
        published_date=FIXED_TS,
        affected_packages=[],
        references=[],
    )


@pytest.fixture()
def cve_unknown_severity() -> CVERecord:
    """A CVE with unknown severity and no CVSS score."""
    return CVERecord(
        cve_id="GHSA-xxxx-yyyy-zzzz",
        description="Advisory with unknown severity.",
        severity=CVESeverity.unknown,
        cvss_score=None,
        published_date=FIXED_TS,
        affected_packages=["some-package"],
        references=[],
    )


@pytest.fixture()
def sample_cves(
    cve_critical: CVERecord,
    cve_high: CVERecord,
    cve_medium: CVERecord,
) -> list[CVERecord]:
    """A list of three sample CVEs for bulk tests."""
    return [cve_critical, cve_high, cve_medium]


# ---------------------------------------------------------------------------
# DependencyInfo fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def dep_langchain() -> DependencyInfo:
    """langchain-core at a vulnerable version."""
    return DependencyInfo(name="langchain-core", version="0.1.45")


@pytest.fixture()
def dep_requests_old() -> DependencyInfo:
    """requests at a version affected by cve_high (<2.32.0)."""
    return DependencyInfo(name="requests", version="2.28.0")


@pytest.fixture()
def dep_requests_new() -> DependencyInfo:
    """requests at a fixed version (>=2.32.0)."""
    return DependencyInfo(name="requests", version="2.32.1")


@pytest.fixture()
def dep_pydantic_v1() -> DependencyInfo:
    """pydantic v1 — in range for cve_medium."""
    return DependencyInfo(name="pydantic", version="1.10.13")


@pytest.fixture()
def dep_pydantic_v2() -> DependencyInfo:
    """pydantic v2 — out of range for cve_medium."""
    return DependencyInfo(name="pydantic", version="2.7.1")


@pytest.fixture()
def dep_unrelated() -> DependencyInfo:
    """A dependency that should not match any sample CVE."""
    return DependencyInfo(name="boto3", version="1.34.0")


@pytest.fixture()
def sample_deps(
    dep_langchain: DependencyInfo,
    dep_requests_old: DependencyInfo,
    dep_pydantic_v1: DependencyInfo,
    dep_unrelated: DependencyInfo,
) -> list[DependencyInfo]:
    """A realistic set of project dependencies."""
    return [dep_langchain, dep_requests_old, dep_pydantic_v1, dep_unrelated]


# ---------------------------------------------------------------------------
# VulnerabilityMatch / VulnerabilityReport fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def match_critical(
    cve_critical: CVERecord, dep_langchain: DependencyInfo
) -> VulnerabilityMatch:
    """A high-confidence match for the critical CVE."""
    return VulnerabilityMatch(
        cve=cve_critical,
        dependency=dep_langchain,
        match_confidence=0.8,
    )


@pytest.fixture()
def match_high(
    cve_high: CVERecord, dep_requests_old: DependencyInfo
) -> VulnerabilityMatch:
    """A match for the high-severity CVE."""
    return VulnerabilityMatch(
        cve=cve_high,
        dependency=dep_requests_old,
        match_confidence=1.0,
    )


@pytest.fixture()
def empty_report() -> VulnerabilityReport:
    """A report with no vulnerabilities."""
    return VulnerabilityReport(
        scan_id="scan-empty-001",
        timestamp=FIXED_TS,
        project_name="clean-project",
        total_dependencies=10,
        vulnerable_dependencies=0,
        matches=[],
        summary="No vulnerabilities detected.",
    )


@pytest.fixture()
def populated_report(
    match_critical: VulnerabilityMatch,
    match_high: VulnerabilityMatch,
) -> VulnerabilityReport:
    """A report with two vulnerability matches."""
    return VulnerabilityReport(
        scan_id="scan-test-001",
        timestamp=FIXED_TS,
        project_name="my-ai-agent",
        total_dependencies=5,
        vulnerable_dependencies=2,
        matches=[match_critical, match_high],
        summary="Found 2 vulnerabilities (1 critical, 1 high) across 2 packages.",
    )


# ---------------------------------------------------------------------------
# NVD feed data fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def nvd_api2_entry() -> dict:
    """A minimal NVD API 2.0 format CVE entry."""
    return {
        "id": "CVE-2024-55555",
        "descriptions": [
            {"lang": "en", "value": "Buffer overflow in example-lib."},
            {"lang": "es", "value": "Desbordamiento de buffer en example-lib."},
        ],
        "published": "2024-03-10T08:00:00.000",
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:example:example-lib:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [
            {"url": "https://example.com/advisory/1234"},
        ],
    }


@pytest.fixture()
def nvd_feed1_entry() -> dict:
    """A minimal NVD JSON Feed 1.1 format CVE entry."""
    return {
        "cve": {
            "CVE_data_meta": {"ID": "CVE-2023-11111"},
            "description": {
                "description_data": [
                    {"lang": "en", "value": "SQL injection in old-package."}
                ]
            },
            "references": {
                "reference_data": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-11111"}
                ]
            },
        },
        "impact": {
            "baseMetricV3": {
                "cvssV3": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                }
            }
        },
        "publishedDate": "2023-11-20T12:00:00",
        "configurations": {
            "nodes": [
                {
                    "cpe_match": [
                        {"cpe23Uri": "cpe:2.3:a:vendor:old-package:1.0.0:*:*:*:*:*:*:*"}
                    ]
                }
            ]
        },
    }


@pytest.fixture()
def nvd_api2_feed(nvd_api2_entry: dict) -> dict:
    """A complete NVD API 2.0 feed response dict."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": nvd_api2_entry}],
    }


@pytest.fixture()
def nvd_feed1_feed(nvd_feed1_entry: dict) -> dict:
    """A complete NVD JSON Feed 1.1 dict."""
    return {
        "CVE_data_type": "CVE",
        "CVE_data_version": "4.0",
        "CVE_Items": [nvd_feed1_entry],
    }


@pytest.fixture()
def ghsa_advisory() -> dict:
    """A GitHub Security Advisory dict."""
    return {
        "ghsaId": "GHSA-abcd-1234-efgh",
        "summary": "Path traversal in ai-framework",
        "description": "A path traversal vulnerability allows attackers to read arbitrary files.",
        "severity": "HIGH",
        "publishedAt": "2024-05-01T00:00:00",
        "cvss": {"score": 7.5},
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-abcd-1234-efgh"},
            {"type": "CVE", "value": "CVE-2024-77777"},
        ],
        "vulnerabilities": [
            {
                "package": {"name": "ai-framework", "ecosystem": "pip"},
                "vulnerableVersionRange": "<3.0.0",
            }
        ],
        "references": [
            {"url": "https://github.com/advisories/GHSA-abcd-1234-efgh"},
        ],
    }


# ---------------------------------------------------------------------------
# Filesystem fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_nvd_feed_file(tmp_path: Path, nvd_api2_feed: dict) -> Path:
    """Write a NVD API 2.0 feed to a temp JSON file."""
    feed_file = tmp_path / "nvd_feed.json"
    feed_file.write_text(json.dumps(nvd_api2_feed), encoding="utf-8")
    return feed_file


@pytest.fixture()
def tmp_ghsa_feed_file(tmp_path: Path, ghsa_advisory: dict) -> Path:
    """Write a GHSA advisory list to a temp JSON file."""
    feed_file = tmp_path / "ghsa_feed.json"
    feed_file.write_text(json.dumps([ghsa_advisory]), encoding="utf-8")
    return feed_file


@pytest.fixture()
def tmp_project_dir(tmp_path: Path) -> Path:
    """Create a minimal project directory with a requirements.txt."""
    project = tmp_path / "my_project"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "langchain-core==0.1.45\nrequests==2.28.0\nboto3==1.34.0\n",
        encoding="utf-8",
    )
    return project
