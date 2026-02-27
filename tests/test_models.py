"""Tests for aumai_agentcve.models — Pydantic model validation and behaviour."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aumai_agentcve.models import (
    CVERecord,
    CVESeverity,
    DependencyInfo,
    VulnerabilityMatch,
    VulnerabilityReport,
)

FIXED_TS = datetime(2024, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# CVESeverity
# ---------------------------------------------------------------------------


class TestCVESeverity:
    def test_enum_values_exist(self) -> None:
        assert CVESeverity.critical.value == "critical"
        assert CVESeverity.high.value == "high"
        assert CVESeverity.medium.value == "medium"
        assert CVESeverity.low.value == "low"
        assert CVESeverity.unknown.value == "unknown"

    def test_is_string_enum(self) -> None:
        assert isinstance(CVESeverity.critical, str)


# ---------------------------------------------------------------------------
# CVERecord
# ---------------------------------------------------------------------------


class TestCVERecord:
    def test_valid_cve_id(self) -> None:
        record = CVERecord(
            cve_id="CVE-2024-12345",
            description="Test vulnerability",
            published_date=FIXED_TS,
        )
        assert record.cve_id == "CVE-2024-12345"

    def test_valid_ghsa_id(self) -> None:
        record = CVERecord(
            cve_id="GHSA-xxxx-yyyy-zzzz",
            description="GHSA advisory",
            published_date=FIXED_TS,
        )
        assert record.cve_id == "GHSA-XXXX-YYYY-ZZZZ"

    def test_cve_id_uppercased(self) -> None:
        record = CVERecord(
            cve_id="cve-2024-99999",
            description="lowercase input",
            published_date=FIXED_TS,
        )
        assert record.cve_id == "CVE-2024-99999"

    def test_cve_id_whitespace_stripped(self) -> None:
        record = CVERecord(
            cve_id="  CVE-2024-00001  ",
            description="whitespace",
            published_date=FIXED_TS,
        )
        assert record.cve_id == "CVE-2024-00001"

    def test_invalid_cve_id_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid CVE ID format"):
            CVERecord(
                cve_id="INVALID-ID",
                description="bad id",
                published_date=FIXED_TS,
            )

    def test_empty_cve_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            CVERecord(
                cve_id="",
                description="empty id",
                published_date=FIXED_TS,
            )

    def test_default_severity_is_unknown(self) -> None:
        record = CVERecord(
            cve_id="CVE-2024-11111",
            description="no severity",
            published_date=FIXED_TS,
        )
        assert record.severity == CVESeverity.unknown

    def test_cvss_score_bounds_valid(self) -> None:
        for score in (0.0, 5.0, 10.0):
            record = CVERecord(
                cve_id="CVE-2024-22222",
                description="score test",
                cvss_score=score,
                published_date=FIXED_TS,
            )
            assert record.cvss_score == score

    def test_cvss_score_above_max_raises(self) -> None:
        with pytest.raises(ValidationError):
            CVERecord(
                cve_id="CVE-2024-33333",
                description="overflow",
                cvss_score=10.1,
                published_date=FIXED_TS,
            )

    def test_cvss_score_below_min_raises(self) -> None:
        with pytest.raises(ValidationError):
            CVERecord(
                cve_id="CVE-2024-44444",
                description="underflow",
                cvss_score=-0.1,
                published_date=FIXED_TS,
            )

    def test_affected_packages_default_empty(self) -> None:
        record = CVERecord(
            cve_id="CVE-2024-55555",
            description="no packages",
            published_date=FIXED_TS,
        )
        assert record.affected_packages == []

    def test_references_default_empty(self) -> None:
        record = CVERecord(
            cve_id="CVE-2024-66666",
            description="no refs",
            published_date=FIXED_TS,
        )
        assert record.references == []

    def test_full_construction(self) -> None:
        record = CVERecord(
            cve_id="CVE-2024-77777",
            description="Full record test.",
            severity=CVESeverity.high,
            cvss_score=8.5,
            published_date=FIXED_TS,
            affected_packages=["requests<2.32.0"],
            references=["https://example.com/advisory"],
        )
        assert record.severity == CVESeverity.high
        assert record.cvss_score == 8.5
        assert len(record.affected_packages) == 1
        assert len(record.references) == 1


# ---------------------------------------------------------------------------
# DependencyInfo
# ---------------------------------------------------------------------------


class TestDependencyInfo:
    def test_name_normalized_to_lowercase(self) -> None:
        dep = DependencyInfo(name="LangChain", version="0.1.0")
        assert dep.name == "langchain"

    def test_underscores_replaced_with_hyphens(self) -> None:
        dep = DependencyInfo(name="langchain_core", version="0.1.0")
        assert dep.name == "langchain-core"

    def test_whitespace_stripped(self) -> None:
        dep = DependencyInfo(name="  requests  ", version="2.28.0")
        assert dep.name == "requests"

    def test_default_source_is_pypi(self) -> None:
        dep = DependencyInfo(name="boto3", version="1.34.0")
        assert dep.source == "pypi"

    def test_custom_source(self) -> None:
        dep = DependencyInfo(name="internal-pkg", version="1.0.0", source="artifactory")
        assert dep.source == "artifactory"

    def test_version_stored_as_given(self) -> None:
        dep = DependencyInfo(name="requests", version=">=2.28.0,<3.0.0")
        assert dep.version == ">=2.28.0,<3.0.0"


# ---------------------------------------------------------------------------
# VulnerabilityMatch
# ---------------------------------------------------------------------------


class TestVulnerabilityMatch:
    def test_valid_match(
        self, cve_critical: CVERecord, dep_langchain: DependencyInfo
    ) -> None:
        match = VulnerabilityMatch(
            cve=cve_critical,
            dependency=dep_langchain,
            match_confidence=0.95,
        )
        assert match.match_confidence == 0.95
        assert match.cve.cve_id == "CVE-2024-10001"

    def test_confidence_below_zero_raises(
        self, cve_critical: CVERecord, dep_langchain: DependencyInfo
    ) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityMatch(
                cve=cve_critical,
                dependency=dep_langchain,
                match_confidence=-0.1,
            )

    def test_confidence_above_one_raises(
        self, cve_critical: CVERecord, dep_langchain: DependencyInfo
    ) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityMatch(
                cve=cve_critical,
                dependency=dep_langchain,
                match_confidence=1.01,
            )

    def test_confidence_boundary_values(
        self, cve_critical: CVERecord, dep_langchain: DependencyInfo
    ) -> None:
        for value in (0.0, 1.0):
            match = VulnerabilityMatch(
                cve=cve_critical,
                dependency=dep_langchain,
                match_confidence=value,
            )
            assert match.match_confidence == value


# ---------------------------------------------------------------------------
# VulnerabilityReport
# ---------------------------------------------------------------------------


class TestVulnerabilityReport:
    def test_basic_report_construction(self, empty_report: VulnerabilityReport) -> None:
        assert empty_report.scan_id == "scan-empty-001"
        assert empty_report.total_dependencies == 10
        assert empty_report.vulnerable_dependencies == 0
        assert empty_report.matches == []

    def test_negative_total_deps_raises(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityReport(
                scan_id="x",
                timestamp=FIXED_TS,
                project_name="proj",
                total_dependencies=-1,
                vulnerable_dependencies=0,
            )

    def test_negative_vulnerable_raises(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityReport(
                scan_id="x",
                timestamp=FIXED_TS,
                project_name="proj",
                total_dependencies=5,
                vulnerable_dependencies=-1,
            )

    def test_summary_defaults_to_empty_string(self) -> None:
        report = VulnerabilityReport(
            scan_id="x",
            timestamp=FIXED_TS,
            project_name="proj",
            total_dependencies=0,
            vulnerable_dependencies=0,
        )
        assert report.summary == ""

    def test_populated_report_has_matches(
        self, populated_report: VulnerabilityReport
    ) -> None:
        assert len(populated_report.matches) == 2
        assert populated_report.vulnerable_dependencies == 2

    def test_model_dump_serializable(
        self, populated_report: VulnerabilityReport
    ) -> None:
        data = populated_report.model_dump(mode="json")
        assert isinstance(data, dict)
        assert data["scan_id"] == "scan-test-001"
        assert isinstance(data["matches"], list)
        assert len(data["matches"]) == 2
