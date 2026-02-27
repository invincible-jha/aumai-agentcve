"""Tests for aumai_agentcve.core — DependencyScanner, CVEDatabase,
VulnerabilityMatcher, and ReportGenerator."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from aumai_agentcve.core import (
    CVEDatabase,
    DependencyScanner,
    ReportGenerator,
    VulnerabilityMatcher,
)
from aumai_agentcve.models import (
    CVERecord,
    CVESeverity,
    DependencyInfo,
    VulnerabilityMatch,
    VulnerabilityReport,
)

# ---------------------------------------------------------------------------
# DependencyScanner — scan_requirements_txt
# ---------------------------------------------------------------------------


class TestScanRequirementsTxt:
    def test_exact_pin(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("requests==2.28.0\n")
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_range_specifier_stored_verbatim(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("requests>=2.0,<3.0\n")
        assert len(deps) == 1
        assert "2.0" in deps[0].version

    def test_comments_ignored(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("# This is a comment\nrequests==2.28.0\n")
        assert len(deps) == 1

    def test_blank_lines_ignored(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("\n\nrequests==2.28.0\n\n")
        assert len(deps) == 1

    def test_inline_comment_stripped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("requests==2.28.0  # security fix\n")
        assert deps[0].version == "2.28.0"

    def test_dash_r_include_skipped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("-r base.txt\nrequests==2.28.0\n")
        assert len(deps) == 1

    def test_url_requirement_skipped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt(
            "https://example.com/my-pkg.tar.gz\nrequests==2.28.0\n"
        )
        assert len(deps) == 1

    def test_pep440_direct_reference(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt(
            "my-pkg @ https://github.com/org/repo/archive/main.zip\n"
        )
        assert len(deps) == 1
        assert deps[0].name == "my-pkg"
        assert deps[0].version == "unknown"

    def test_package_without_version_specifier(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("requests\n")
        assert len(deps) == 1
        assert deps[0].version == "unknown"

    def test_empty_content(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("")
        assert deps == []

    def test_multiple_packages(self) -> None:
        content = "requests==2.28.0\nboto3==1.34.0\nlangchain-core==0.1.45\n"
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt(content)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "boto3" in names
        assert "langchain-core" in names

    def test_name_normalized(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_requirements_txt("LangChain_Core==0.1.0\n")
        assert deps[0].name == "langchain-core"


# ---------------------------------------------------------------------------
# DependencyScanner — scan_pip_freeze
# ---------------------------------------------------------------------------


class TestScanPipFreeze:
    def test_standard_pin(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pip_freeze("requests==2.28.0\nboto3==1.34.0\n")
        assert len(deps) == 2

    def test_comment_lines_skipped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pip_freeze("# pip freeze output\nrequests==2.28.0\n")
        assert len(deps) == 1

    def test_dash_lines_skipped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pip_freeze("-e .\nrequests==2.28.0\n")
        assert len(deps) == 1

    def test_lines_without_double_equals_skipped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pip_freeze("requests>=2.28.0\nboto3==1.34.0\n")
        assert len(deps) == 1
        assert deps[0].name == "boto3"

    def test_empty_content(self) -> None:
        scanner = DependencyScanner()
        assert scanner.scan_pip_freeze("") == []

    def test_version_with_double_equals_split(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pip_freeze("mypackage==1.2.3\n")
        assert deps[0].version == "1.2.3"


# ---------------------------------------------------------------------------
# DependencyScanner — scan_pyproject_toml
# ---------------------------------------------------------------------------


class TestScanPyprojectToml:
    POETRY_TOML = """\
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.28.0"
langchain-core = "0.1.45"
"""

    PEP517_TOML = """\
[project]
name = "my-project"
dependencies = [
    "requests>=2.0,<3.0",
    "boto3==1.34.0",
]
"""

    def test_poetry_deps_extracted(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml(self.POETRY_TOML)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "langchain-core" in names

    def test_python_key_excluded_from_poetry(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml(self.POETRY_TOML)
        assert all(d.name != "python" for d in deps)

    def test_poetry_caret_stripped(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml(self.POETRY_TOML)
        req = next(d for d in deps if d.name == "requests")
        assert not req.version.startswith("^")

    def test_pep517_inline_dep_list(self) -> None:
        inline = '[project]\ndependencies = ["requests>=2.0", "boto3==1.34.0"]\n'
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml(inline)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "boto3" in names

    def test_pep517_multiline_list(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml(self.PEP517_TOML)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "boto3" in names

    def test_pep517_exact_pin_extracted(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml(self.PEP517_TOML)
        boto = next(d for d in deps if d.name == "boto3")
        assert boto.version == "1.34.0"

    def test_empty_toml(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml("")
        assert deps == []

    def test_no_relevant_sections(self) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_pyproject_toml("[tool.other]\nfoo = 'bar'\n")
        assert deps == []


# ---------------------------------------------------------------------------
# DependencyScanner — scan_directory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    def test_reads_requirements_txt(self, tmp_project_dir: Path) -> None:
        scanner = DependencyScanner()
        deps = scanner.scan_directory(tmp_project_dir)
        names = [d.name for d in deps]
        assert "langchain-core" in names
        assert "requests" in names

    def test_pip_freeze_takes_priority(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (project / "requirements-freeze.txt").write_text(
            "requests==2.28.0\n", encoding="utf-8"
        )
        (project / "requirements.txt").write_text(
            "requests==2.99.0\n", encoding="utf-8"
        )
        scanner = DependencyScanner()
        deps = scanner.scan_directory(project)
        # pip freeze listed first — the dup from requirements.txt should be skipped
        versions = [d.version for d in deps if d.name == "requests"]
        assert "2.28.0" in versions

    def test_deduplication_across_files(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        (project / "requirements-freeze.txt").write_text(
            "requests==2.28.0\n", encoding="utf-8"
        )
        (project / "requirements.txt").write_text(
            "requests==2.28.0\n", encoding="utf-8"
        )
        scanner = DependencyScanner()
        deps = scanner.scan_directory(project)
        assert sum(1 for d in deps if d.name == "requests") == 1

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        scanner = DependencyScanner()
        deps = scanner.scan_directory(empty_dir)
        assert deps == []


# ---------------------------------------------------------------------------
# CVEDatabase
# ---------------------------------------------------------------------------


class TestCVEDatabase:
    def test_add_and_get(self, cve_critical: CVERecord) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        record = db.get("CVE-2024-10001")
        assert record is not None
        assert record.cve_id == "CVE-2024-10001"

    def test_get_missing_returns_none(self) -> None:
        db = CVEDatabase()
        assert db.get("CVE-9999-99999") is None

    def test_add_updates_existing(self, cve_critical: CVERecord) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        updated = cve_critical.model_copy(update={"description": "Updated desc"})
        db.add(updated)
        assert db.count == 1
        assert db.get("CVE-2024-10001").description == "Updated desc"  # type: ignore[union-attr]

    def test_add_bulk_returns_new_count(self, sample_cves: list[CVERecord]) -> None:
        db = CVEDatabase()
        added = db.add_bulk(sample_cves)
        assert added == 3

    def test_add_bulk_no_duplicates_counted(self, cve_critical: CVERecord) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        added = db.add_bulk([cve_critical])
        assert added == 0

    def test_count_property(self, sample_cves: list[CVERecord]) -> None:
        db = CVEDatabase()
        db.add_bulk(sample_cves)
        assert db.count == 3

    def test_all_records(self, sample_cves: list[CVERecord]) -> None:
        db = CVEDatabase()
        db.add_bulk(sample_cves)
        records = db.all_records()
        assert len(records) == 3

    def test_search_by_package_case_insensitive(self, cve_critical: CVERecord) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        results = db.search_by_package("LangChain-Core")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-10001"

    def test_search_by_package_substring(self) -> None:

        cve = CVERecord(
            cve_id="CVE-2024-PKG",
            description="pkg test",
            published_date=datetime(2024, 1, 1, tzinfo=UTC),
            affected_packages=["langchain-core"],
        )
        db = CVEDatabase()
        db.add(cve)
        results = db.search_by_package("langchain")
        assert len(results) == 1

    def test_search_by_package_no_match(self, cve_critical: CVERecord) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        results = db.search_by_package("boto3")
        assert results == []

    def test_filter_by_severity(self, sample_cves: list[CVERecord]) -> None:
        db = CVEDatabase()
        db.add_bulk(sample_cves)
        critical = db.filter_by_severity(CVESeverity.critical)
        assert len(critical) == 1
        assert critical[0].cve_id == "CVE-2024-10001"

    def test_filter_by_severity_no_match(self, sample_cves: list[CVERecord]) -> None:
        db = CVEDatabase()
        db.add_bulk(sample_cves)
        unknown = db.filter_by_severity(CVESeverity.unknown)
        assert unknown == []

    def test_load_json_nvd_api2(self, nvd_api2_feed: dict) -> None:
        db = CVEDatabase()
        count = db.load_json(nvd_api2_feed)
        assert count == 1
        assert db.get("CVE-2024-55555") is not None

    def test_load_json_empty_feed(self) -> None:
        db = CVEDatabase()
        count = db.load_json({})
        assert count == 0


# ---------------------------------------------------------------------------
# VulnerabilityMatcher
# ---------------------------------------------------------------------------


class TestVulnerabilityMatcher:
    def test_match_returns_results_above_threshold(
        self,
        cve_critical: CVERecord,
        dep_langchain: DependencyInfo,
    ) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        matcher = VulnerabilityMatcher(db)
        matches = matcher.match([dep_langchain])
        assert len(matches) == 1

    def test_match_filters_below_min_confidence(
        self,
        cve_critical: CVERecord,
        dep_langchain: DependencyInfo,
    ) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        matcher = VulnerabilityMatcher(db)
        # langchain-core exact match * 0.8 = 0.8; require 0.9 → excluded
        matches = matcher.match([dep_langchain], min_confidence=0.9)
        assert matches == []

    def test_match_empty_database(self, dep_langchain: DependencyInfo) -> None:
        db = CVEDatabase()
        matcher = VulnerabilityMatcher(db)
        matches = matcher.match([dep_langchain])
        assert matches == []

    def test_match_empty_deps(self, cve_critical: CVERecord) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        matcher = VulnerabilityMatcher(db)
        matches = matcher.match([])
        assert matches == []

    def test_match_default_min_confidence_is_0_5(
        self,
        cve_critical: CVERecord,
        dep_langchain: DependencyInfo,
    ) -> None:
        db = CVEDatabase()
        db.add(cve_critical)
        matcher = VulnerabilityMatcher(db)
        # default min_confidence=0.5 — should include 0.8 match
        matches = matcher.match([dep_langchain])
        assert all(m.match_confidence >= 0.5 for m in matches)


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------


class TestReportGenerator:
    def test_generate_scan_id_is_uuid(
        self,
        sample_deps: list[DependencyInfo],
        match_critical: VulnerabilityMatch,
    ) -> None:
        import uuid

        generator = ReportGenerator()
        report = generator.generate("my-project", sample_deps, [match_critical])
        uuid.UUID(report.scan_id)  # raises ValueError if not a valid UUID

    def test_generate_total_dependencies(
        self,
        sample_deps: list[DependencyInfo],
    ) -> None:
        generator = ReportGenerator()
        report = generator.generate("my-project", sample_deps, [])
        assert report.total_dependencies == len(sample_deps)

    def test_generate_vulnerable_dependencies_count(
        self,
        sample_deps: list[DependencyInfo],
        match_critical: VulnerabilityMatch,
        match_high: VulnerabilityMatch,
    ) -> None:
        generator = ReportGenerator()
        report = generator.generate("my-project", sample_deps, [match_critical, match_high])
        assert report.vulnerable_dependencies == 2

    def test_generate_no_matches_summary(
        self, sample_deps: list[DependencyInfo]
    ) -> None:
        generator = ReportGenerator()
        report = generator.generate("clean-project", sample_deps, [])
        assert "No vulnerabilities detected" in report.summary

    def test_generate_with_matches_summary(
        self,
        sample_deps: list[DependencyInfo],
        match_critical: VulnerabilityMatch,
        match_high: VulnerabilityMatch,
    ) -> None:
        generator = ReportGenerator()
        report = generator.generate("my-project", sample_deps, [match_critical, match_high])
        assert "2 vulnerabilities" in report.summary
        assert "1 critical" in report.summary
        assert "1 high" in report.summary

    def test_generate_project_name(self, sample_deps: list[DependencyInfo]) -> None:
        generator = ReportGenerator()
        report = generator.generate("aumai-agent", sample_deps, [])
        assert report.project_name == "aumai-agent"

    def test_generate_timestamp_is_utc(
        self, sample_deps: list[DependencyInfo]
    ) -> None:
        generator = ReportGenerator()
        report = generator.generate("proj", sample_deps, [])
        assert report.timestamp.tzinfo == UTC

    def test_generate_matches_included(
        self,
        sample_deps: list[DependencyInfo],
        match_critical: VulnerabilityMatch,
    ) -> None:
        generator = ReportGenerator()
        report = generator.generate("proj", sample_deps, [match_critical])
        assert len(report.matches) == 1

    def test_generate_deduplicated_vulnerable_dep_names(
        self,
        dep_langchain: DependencyInfo,
        cve_critical: CVERecord,
    ) -> None:
        """Two matches on the same dep should count as one vulnerable dep."""

        second_cve = CVERecord(
            cve_id="CVE-2024-EXTRA",
            description="Second CVE on same dep.",
            published_date=datetime(2024, 1, 1, tzinfo=UTC),
            affected_packages=["langchain-core"],
        )
        match1 = VulnerabilityMatch(
            cve=cve_critical, dependency=dep_langchain, match_confidence=0.8
        )
        match2 = VulnerabilityMatch(
            cve=second_cve, dependency=dep_langchain, match_confidence=0.8
        )
        generator = ReportGenerator()
        report = generator.generate("proj", [dep_langchain], [match1, match2])
        assert report.vulnerable_dependencies == 1

    # -- to_text --

    def test_to_text_no_matches(self, empty_report: VulnerabilityReport) -> None:
        generator = ReportGenerator()
        text = generator.to_text(empty_report)
        assert "no vulnerabilities found" in text
        assert "clean-project" in text

    def test_to_text_with_matches(self, populated_report: VulnerabilityReport) -> None:
        generator = ReportGenerator()
        text = generator.to_text(populated_report)
        assert "CVE-2024-10001" in text
        assert "CVE-2024-20002" in text
        assert "langchain-core" in text
        assert "requests" in text

    def test_to_text_matches_sorted_by_confidence_descending(
        self, populated_report: VulnerabilityReport
    ) -> None:
        generator = ReportGenerator()
        text = generator.to_text(populated_report)
        idx_high = text.index("CVE-2024-20002")  # confidence 1.0
        idx_critical = text.index("CVE-2024-10001")  # confidence 0.8
        assert idx_high < idx_critical  # higher confidence appears first

    def test_to_text_cvss_score_included_when_present(
        self, populated_report: VulnerabilityReport
    ) -> None:
        generator = ReportGenerator()
        text = generator.to_text(populated_report)
        assert "CVSS:" in text

    def test_to_text_contains_scan_id(
        self, populated_report: VulnerabilityReport
    ) -> None:
        generator = ReportGenerator()
        text = generator.to_text(populated_report)
        assert populated_report.scan_id in text

    # -- to_json --

    def test_to_json_valid_json(self, populated_report: VulnerabilityReport) -> None:
        generator = ReportGenerator()
        json_str = generator.to_json(populated_report)
        data = json.loads(json_str)
        assert isinstance(data, dict)

    def test_to_json_scan_id_present(
        self, populated_report: VulnerabilityReport
    ) -> None:
        generator = ReportGenerator()
        data = json.loads(generator.to_json(populated_report))
        assert data["scan_id"] == "scan-test-001"

    def test_to_json_matches_count(
        self, populated_report: VulnerabilityReport
    ) -> None:
        generator = ReportGenerator()
        data = json.loads(generator.to_json(populated_report))
        assert len(data["matches"]) == 2

    def test_to_json_empty_report(self, empty_report: VulnerabilityReport) -> None:
        generator = ReportGenerator()
        data = json.loads(generator.to_json(empty_report))
        assert data["matches"] == []
        assert data["vulnerable_dependencies"] == 0
