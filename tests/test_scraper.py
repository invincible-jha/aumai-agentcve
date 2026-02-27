"""Tests for aumai_agentcve.scraper — NVD and GHSA feed parsing."""

from __future__ import annotations

import json
import logging
from datetime import UTC
from pathlib import Path
from typing import Any

import pytest

from aumai_agentcve.models import CVESeverity
from aumai_agentcve.scraper import (
    GitHubAdvisoryParser,
    NVDFeedParser,
    _parse_nvd_datetime,
    _severity_from_cvss_score,
    _severity_from_string,
    parse_nvd_entry,
)

# ---------------------------------------------------------------------------
# _severity_from_cvss_score
# ---------------------------------------------------------------------------


class TestSeverityFromCvssScore:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (9.0, CVESeverity.critical),
            (9.8, CVESeverity.critical),
            (10.0, CVESeverity.critical),
            (7.0, CVESeverity.high),
            (8.9, CVESeverity.high),
            (4.0, CVESeverity.medium),
            (6.9, CVESeverity.medium),
            (0.1, CVESeverity.low),
            (3.9, CVESeverity.low),
            (0.0, CVESeverity.unknown),
            (None, CVESeverity.unknown),
        ],
    )
    def test_score_to_severity(
        self, score: float | None, expected: CVESeverity
    ) -> None:
        assert _severity_from_cvss_score(score) == expected


# ---------------------------------------------------------------------------
# _severity_from_string
# ---------------------------------------------------------------------------


class TestSeverityFromString:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("critical", CVESeverity.critical),
            ("CRITICAL", CVESeverity.critical),
            ("high", CVESeverity.high),
            ("HIGH", CVESeverity.high),
            ("medium", CVESeverity.medium),
            ("moderate", CVESeverity.medium),
            ("MODERATE", CVESeverity.medium),
            ("low", CVESeverity.low),
            ("none", CVESeverity.low),
            ("unknown_value", CVESeverity.unknown),
            ("", CVESeverity.unknown),
            ("n/a", CVESeverity.unknown),
        ],
    )
    def test_string_to_severity(self, label: str, expected: CVESeverity) -> None:
        assert _severity_from_string(label) == expected


# ---------------------------------------------------------------------------
# _parse_nvd_datetime
# ---------------------------------------------------------------------------


class TestParseNvdDatetime:
    @pytest.mark.parametrize(
        "value",
        [
            "2024-01-15T12:34:56.123",
            "2024-01-15T12:34:56",
            "2024-01-15",
        ],
    )
    def test_valid_formats_parse(self, value: str) -> None:
        result = _parse_nvd_datetime(value)
        assert result.tzinfo == UTC
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_unparseable_falls_back_to_now(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="aumai_agentcve.scraper"):
            result = _parse_nvd_datetime("not-a-date")
        assert result.tzinfo == UTC
        assert "Could not parse" in caplog.text


# ---------------------------------------------------------------------------
# parse_nvd_entry — NVD API 2.0 format
# ---------------------------------------------------------------------------


class TestParseNvdEntryApi2:
    def test_parses_id_and_description(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert record.cve_id == "CVE-2024-55555"
        assert "Buffer overflow" in record.description

    def test_english_description_selected(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert "Desbordamiento" not in record.description

    def test_cvss_v31_score_extracted(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert record.cvss_score == 8.1

    def test_severity_from_baseseverity_string(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert record.severity == CVESeverity.high

    def test_affected_package_from_cpe(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert "example-lib" in record.affected_packages

    def test_references_extracted(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert "https://example.com/advisory/1234" in record.references

    def test_published_date_parsed(self, nvd_api2_entry: dict) -> None:
        record = parse_nvd_entry(nvd_api2_entry)
        assert record is not None
        assert record.published_date.year == 2024
        assert record.published_date.month == 3
        assert record.published_date.day == 10

    def test_cvss_v30_fallback(self) -> None:
        """Entry without v31 but with v30 metrics should still parse score."""
        entry: dict[str, Any] = {
            "id": "CVE-2024-11111",
            "descriptions": [{"lang": "en", "value": "Test desc"}],
            "published": "2024-01-01T00:00:00",
            "metrics": {
                "cvssMetricV30": [
                    {
                        "cvssData": {
                            "baseScore": 7.2,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.cvss_score == 7.2
        assert record.severity == CVESeverity.high

    def test_no_metrics_yields_unknown_severity(self) -> None:
        entry: dict[str, Any] = {
            "id": "CVE-2024-22222",
            "descriptions": [{"lang": "en", "value": "No metrics"}],
            "published": "2024-01-01T00:00:00",
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.severity == CVESeverity.unknown
        assert record.cvss_score is None

    def test_no_english_description_yields_empty_string(self) -> None:
        entry: dict[str, Any] = {
            "id": "CVE-2024-33333",
            "descriptions": [{"lang": "fr", "value": "Vulnérabilité"}],
            "published": "2024-01-01T00:00:00",
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.description == ""

    def test_cpe_wildcard_product_excluded(self) -> None:
        entry: dict[str, Any] = {
            "id": "CVE-2024-44444",
            "descriptions": [{"lang": "en", "value": "desc"}],
            "published": "2024-01-01T00:00:00",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.affected_packages == []

    def test_duplicate_cpe_packages_deduplicated(self) -> None:
        entry: dict[str, Any] = {
            "id": "CVE-2024-55551",
            "descriptions": [{"lang": "en", "value": "desc"}],
            "published": "2024-01-01T00:00:00",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:v:my-pkg:1.0:*:*:*:*:*:*:*"},
                                {"criteria": "cpe:2.3:a:v:my-pkg:2.0:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ],
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.affected_packages.count("my-pkg") == 1

    def test_severity_derived_from_score_when_string_unknown(self) -> None:
        entry: dict[str, Any] = {
            "id": "CVE-2024-66666",
            "descriptions": [{"lang": "en", "value": "desc"}],
            "published": "2024-01-01T00:00:00",
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.5, "baseSeverity": "BOGUS"}}
                ]
            },
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.cvss_score == 9.5
        assert record.severity == CVESeverity.critical


# ---------------------------------------------------------------------------
# parse_nvd_entry — NVD JSON Feed 1.1 format
# ---------------------------------------------------------------------------


class TestParseNvdEntryFeed1:
    def test_parses_feed1_entry(self, nvd_feed1_entry: dict) -> None:
        record = parse_nvd_entry(nvd_feed1_entry)
        assert record is not None
        assert record.cve_id == "CVE-2023-11111"
        assert "SQL injection" in record.description

    def test_feed1_cvss_score(self, nvd_feed1_entry: dict) -> None:
        record = parse_nvd_entry(nvd_feed1_entry)
        assert record is not None
        assert record.cvss_score == 9.8
        assert record.severity == CVESeverity.critical

    def test_feed1_reference_extracted(self, nvd_feed1_entry: dict) -> None:
        record = parse_nvd_entry(nvd_feed1_entry)
        assert record is not None
        assert "https://nvd.nist.gov/vuln/detail/CVE-2023-11111" in record.references

    def test_feed1_affected_package_from_cpe23uri(self, nvd_feed1_entry: dict) -> None:
        record = parse_nvd_entry(nvd_feed1_entry)
        assert record is not None
        assert "old-package" in record.affected_packages

    def test_feed1_missing_id_returns_none(self) -> None:
        entry: dict[str, Any] = {
            "cve": {
                "CVE_data_meta": {"ID": ""},
                "description": {"description_data": []},
            }
        }
        record = parse_nvd_entry(entry)
        assert record is None

    def test_feed1_no_impact_block(self) -> None:
        entry: dict[str, Any] = {
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2023-22222"},
                "description": {
                    "description_data": [{"lang": "en", "value": "No impact block."}]
                },
                "references": {"reference_data": []},
            },
            "publishedDate": "2023-06-01T00:00:00",
            "configurations": {"nodes": []},
        }
        record = parse_nvd_entry(entry)
        assert record is not None
        assert record.severity == CVESeverity.unknown
        assert record.cvss_score is None

    def test_corrupt_entry_returns_none(self, caplog: pytest.LogCaptureFixture) -> None:
        """Completely malformed entry should not raise — returns None."""
        with caplog.at_level(logging.WARNING, logger="aumai_agentcve.scraper"):
            result = parse_nvd_entry({"completely": "wrong"})
        # No CVE id found in feed 1.1 path → None
        assert result is None


# ---------------------------------------------------------------------------
# NVDFeedParser
# ---------------------------------------------------------------------------


class TestNVDFeedParser:
    def test_parse_dict_api2_format(self, nvd_api2_feed: dict) -> None:
        parser = NVDFeedParser()
        records = parser.parse_dict(nvd_api2_feed)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2024-55555"

    def test_parse_dict_feed1_format(self, nvd_feed1_feed: dict) -> None:
        parser = NVDFeedParser()
        records = parser.parse_dict(nvd_feed1_feed)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2023-11111"

    def test_parse_dict_empty_feed(self) -> None:
        parser = NVDFeedParser()
        records = parser.parse_dict({})
        assert records == []

    def test_parse_dict_api2_skips_invalid_entries(self) -> None:
        feed: dict[str, Any] = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-77777", "descriptions": [], "published": "2024-01-01T00:00:00"}},
                {"cve": {}},  # malformed — no id → returns None
            ]
        }
        parser = NVDFeedParser()
        records = parser.parse_dict(feed)
        # The well-formed one should parse; the malformed one yields None (skipped)
        assert len(records) == 1

    def test_parse_dict_feed1_skips_invalid(self) -> None:
        feed: dict[str, Any] = {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": ""},
                        "description": {"description_data": []},
                    }
                }
            ]
        }
        parser = NVDFeedParser()
        records = parser.parse_dict(feed)
        assert records == []

    def test_parse_file_api2(self, tmp_nvd_feed_file: Path) -> None:
        parser = NVDFeedParser()
        records = parser.parse_file(tmp_nvd_feed_file)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2024-55555"

    def test_parse_file_nonexistent_raises(self, tmp_path: Path) -> None:
        parser = NVDFeedParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_file(tmp_path / "nonexistent.json")

    def test_parse_dict_api2_vuln_without_cve_key(self) -> None:
        """vulnerabilities entry that has cve fields directly (no nested cve key)."""
        feed: dict[str, Any] = {
            "vulnerabilities": [
                {
                    "id": "CVE-2024-88888",
                    "descriptions": [{"lang": "en", "value": "Direct entry"}],
                    "published": "2024-01-01T00:00:00",
                }
            ]
        }
        parser = NVDFeedParser()
        records = parser.parse_dict(feed)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2024-88888"


# ---------------------------------------------------------------------------
# GitHubAdvisoryParser
# ---------------------------------------------------------------------------


class TestGitHubAdvisoryParser:
    def test_parse_advisory_ghsa_id(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        # CVE alias should take priority over GHSA id
        assert record.cve_id == "CVE-2024-77777"

    def test_parse_advisory_description(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        assert "path traversal" in record.description.lower()

    def test_parse_advisory_severity(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        assert record.severity == CVESeverity.high

    def test_parse_advisory_cvss_score(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        assert record.cvss_score == 7.5

    def test_parse_advisory_affected_package(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        assert any("ai-framework" in pkg for pkg in record.affected_packages)

    def test_parse_advisory_version_range_appended(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        # The version range "<3.0.0" is appended to the package name entry
        entry = next(p for p in record.affected_packages if "ai-framework" in p)
        assert "<3.0.0" in entry

    def test_parse_advisory_references(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        assert "https://github.com/advisories/GHSA-abcd-1234-efgh" in record.references

    def test_parse_advisory_published_date(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(ghsa_advisory)
        assert record is not None
        assert record.published_date.year == 2024
        assert record.published_date.month == 5

    def test_parse_advisory_uses_ghsa_id_when_no_cve_alias(self) -> None:
        advisory: dict[str, Any] = {
            "ghsaId": "GHSA-0000-0000-0000",
            "description": "No CVE alias here.",
            "severity": "LOW",
            "publishedAt": "2024-01-01T00:00:00",
            "identifiers": [{"type": "GHSA", "value": "GHSA-0000-0000-0000"}],
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert record.cve_id == "GHSA-0000-0000-0000"

    def test_parse_advisory_string_alias_cve(self) -> None:
        """identifiers as plain string list (CVE- prefix triggers alias use)."""
        advisory: dict[str, Any] = {
            "ghsaId": "GHSA-aaaa-bbbb-cccc",
            "description": "String alias test.",
            "severity": "MEDIUM",
            "publishedAt": "2024-02-01T00:00:00",
            "identifiers": ["GHSA-aaaa-bbbb-cccc", "CVE-2024-12345"],
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert record.cve_id == "CVE-2024-12345"

    def test_parse_advisory_missing_ghsa_id_returns_none(self) -> None:
        parser = GitHubAdvisoryParser()
        result = parser.parse_advisory({})
        assert result is None

    def test_parse_advisory_no_packages(self) -> None:
        advisory: dict[str, Any] = {
            "ghsaId": "GHSA-zzzz-zzzz-zzzz",
            "description": "No packages.",
            "publishedAt": "2024-01-01T00:00:00",
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert record.affected_packages == []

    def test_parse_advisory_cvss_score_drives_severity_when_string_unknown(self) -> None:
        advisory: dict[str, Any] = {
            "ghsaId": "GHSA-1111-2222-3333",
            "description": "Severity from score.",
            "severity": "",
            "publishedAt": "2024-01-01T00:00:00",
            "cvss": {"score": 9.5},
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert record.severity == CVESeverity.critical

    def test_parse_advisory_url_string_references(self) -> None:
        advisory: dict[str, Any] = {
            "ghsaId": "GHSA-4444-5555-6666",
            "description": "String refs.",
            "publishedAt": "2024-01-01T00:00:00",
            "references": ["https://plain-url.example.com/ref"],
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert "https://plain-url.example.com/ref" in record.references

    def test_parse_advisory_uses_published_at_fallback(self) -> None:
        advisory: dict[str, Any] = {
            "ghsaId": "GHSA-7777-8888-9999",
            "description": "published_at fallback",
            "published_at": "2023-12-01T00:00:00",
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert record.published_date.year == 2023

    def test_parse_bulk(self, ghsa_advisory: dict) -> None:
        parser = GitHubAdvisoryParser()
        records = parser.parse_bulk([ghsa_advisory, ghsa_advisory])
        assert len(records) == 2

    def test_parse_bulk_skips_invalid(self) -> None:
        parser = GitHubAdvisoryParser()
        records = parser.parse_bulk([{}, {}])
        assert records == []

    def test_parse_file_list(self, tmp_ghsa_feed_file: Path) -> None:
        parser = GitHubAdvisoryParser()
        records = parser.parse_file(tmp_ghsa_feed_file)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2024-77777"

    def test_parse_file_single_dict(self, tmp_path: Path, ghsa_advisory: dict) -> None:
        """A file containing a single advisory object (not a list)."""
        single_file = tmp_path / "single.json"
        single_file.write_text(json.dumps(ghsa_advisory), encoding="utf-8")
        parser = GitHubAdvisoryParser()
        records = parser.parse_file(single_file)
        assert len(records) == 1

    def test_parse_file_invalid_json_type(self, tmp_path: Path) -> None:
        """Non-list, non-dict JSON (e.g. number) returns empty list."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("42", encoding="utf-8")
        parser = GitHubAdvisoryParser()
        records = parser.parse_file(bad_file)
        assert records == []

    def test_parse_advisory_uses_id_key_when_no_ghsaid(self) -> None:
        advisory: dict[str, Any] = {
            "id": "GHSA-aaaa-1111-bbbb",
            "description": "Uses id key.",
            "publishedAt": "2024-01-01T00:00:00",
        }
        parser = GitHubAdvisoryParser()
        record = parser.parse_advisory(advisory)
        assert record is not None
        assert record.cve_id == "GHSA-AAAA-1111-BBBB"
