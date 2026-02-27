"""Tests for aumai_agentcve.notifier — ConsoleNotifier, JSONFileNotifier,
WebhookNotifier, and the Notifier protocol."""

from __future__ import annotations

import json
import sys
from datetime import UTC
from io import StringIO
from pathlib import Path

import pytest

from aumai_agentcve.models import VulnerabilityReport
from aumai_agentcve.notifier import (
    ConsoleNotifier,
    JSONFileNotifier,
    Notifier,
    WebhookNotifier,
)

# ---------------------------------------------------------------------------
# Notifier Protocol
# ---------------------------------------------------------------------------


class TestNotifierProtocol:
    def test_console_notifier_is_notifier(self) -> None:
        assert isinstance(ConsoleNotifier(), Notifier)

    def test_json_file_notifier_is_notifier(self, tmp_path: Path) -> None:
        notifier = JSONFileNotifier(tmp_path / "report.json")
        assert isinstance(notifier, Notifier)

    def test_webhook_notifier_is_notifier(self) -> None:
        notifier = WebhookNotifier(url="https://example.com/webhook")
        assert isinstance(notifier, Notifier)

    def test_arbitrary_class_with_notify_satisfies_protocol(self) -> None:
        class MinimalNotifier:
            def notify(self, report: VulnerabilityReport) -> None:
                pass

        assert isinstance(MinimalNotifier(), Notifier)


# ---------------------------------------------------------------------------
# ConsoleNotifier
# ---------------------------------------------------------------------------


class TestConsoleNotifier:
    def _capture(self, report: VulnerabilityReport) -> str:
        buf = StringIO()
        notifier = ConsoleNotifier()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            notifier.notify(report)
        finally:
            sys.stdout = old_stdout
        return buf.getvalue()

    def test_prints_project_name(self, empty_report: VulnerabilityReport) -> None:
        output = self._capture(empty_report)
        assert "clean-project" in output

    def test_prints_scan_id(self, empty_report: VulnerabilityReport) -> None:
        output = self._capture(empty_report)
        assert "scan-empty-001" in output

    def test_prints_timestamp(self, empty_report: VulnerabilityReport) -> None:
        output = self._capture(empty_report)
        assert empty_report.timestamp.isoformat() in output

    def test_prints_total_dependencies(self, empty_report: VulnerabilityReport) -> None:
        output = self._capture(empty_report)
        assert str(empty_report.total_dependencies) in output

    def test_no_vulnerabilities_message(self, empty_report: VulnerabilityReport) -> None:
        output = self._capture(empty_report)
        assert "No vulnerabilities found" in output

    def test_prints_summary(self, empty_report: VulnerabilityReport) -> None:
        output = self._capture(empty_report)
        assert empty_report.summary in output

    def test_populated_report_lists_cves(
        self, populated_report: VulnerabilityReport
    ) -> None:
        output = self._capture(populated_report)
        assert "CVE-2024-10001" in output
        assert "CVE-2024-20002" in output

    def test_populated_report_shows_severity(
        self, populated_report: VulnerabilityReport
    ) -> None:
        output = self._capture(populated_report)
        assert "CRITICAL" in output

    def test_populated_report_shows_package_name(
        self, populated_report: VulnerabilityReport
    ) -> None:
        output = self._capture(populated_report)
        assert "langchain-core" in output
        assert "requests" in output

    def test_populated_report_shows_confidence(
        self, populated_report: VulnerabilityReport
    ) -> None:
        output = self._capture(populated_report)
        assert "confidence:" in output

    def test_populated_report_shows_cvss_score(
        self, populated_report: VulnerabilityReport
    ) -> None:
        output = self._capture(populated_report)
        assert "CVSS Score:" in output

    def test_matches_sorted_by_confidence_descending(
        self, populated_report: VulnerabilityReport
    ) -> None:
        """match_high has confidence 1.0, match_critical has 0.8 — high comes first."""
        output = self._capture(populated_report)
        idx_high = output.index("CVE-2024-20002")
        idx_critical = output.index("CVE-2024-10001")
        assert idx_high < idx_critical

    def test_description_truncated_at_120_chars(
        self, populated_report: VulnerabilityReport
    ) -> None:
        """Description in output should not exceed 120 + '...' chars per line."""
        output = self._capture(populated_report)
        # Each description line ends with "..."
        assert "..." in output

    def test_no_cvss_score_line_when_none(
        self, populated_report: VulnerabilityReport
    ) -> None:
        """If a match has no CVSS score, 'CVSS Score:' should not appear for it."""
        # Set cvss_score to None on the critical match
        from aumai_agentcve.models import VulnerabilityMatch

        no_score_cve = populated_report.matches[0].cve.model_copy(
            update={"cvss_score": None}
        )
        modified_match = VulnerabilityMatch(
            cve=no_score_cve,
            dependency=populated_report.matches[0].dependency,
            match_confidence=populated_report.matches[0].match_confidence,
        )
        from datetime import datetime

        report = VulnerabilityReport(
            scan_id="test-no-cvss",
            timestamp=datetime(2024, 1, 1, tzinfo=UTC),
            project_name="proj",
            total_dependencies=1,
            vulnerable_dependencies=1,
            matches=[modified_match],
        )
        output = self._capture(report)
        assert "CVSS Score:" not in output


# ---------------------------------------------------------------------------
# JSONFileNotifier
# ---------------------------------------------------------------------------


class TestJSONFileNotifier:
    def test_creates_file(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "report.json"
        notifier = JSONFileNotifier(output_path)
        notifier.notify(populated_report)
        assert output_path.exists()

    def test_creates_parent_directories(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "nested" / "deep" / "report.json"
        notifier = JSONFileNotifier(output_path)
        notifier.notify(populated_report)
        assert output_path.exists()

    def test_output_is_valid_json(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "report.json"
        JSONFileNotifier(output_path).notify(populated_report)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_output_contains_scan_id(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "report.json"
        JSONFileNotifier(output_path).notify(populated_report)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["scan_id"] == "scan-test-001"

    def test_output_contains_matches(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "report.json"
        JSONFileNotifier(output_path).notify(populated_report)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert len(data["matches"]) == 2

    def test_output_path_stored(self, tmp_path: Path) -> None:
        path = tmp_path / "out.json"
        notifier = JSONFileNotifier(path)
        assert notifier.output_path == path

    def test_empty_report_serialized(
        self, tmp_path: Path, empty_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "empty.json"
        JSONFileNotifier(output_path).notify(empty_report)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["matches"] == []

    def test_overwrites_existing_file(
        self, tmp_path: Path, empty_report: VulnerabilityReport, populated_report: VulnerabilityReport
    ) -> None:
        output_path = tmp_path / "report.json"
        JSONFileNotifier(output_path).notify(populated_report)
        JSONFileNotifier(output_path).notify(empty_report)
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["scan_id"] == "scan-empty-001"


# ---------------------------------------------------------------------------
# WebhookNotifier
# ---------------------------------------------------------------------------


class TestWebhookNotifier:
    def test_url_stored(self) -> None:
        notifier = WebhookNotifier(url="https://hooks.example.com/cve")
        assert notifier.url == "https://hooks.example.com/cve"

    def test_headers_stored(self) -> None:
        headers = {"Authorization": "Bearer token"}
        notifier = WebhookNotifier(url="https://example.com", headers=headers)
        assert notifier.headers == headers

    def test_default_headers_empty(self) -> None:
        notifier = WebhookNotifier(url="https://example.com")
        assert notifier.headers == {}

    def test_last_payload_none_before_notify(self) -> None:
        notifier = WebhookNotifier(url="https://example.com")
        assert notifier.last_payload is None

    def test_notify_stores_payload(
        self, populated_report: VulnerabilityReport, capsys: pytest.CaptureFixture[str]
    ) -> None:
        notifier = WebhookNotifier(url="https://example.com")
        notifier.notify(populated_report)
        assert notifier.last_payload is not None

    def test_payload_contains_scan_id(
        self, populated_report: VulnerabilityReport, capsys: pytest.CaptureFixture[str]
    ) -> None:
        notifier = WebhookNotifier(url="https://example.com")
        notifier.notify(populated_report)
        assert notifier.last_payload is not None
        assert notifier.last_payload["scan_id"] == "scan-test-001"

    def test_notify_prints_to_stderr(
        self, populated_report: VulnerabilityReport, capsys: pytest.CaptureFixture[str]
    ) -> None:
        notifier = WebhookNotifier(url="https://hooks.example.com")
        notifier.notify(populated_report)
        captured = capsys.readouterr()
        assert "WebhookNotifier" in captured.err
        assert "scan-test-001" in captured.err

    def test_payload_is_dict(
        self, empty_report: VulnerabilityReport, capsys: pytest.CaptureFixture[str]
    ) -> None:
        notifier = WebhookNotifier(url="https://example.com")
        notifier.notify(empty_report)
        assert isinstance(notifier.last_payload, dict)

    def test_payload_updated_on_second_notify(
        self,
        empty_report: VulnerabilityReport,
        populated_report: VulnerabilityReport,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        notifier = WebhookNotifier(url="https://example.com")
        notifier.notify(empty_report)
        notifier.notify(populated_report)
        assert notifier.last_payload is not None
        assert notifier.last_payload["scan_id"] == "scan-test-001"
