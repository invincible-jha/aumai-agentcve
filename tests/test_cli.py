"""Tests for aumai_agentcve.cli — Click commands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from aumai_agentcve.cli import main
from aumai_agentcve.models import VulnerabilityReport

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_nvd_feed(cve_id: str = "CVE-2024-55555") -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {"lang": "en", "value": f"Test vuln {cve_id}"}
                    ],
                    "published": "2024-01-01T00:00:00",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:vendor:requests:*:*:*:*:*:*:*:*"
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def make_ghsa_feed(pkg: str = "requests") -> list:
    return [
        {
            "ghsaId": "GHSA-test-1234-abcd",
            "description": f"Vulnerability in {pkg}",
            "severity": "HIGH",
            "publishedAt": "2024-01-01T00:00:00",
            "vulnerabilities": [
                {"package": {"name": pkg}, "vulnerableVersionRange": "<3.0.0"}
            ],
            "references": [],
        }
    ]


# ---------------------------------------------------------------------------
# main / --version
# ---------------------------------------------------------------------------


class TestMainGroup:
    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "ingest" in result.output
        assert "report" in result.output


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


class TestScanCommand:
    def test_scan_no_feed_warns_and_succeeds(self, tmp_project_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--project-dir", str(tmp_project_dir)],
        )
        # No CVE data — should warn but exit 0 (no vulnerabilities means no sys.exit(1))
        assert "No CVE data loaded" in result.output

    def test_scan_with_nvd_feed_no_match(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text(
            "boto3==1.34.0\n", encoding="utf-8"
        )
        feed_file = tmp_path / "feed.json"
        feed_file.write_text(json.dumps(make_nvd_feed()), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--project-dir", str(project), "--feed", str(feed_file)],
        )
        assert result.exit_code == 0
        assert "No vulnerabilities found" in result.output

    def test_scan_with_nvd_feed_match_exits_1(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text(
            "requests==2.28.0\n", encoding="utf-8"
        )
        feed_file = tmp_path / "feed.json"
        feed_file.write_text(json.dumps(make_nvd_feed()), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--project-dir", str(project), "--feed", str(feed_file)],
        )
        # Vulnerability found → sys.exit(1) → exit_code == 1
        assert result.exit_code == 1

    def test_scan_writes_json_output_file(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text("boto3==1.34.0\n", encoding="utf-8")
        feed_file = tmp_path / "feed.json"
        feed_file.write_text(json.dumps(make_nvd_feed()), encoding="utf-8")
        output_file = tmp_path / "report.json"

        runner = CliRunner()
        runner.invoke(
            main,
            [
                "scan",
                "--project-dir", str(project),
                "--feed", str(feed_file),
                "--output", str(output_file),
            ],
        )
        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "scan_id" in data

    def test_scan_json_format_output(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text("boto3==1.34.0\n", encoding="utf-8")
        feed_file = tmp_path / "feed.json"
        feed_file.write_text(json.dumps(make_nvd_feed()), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--project-dir", str(project),
                "--feed", str(feed_file),
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        # stdout should contain valid JSON
        # Find the JSON block in output (after "Loaded N CVEs" lines)
        lines = result.output.strip().splitlines()
        json_start = next(
            (i for i, line in enumerate(lines) if line.strip().startswith("{")), None
        )
        assert json_start is not None
        json_str = "\n".join(lines[json_start:])
        data = json.loads(json_str)
        assert "scan_id" in data

    def test_scan_with_ghsa_feed(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text("boto3==1.34.0\n", encoding="utf-8")
        feed_file = tmp_path / "ghsa.json"
        feed_file.write_text(json.dumps(make_ghsa_feed()), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--project-dir", str(project), "--feed", str(feed_file)],
        )
        assert "Loaded" in result.output

    def test_scan_bad_feed_file_warns(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text("boto3==1.34.0\n", encoding="utf-8")
        bad_feed = tmp_path / "bad.json"
        bad_feed.write_text("THIS IS NOT JSON", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--project-dir", str(project), "--feed", str(bad_feed)],
        )
        assert "Warning" in result.output or "failed" in result.output.lower()

    def test_scan_multiple_feeds(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text("boto3==1.34.0\n", encoding="utf-8")

        feed1 = tmp_path / "feed1.json"
        feed1.write_text(json.dumps(make_nvd_feed("CVE-2024-11111")), encoding="utf-8")
        feed2 = tmp_path / "feed2.json"
        feed2.write_text(json.dumps(make_nvd_feed("CVE-2024-22222")), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--project-dir", str(project),
                "--feed", str(feed1),
                "--feed", str(feed2),
            ],
        )
        assert result.output.count("Loaded") == 2

    def test_scan_reports_dep_count(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text(
            "boto3==1.34.0\nnumpy==1.26.0\n", encoding="utf-8"
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--project-dir", str(project)],
        )
        assert "2 dependencies" in result.output

    def test_scan_min_confidence_filters_results(self, tmp_path: Path) -> None:
        """A very high min_confidence should suppress borderline matches."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text(
            "requests==2.28.0\n", encoding="utf-8"
        )
        feed_file = tmp_path / "feed.json"
        feed_file.write_text(json.dumps(make_nvd_feed()), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--project-dir", str(project),
                "--feed", str(feed_file),
                "--min-confidence", "0.99",
            ],
        )
        # With min_confidence=0.99 the match (confidence ~0.8) should be excluded
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# ingest command
# ---------------------------------------------------------------------------


class TestIngestCommand:
    def test_ingest_nvd_feed(self, tmp_nvd_feed_file: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--feed", str(tmp_nvd_feed_file)]
        )
        assert result.exit_code == 0
        assert "Parsed 1 CVE records" in result.output

    def test_ingest_ghsa_feed(self, tmp_ghsa_feed_file: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--feed", str(tmp_ghsa_feed_file)]
        )
        assert result.exit_code == 0
        assert "Parsed 1 CVE records" in result.output

    def test_ingest_auto_detects_nvd_dict(self, tmp_nvd_feed_file: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--feed", str(tmp_nvd_feed_file), "--format", "auto"]
        )
        assert result.exit_code == 0

    def test_ingest_auto_detects_ghsa_list(self, tmp_ghsa_feed_file: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ingest", "--feed", str(tmp_ghsa_feed_file), "--format", "auto"],
        )
        assert result.exit_code == 0

    def test_ingest_explicit_nvd_format(self, tmp_nvd_feed_file: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--feed", str(tmp_nvd_feed_file), "--format", "nvd"]
        )
        assert result.exit_code == 0
        assert "Parsed" in result.output

    def test_ingest_explicit_ghsa_format(self, tmp_ghsa_feed_file: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--feed", str(tmp_ghsa_feed_file), "--format", "ghsa"]
        )
        assert result.exit_code == 0

    def test_ingest_writes_output_file(
        self, tmp_path: Path, tmp_nvd_feed_file: Path
    ) -> None:
        output = tmp_path / "parsed.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ingest", "--feed", str(tmp_nvd_feed_file), "--output", str(output)],
        )
        assert result.exit_code == 0
        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == 1

    def test_ingest_output_contains_cve_id(
        self, tmp_path: Path, tmp_nvd_feed_file: Path
    ) -> None:
        output = tmp_path / "parsed.json"
        runner = CliRunner()
        runner.invoke(
            main,
            ["ingest", "--feed", str(tmp_nvd_feed_file), "--output", str(output)],
        )
        data = json.loads(output.read_text(encoding="utf-8"))
        assert data[0]["cve_id"] == "CVE-2024-55555"

    def test_ingest_missing_feed_arg_fails(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ingest"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


class TestReportCommand:
    def _write_report_file(
        self, path: Path, report_data: dict
    ) -> None:
        path.write_text(json.dumps(report_data), encoding="utf-8")

    def test_report_text_format(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        from aumai_agentcve.core import ReportGenerator

        report_file = tmp_path / "report.json"
        data = json.loads(ReportGenerator().to_json(populated_report))
        self._write_report_file(report_file, data)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "report",
                "--scan-id", populated_report.scan_id,
                "--report-file", str(report_file),
            ],
        )
        assert result.exit_code == 0
        assert populated_report.project_name in result.output

    def test_report_json_format(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        from aumai_agentcve.core import ReportGenerator

        report_file = tmp_path / "report.json"
        data = json.loads(ReportGenerator().to_json(populated_report))
        self._write_report_file(report_file, data)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "report",
                "--scan-id", populated_report.scan_id,
                "--report-file", str(report_file),
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        output_data = json.loads(result.output)
        assert output_data["scan_id"] == populated_report.scan_id

    def test_report_scan_id_mismatch_warns(
        self, tmp_path: Path, populated_report: VulnerabilityReport
    ) -> None:
        from aumai_agentcve.core import ReportGenerator

        report_file = tmp_path / "report.json"
        data = json.loads(ReportGenerator().to_json(populated_report))
        self._write_report_file(report_file, data)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "report",
                "--scan-id", "wrong-scan-id-xxxx",
                "--report-file", str(report_file),
            ],
        )
        # Should warn but not crash
        assert "mismatch" in result.output.lower() or "Warning" in result.output

    def test_report_missing_args_fails(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["report"])
        assert result.exit_code != 0

    def test_report_nonexistent_file_fails(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "report",
                "--scan-id", "abc",
                "--report-file", str(tmp_path / "missing.json"),
            ],
        )
        assert result.exit_code != 0
