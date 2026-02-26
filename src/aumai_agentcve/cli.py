"""CLI entry point for aumai-agentcve."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from aumai_agentcve.core import (
    CVEDatabase,
    DependencyScanner,
    ReportGenerator,
    VulnerabilityMatcher,
)
from aumai_agentcve.notifier import ConsoleNotifier, JSONFileNotifier
from aumai_agentcve.scraper import GitHubAdvisoryParser, NVDFeedParser


@click.group()
@click.version_option()
def main() -> None:
    """AumAI AgentCVE — vulnerability tracking for AI agent frameworks."""


@main.command("scan")
@click.option(
    "--project-dir",
    default=".",
    show_default=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Project directory to scan for dependencies.",
)
@click.option(
    "--feed",
    "feed_files",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="NVD/GHSA JSON feed file(s) to load CVEs from.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write JSON report to this file.",
)
@click.option(
    "--min-confidence",
    default=0.5,
    show_default=True,
    type=float,
    help="Minimum match confidence (0.0–1.0) to include in report.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format for console report.",
)
def scan(
    project_dir: Path,
    feed_files: tuple[Path, ...],
    output: Path | None,
    min_confidence: float,
    output_format: str,
) -> None:
    """Scan project dependencies for known CVEs."""
    scanner = DependencyScanner()
    database = CVEDatabase()
    nvd_parser = NVDFeedParser()
    ghsa_parser = GitHubAdvisoryParser()

    # Load CVE feeds
    for feed_path in feed_files:
        try:
            with feed_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                records = ghsa_parser.parse_bulk(data)
            else:
                records = nvd_parser.parse_dict(data)
            count = database.add_bulk(records)
            click.echo(f"Loaded {count} CVEs from {feed_path.name}")
        except Exception as exc:
            click.echo(f"Warning: failed to load {feed_path}: {exc}", err=True)

    if database.count == 0:
        click.echo(
            "No CVE data loaded. Use --feed to provide NVD/GHSA JSON feed files.",
            err=True,
        )

    # Scan dependencies
    deps = scanner.scan_directory(project_dir)
    click.echo(f"Scanned {len(deps)} dependencies in {project_dir}")

    # Match vulnerabilities
    matcher = VulnerabilityMatcher(database)
    matches = matcher.match(deps, min_confidence=min_confidence)

    # Generate report
    generator = ReportGenerator()
    report = generator.generate(
        project_name=project_dir.resolve().name,
        dependencies=deps,
        matches=matches,
    )

    # Output
    if output_format == "json":
        click.echo(generator.to_json(report))
    else:
        ConsoleNotifier().notify(report)

    if output:
        JSONFileNotifier(output).notify(report)
        click.echo(f"Report written to {output}")

    if report.vulnerable_dependencies > 0:
        sys.exit(1)


@main.command("ingest")
@click.option(
    "--feed",
    "feed_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="NVD or GHSA JSON feed file to ingest.",
)
@click.option(
    "--format",
    "feed_format",
    type=click.Choice(["nvd", "ghsa", "auto"]),
    default="auto",
    show_default=True,
    help="Feed format. 'auto' detects from file structure.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write parsed CVEs as JSON array to this file.",
)
def ingest(feed_file: Path, feed_format: str, output: Path | None) -> None:
    """Ingest a CVE feed file and optionally export parsed records."""
    with feed_file.open(encoding="utf-8") as fh:
        data = json.load(fh)

    records = []
    if feed_format == "ghsa" or (
        feed_format == "auto" and isinstance(data, list)
    ):
        parser_ghsa = GitHubAdvisoryParser()
        records = parser_ghsa.parse_bulk(data if isinstance(data, list) else [data])
    else:
        parser_nvd = NVDFeedParser()
        records = parser_nvd.parse_dict(data if isinstance(data, dict) else {})

    click.echo(f"Parsed {len(records)} CVE records from {feed_file.name}")

    if output:
        serialized = [r.model_dump(mode="json") for r in records]
        output.write_text(
            json.dumps(serialized, indent=2, default=str), encoding="utf-8"
        )
        click.echo(f"Exported to {output}")


@main.command("report")
@click.option("--scan-id", required=True, help="Scan ID to look up (must match file).")
@click.option(
    "--report-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the JSON report file produced by 'scan'.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "text"]),
    default="text",
    show_default=True,
)
def report(scan_id: str, report_file: Path, output_format: str) -> None:
    """Display a previously generated vulnerability report."""
    from aumai_agentcve.models import VulnerabilityReport

    raw = json.loads(report_file.read_text(encoding="utf-8"))
    loaded_report = VulnerabilityReport.model_validate(raw)

    if loaded_report.scan_id != scan_id:
        click.echo(
            f"Warning: scan_id mismatch. File has {loaded_report.scan_id!r}, "
            f"requested {scan_id!r}",
            err=True,
        )

    if output_format == "json":
        click.echo(ReportGenerator().to_json(loaded_report))
    else:
        ConsoleNotifier().notify(loaded_report)


if __name__ == "__main__":
    main()
