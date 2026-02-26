"""Alert and notification system for vulnerability reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Protocol, runtime_checkable

from aumai_agentcve.models import VulnerabilityReport


@runtime_checkable
class Notifier(Protocol):
    """Protocol for all vulnerability report notifiers."""

    def notify(self, report: VulnerabilityReport) -> None:
        """Send or persist a vulnerability report."""
        ...


class ConsoleNotifier:
    """Print vulnerability report summary to the terminal."""

    def notify(self, report: VulnerabilityReport) -> None:
        """Print a formatted summary to stdout."""
        out = sys.stdout
        print(f"=== Vulnerability Report: {report.project_name} ===", file=out)
        print(f"Scan ID   : {report.scan_id}", file=out)
        print(f"Timestamp : {report.timestamp.isoformat()}", file=out)
        print(
            f"Dependencies scanned : {report.total_dependencies}", file=out
        )
        print(
            f"Vulnerable           : {report.vulnerable_dependencies}", file=out
        )
        print(f"Summary   : {report.summary}", file=out)

        if not report.matches:
            print("No vulnerabilities found.", file=out)
            return

        print("\nVulnerabilities:", file=out)
        for match in sorted(
            report.matches, key=lambda m: m.match_confidence, reverse=True
        ):
            cve = match.cve
            dep = match.dependency
            print(
                f"  [{cve.severity.value.upper()}] {cve.cve_id}"
                f" — {dep.name}=={dep.version}"
                f" (confidence: {match.match_confidence:.0%})",
                file=out,
            )
            if cve.cvss_score is not None:
                print(f"    CVSS Score: {cve.cvss_score}", file=out)
            print(f"    {cve.description[:120]}...", file=out)


class JSONFileNotifier:
    """Write the vulnerability report as a JSON file."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path

    def notify(self, report: VulnerabilityReport) -> None:
        """Serialize the report to a JSON file."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as fh:
            json.dump(report.model_dump(mode="json"), fh, indent=2, default=str)


class WebhookNotifier:
    """Placeholder webhook notifier — stores config, skips live HTTP in MVP."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers: dict[str, str] = headers or {}

    def notify(self, report: VulnerabilityReport) -> None:
        """Log webhook payload (live HTTP disabled in MVP)."""
        payload = report.model_dump(mode="json")
        # In production this would POST the payload to self.url
        print(
            f"[WebhookNotifier] Would POST scan_id={report.scan_id}"
            f" to {self.url} — {len(report.matches)} findings",
            file=sys.stderr,
        )
        # Keep payload accessible for testing
        self._last_payload = payload

    @property
    def last_payload(self) -> dict[str, object] | None:
        """Return the last prepared payload (for testing)."""
        return getattr(self, "_last_payload", None)


__all__ = [
    "Notifier",
    "ConsoleNotifier",
    "JSONFileNotifier",
    "WebhookNotifier",
]
