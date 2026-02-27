"""Core pipeline: scanning, database, matching, and report generation."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aumai_agentcve.matcher import find_matches
from aumai_agentcve.models import (
    CVERecord,
    CVESeverity,
    DependencyInfo,
    VulnerabilityMatch,
    VulnerabilityReport,
)


class DependencyScanner:
    """Extract dependency information from various Python project files."""

    def scan_requirements_txt(self, content: str) -> list[DependencyInfo]:
        """Parse requirements.txt file content into DependencyInfo objects.

        Handles:
        - ``package==1.2.3``
        - ``package>=1.0,<2.0``  (stores the full specifier as version)
        - Comments and blank lines
        - ``-r other.txt`` references (skipped)
        - ``package @ url`` PEP 440 direct references
        """
        deps: list[DependencyInfo] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Skip comments, blank lines, options, and URL requirements
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if line.startswith("http://") or line.startswith("https://"):
                continue

            # Strip inline comments
            line = line.split("#")[0].strip()
            if not line:
                continue

            # Handle PEP 440 direct references: name @ url
            if " @ " in line:
                name = line.split(" @ ")[0].strip()
                deps.append(DependencyInfo(name=name, version="unknown"))
                continue

            # Extract name and version specifier
            match = re.match(
                r"^([A-Za-z0-9_.\-]+)\s*([><=!~,\d. *\[\]]+)?", line
            )
            if match:
                pkg_name = match.group(1).strip()
                version_spec = (match.group(2) or "").strip()

                # For exact pins (==) extract just the version number
                exact = re.match(r"^==\s*(.+)$", version_spec)
                version = exact.group(1) if exact else (version_spec or "unknown")
                deps.append(DependencyInfo(name=pkg_name, version=version))

        return deps

    def scan_pip_freeze(self, content: str) -> list[DependencyInfo]:
        """Parse ``pip freeze`` output (``name==version`` per line)."""
        deps: list[DependencyInfo] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" in line:
                parts = line.split("==", 1)
                deps.append(
                    DependencyInfo(name=parts[0].strip(), version=parts[1].strip())
                )
        return deps

    def scan_pyproject_toml(self, content: str) -> list[DependencyInfo]:
        """Parse ``pyproject.toml`` dependency sections.

        Extracts from ``[project] dependencies`` and
        ``[tool.poetry.dependencies]`` sections.
        Handles PEP 517/518 inline metadata.
        """
        deps: list[DependencyInfo] = []
        in_dependencies = False
        in_poetry = False

        for raw_line in content.splitlines():
            line = raw_line.strip()

            # Detect section headers
            if line.startswith("["):
                in_dependencies = line in ("[project]",)
                in_poetry = line in (
                    "[tool.poetry.dependencies]",
                    "[tool.poetry.dev-dependencies]",
                )
                continue

            if in_dependencies:
                # Look for ``dependencies = [...]`` (may be multiline)
                if line.startswith("dependencies"):
                    # Inline list on same line
                    bracket_content = re.search(r"\[([^\]]*)\]", line)
                    if bracket_content:
                        self._parse_pep517_dep_list(bracket_content.group(1), deps)
                    continue

                # Items inside the list block (indented strings)
                item_match = re.match(r'^["\']([^"\']+)["\']', line)
                if item_match:
                    self._parse_pep517_specifier(item_match.group(1), deps)

            elif in_poetry:
                # ``package = "^1.2.3"`` or ``package = {version = "^1.2.3", ...}``
                poetry_match = re.match(
                    r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']([^"\']+)["\']', line
                )
                if poetry_match:
                    pkg = poetry_match.group(1)
                    version = poetry_match.group(2).lstrip("^~>=<!")
                    if pkg.lower() not in ("python",):
                        deps.append(
                            DependencyInfo(name=pkg, version=version or "unknown")
                        )

        return deps

    def _parse_pep517_dep_list(
        self, items_str: str, deps: list[DependencyInfo]
    ) -> None:
        """Parse comma-separated dependency strings from a TOML array."""
        for item in items_str.split(","):
            item = item.strip().strip('"\'')
            if item:
                self._parse_pep517_specifier(item, deps)

    def _parse_pep517_specifier(
        self, specifier: str, deps: list[DependencyInfo]
    ) -> None:
        """Parse a single PEP 508 dependency specifier."""
        # Remove extras like [security]
        specifier = re.sub(r"\[.*?\]", "", specifier).strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~, .\d*\[\]]+)?", specifier)
        if match:
            pkg_name = match.group(1).strip()
            version_spec = (match.group(2) or "").strip()
            exact = re.match(r"^==\s*(.+)$", version_spec)
            version = exact.group(1) if exact else (version_spec or "unknown")
            deps.append(DependencyInfo(name=pkg_name, version=version))

    def scan_directory(self, project_dir: Path) -> list[DependencyInfo]:
        """Auto-discover and scan dependency files in a project directory."""
        deps: list[DependencyInfo] = []
        seen: set[str] = set()

        def _add(new_deps: list[DependencyInfo]) -> None:
            for dep in new_deps:
                key = f"{dep.name}=={dep.version}"
                if key not in seen:
                    seen.add(key)
                    deps.append(dep)

        # Priority order: pip freeze > requirements.txt > pyproject.toml
        pip_freeze = project_dir / "requirements-freeze.txt"
        if pip_freeze.exists():
            _add(self.scan_pip_freeze(pip_freeze.read_text(encoding="utf-8")))

        requirements = project_dir / "requirements.txt"
        if requirements.exists():
            _add(
                self.scan_requirements_txt(
                    requirements.read_text(encoding="utf-8")
                )
            )

        pyproject = project_dir / "pyproject.toml"
        if pyproject.exists():
            _add(
                self.scan_pyproject_toml(pyproject.read_text(encoding="utf-8"))
            )

        return deps


class CVEDatabase:
    """In-memory store of CVERecord objects with search/filter capabilities."""

    def __init__(self) -> None:
        self._records: dict[str, CVERecord] = {}

    def add(self, record: CVERecord) -> None:
        """Add or update a CVE record by its ID."""
        self._records[record.cve_id] = record

    def add_bulk(self, records: list[CVERecord]) -> int:
        """Add multiple records; return count of newly added entries."""
        before = len(self._records)
        for record in records:
            self.add(record)
        return len(self._records) - before

    def get(self, cve_id: str) -> CVERecord | None:
        """Retrieve a CVE by ID."""
        return self._records.get(cve_id)

    def search_by_package(self, package_name: str) -> list[CVERecord]:
        """Return CVEs that reference the given package name (case-insensitive)."""
        name_lower = package_name.lower().replace("_", "-")
        return [
            record
            for record in self._records.values()
            if any(
                name_lower in pkg.lower().replace("_", "-")
                for pkg in record.affected_packages
            )
        ]

    def filter_by_severity(self, severity: CVESeverity) -> list[CVERecord]:
        """Return all CVEs with the given severity level."""
        return [r for r in self._records.values() if r.severity == severity]

    def all_records(self) -> list[CVERecord]:
        """Return all stored CVE records."""
        return list(self._records.values())

    @property
    def count(self) -> int:
        """Total number of stored records."""
        return len(self._records)

    def load_json(self, data: dict[str, Any]) -> int:
        """Load CVE records from a serialized JSON structure (list of records)."""
        from aumai_agentcve.scraper import NVDFeedParser

        parser = NVDFeedParser()
        records = parser.parse_dict(data)
        return self.add_bulk(records)


class VulnerabilityMatcher:
    """Match project dependencies against CVE database records."""

    def __init__(self, database: CVEDatabase) -> None:
        self._database = database

    def match(
        self,
        dependencies: list[DependencyInfo],
        min_confidence: float = 0.5,
    ) -> list[VulnerabilityMatch]:
        """Find all vulnerability matches above the confidence threshold."""
        all_cves = self._database.all_records()
        matches = find_matches(dependencies, all_cves)
        return [m for m in matches if m.match_confidence >= min_confidence]


class ReportGenerator:
    """Generate human-readable and machine-readable vulnerability reports."""

    def generate(
        self,
        project_name: str,
        dependencies: list[DependencyInfo],
        matches: list[VulnerabilityMatch],
    ) -> VulnerabilityReport:
        """Assemble a VulnerabilityReport from scan inputs."""
        vulnerable_dep_names: set[str] = {m.dependency.name for m in matches}
        total_vulns = len(matches)
        critical_count = sum(
            1 for m in matches if m.cve.severity == CVESeverity.critical
        )
        high_count = sum(
            1 for m in matches if m.cve.severity == CVESeverity.high
        )
        summary = (
            f"Found {total_vulns} vulnerabilities"
            f" ({critical_count} critical, {high_count} high)"
            f" across {len(vulnerable_dep_names)} packages."
            if matches
            else "No vulnerabilities detected."
        )

        return VulnerabilityReport(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=UTC),
            project_name=project_name,
            total_dependencies=len(dependencies),
            vulnerable_dependencies=len(vulnerable_dep_names),
            matches=matches,
            summary=summary,
        )

    def to_text(self, report: VulnerabilityReport) -> str:
        """Render the report as a plain-text string."""
        lines: list[str] = [
            f"=== Vulnerability Report: {report.project_name} ===",
            f"Scan ID   : {report.scan_id}",
            f"Timestamp : {report.timestamp.isoformat()}",
            f"Total deps: {report.total_dependencies}",
            f"Vulnerable: {report.vulnerable_dependencies}",
            f"Summary   : {report.summary}",
            "",
        ]
        if not report.matches:
            lines.append("  (no vulnerabilities found)")
        else:
            for match in sorted(
                report.matches, key=lambda m: m.match_confidence, reverse=True
            ):
                cve = match.cve
                dep = match.dependency
                lines.append(
                    f"  [{cve.severity.value.upper():8s}] {cve.cve_id}"
                    f"  {dep.name}=={dep.version}"
                    f"  confidence={match.match_confidence:.0%}"
                )
                if cve.cvss_score is not None:
                    lines.append(f"    CVSS: {cve.cvss_score}")
                lines.append(f"    {cve.description[:160]}")
                lines.append("")

        return "\n".join(lines)

    def to_json(self, report: VulnerabilityReport) -> str:
        """Serialize the report to a JSON string."""
        return json.dumps(report.model_dump(mode="json"), indent=2, default=str)


__all__ = [
    "DependencyScanner",
    "CVEDatabase",
    "VulnerabilityMatcher",
    "ReportGenerator",
]
