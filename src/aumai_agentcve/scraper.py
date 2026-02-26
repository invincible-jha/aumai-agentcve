"""CVE feed ingestion: NVD JSON feed parser and GitHub Advisory parser."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aumai_agentcve.models import CVERecord, CVESeverity

logger = logging.getLogger(__name__)


def _severity_from_cvss_score(score: float | None) -> CVESeverity:
    """Map a CVSS v3 numeric score to a CVESeverity enum value."""
    if score is None:
        return CVESeverity.unknown
    if score >= 9.0:
        return CVESeverity.critical
    if score >= 7.0:
        return CVESeverity.high
    if score >= 4.0:
        return CVESeverity.medium
    if score > 0.0:
        return CVESeverity.low
    return CVESeverity.unknown


def _severity_from_string(value: str) -> CVESeverity:
    """Convert a string severity label to CVESeverity."""
    mapping: dict[str, CVESeverity] = {
        "critical": CVESeverity.critical,
        "high": CVESeverity.high,
        "medium": CVESeverity.medium,
        "moderate": CVESeverity.medium,
        "low": CVESeverity.low,
        "none": CVESeverity.low,
    }
    return mapping.get(value.lower(), CVESeverity.unknown)


def _parse_nvd_datetime(value: str) -> datetime:
    """Parse NVD datetime strings, which may include a fractional-seconds suffix."""
    # NVD uses ISO 8601 format, e.g. "2024-01-15T12:34:56.123"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Fallback: current time to avoid hard failure
    logger.warning("Could not parse NVD datetime %r, using now()", value)
    return datetime.now(tz=timezone.utc)


def parse_nvd_entry(entry: dict[str, Any]) -> CVERecord | None:
    """Parse a single NVD CVE item dict into a CVERecord.

    Supports NVD JSON Feed 1.1 format (``cve``, ``impact``, ``publishedDate``) and
    NVD API 2.0 format (``id``, ``descriptions``, ``metrics``, ``published``).
    """
    try:
        # --- NVD API 2.0 format ---
        if "id" in entry and "descriptions" in entry:
            cve_id: str = entry["id"]
            descriptions: list[dict[str, str]] = entry.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "",
            )

            # CVSS v3 score
            cvss_score: float | None = None
            severity = CVESeverity.unknown
            metrics: dict[str, Any] = entry.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                items: list[dict[str, Any]] = metrics.get(key, [])
                if items:
                    cvss_data: dict[str, Any] = items[0].get("cvssData", {})
                    raw_score = cvss_data.get("baseScore")
                    if isinstance(raw_score, (int, float)):
                        cvss_score = float(raw_score)
                    raw_sev = cvss_data.get("baseSeverity", "")
                    severity = _severity_from_string(str(raw_sev))
                    break

            if cvss_score is not None and severity == CVESeverity.unknown:
                severity = _severity_from_cvss_score(cvss_score)

            published_str: str = entry.get("published", "")
            published_date = _parse_nvd_datetime(published_str) if published_str else datetime.now(tz=timezone.utc)

            # Affected packages from CPE configuration
            affected_packages: list[str] = []
            configurations: list[dict[str, Any]] = entry.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        criteria: str = cpe_match.get("criteria", "")
                        # CPE format: cpe:2.3:a:vendor:product:version:...
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            product = parts[4]
                            if product and product != "*":
                                pkg_name = product.replace("_", "-")
                                if pkg_name not in affected_packages:
                                    affected_packages.append(pkg_name)

            references: list[str] = [
                ref["url"]
                for ref in entry.get("references", [])
                if "url" in ref
            ]

            return CVERecord(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published_date,
                affected_packages=affected_packages,
                references=references,
            )

        # --- NVD JSON Feed 1.1 format ---
        cve_block: dict[str, Any] = entry.get("cve", {})
        cve_meta: dict[str, Any] = cve_block.get("CVE_data_meta", {})
        cve_id = cve_meta.get("ID", "")
        if not cve_id:
            return None

        desc_data: list[dict[str, str]] = (
            cve_block.get("description", {}).get("description_data", [])
        )
        description = next(
            (d["value"] for d in desc_data if d.get("lang") == "en"), ""
        )

        impact: dict[str, Any] = entry.get("impact", {})
        cvss_score = None
        severity = CVESeverity.unknown
        base_metric_v3: dict[str, Any] = impact.get("baseMetricV3", {})
        if base_metric_v3:
            cvss_v3: dict[str, Any] = base_metric_v3.get("cvssV3", {})
            raw = cvss_v3.get("baseScore")
            if isinstance(raw, (int, float)):
                cvss_score = float(raw)
            severity = _severity_from_string(cvss_v3.get("baseSeverity", ""))

        if cvss_score is not None and severity == CVESeverity.unknown:
            severity = _severity_from_cvss_score(cvss_score)

        published_str = entry.get("publishedDate", "")
        published_date = _parse_nvd_datetime(published_str) if published_str else datetime.now(tz=timezone.utc)

        # Affected packages from CPE nodes
        affected_packages = []
        nodes: list[dict[str, Any]] = (
            entry.get("configurations", {}).get("nodes", [])
        )
        for node in nodes:
            for cpe_match in node.get("cpe_match", []):
                cpe23: str = cpe_match.get("cpe23Uri", "")
                parts = cpe23.split(":")
                if len(parts) >= 5:
                    product = parts[4]
                    if product and product != "*":
                        pkg_name = product.replace("_", "-")
                        if pkg_name not in affected_packages:
                            affected_packages.append(pkg_name)

        references = [
            ref_data["url"]
            for ref_block in cve_block.get("references", {}).get("reference_data", [])
            for ref_data in [ref_block]
            if "url" in ref_data
        ]

        return CVERecord(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            published_date=published_date,
            affected_packages=affected_packages,
            references=references,
        )

    except Exception as exc:
        logger.warning("Failed to parse NVD entry: %s", exc)
        return None


class NVDFeedParser:
    """Parse NVD JSON feeds (dict payload or file path)."""

    def parse_dict(self, data: dict[str, Any]) -> list[CVERecord]:
        """Parse an NVD feed dict.

        Supports both:
        - NVD JSON Feed 1.1: ``{"CVE_Items": [...]}``
        - NVD API 2.0 response: ``{"vulnerabilities": [{"cve": {...}}]}``
        """
        records: list[CVERecord] = []

        # API 2.0 format
        if "vulnerabilities" in data:
            for vuln_wrapper in data["vulnerabilities"]:
                cve_entry: dict[str, Any] = vuln_wrapper.get("cve", vuln_wrapper)
                record = parse_nvd_entry(cve_entry)
                if record is not None:
                    records.append(record)
            return records

        # Feed 1.1 format
        for item in data.get("CVE_Items", []):
            record = parse_nvd_entry(item)
            if record is not None:
                records.append(record)

        return records

    def parse_file(self, path: Path) -> list[CVERecord]:
        """Load and parse an NVD JSON feed file."""
        with path.open(encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
        return self.parse_dict(data)


class GitHubAdvisoryParser:
    """Parse GitHub Security Advisory (GHSA) format entries."""

    def parse_advisory(self, advisory: dict[str, Any]) -> CVERecord | None:
        """Parse a single GHSA advisory dict into a CVERecord.

        Expected fields: ghsaId, summary, description, severity,
        publishedAt, references, vulnerabilities.
        """
        try:
            ghsa_id: str = advisory.get("ghsaId", advisory.get("id", ""))
            if not ghsa_id:
                return None

            # Use GHSA id as cve_id; map aliases to CVE ID if available
            aliases: list[str] = advisory.get("identifiers", [])
            cve_id = ghsa_id
            for alias in aliases:
                if isinstance(alias, dict):
                    if alias.get("type") == "CVE":
                        cve_id = alias["value"]
                        break
                elif isinstance(alias, str) and alias.startswith("CVE-"):
                    cve_id = alias
                    break

            description: str = advisory.get("description", advisory.get("summary", ""))
            severity_str: str = advisory.get("severity", "")
            severity = _severity_from_string(severity_str)

            cvss_score: float | None = None
            cvss_block: dict[str, Any] = advisory.get("cvss", {})
            raw_score = cvss_block.get("score")
            if isinstance(raw_score, (int, float)):
                cvss_score = float(raw_score)
            if cvss_score and severity == CVESeverity.unknown:
                severity = _severity_from_cvss_score(cvss_score)

            published_str: str = advisory.get("publishedAt", advisory.get("published_at", ""))
            published_date = _parse_nvd_datetime(published_str) if published_str else datetime.now(tz=timezone.utc)

            # Extract affected packages
            affected_packages: list[str] = []
            for vuln in advisory.get("vulnerabilities", []):
                package: dict[str, Any] = vuln.get("package", {})
                pkg_name: str = package.get("name", "")
                if pkg_name:
                    # Optionally include version range
                    version_range: str = vuln.get("vulnerableVersionRange", "")
                    if version_range:
                        entry = f"{pkg_name}{version_range}"
                    else:
                        entry = pkg_name
                    if entry not in affected_packages:
                        affected_packages.append(entry)

            references: list[str] = [
                ref["url"] if isinstance(ref, dict) else str(ref)
                for ref in advisory.get("references", [])
            ]

            return CVERecord(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published_date,
                affected_packages=affected_packages,
                references=references,
            )

        except Exception as exc:
            logger.warning("Failed to parse GitHub advisory: %s", exc)
            return None

    def parse_bulk(self, advisories: list[dict[str, Any]]) -> list[CVERecord]:
        """Parse a list of advisory dicts."""
        records: list[CVERecord] = []
        for advisory in advisories:
            record = self.parse_advisory(advisory)
            if record is not None:
                records.append(record)
        return records

    def parse_file(self, path: Path) -> list[CVERecord]:
        """Load and parse a GHSA JSON file (array of advisories)."""
        with path.open(encoding="utf-8") as fh:
            data: list[dict[str, Any]] | dict[str, Any] = json.load(fh)
        if isinstance(data, list):
            return self.parse_bulk(data)
        if isinstance(data, dict):
            record = self.parse_advisory(data)
            return [record] if record else []
        return []


__all__ = [
    "NVDFeedParser",
    "GitHubAdvisoryParser",
    "parse_nvd_entry",
]
