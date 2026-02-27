"""Quickstart examples for aumai-agentcve.

Demonstrates the core API: dependency scanning, CVE database loading,
vulnerability matching, and report generation.

Run this file directly to verify your installation:

    python examples/quickstart.py

No external network access is required. The examples use synthetic CVE and
dependency data so that the script runs standalone without downloading feeds.
"""

from __future__ import annotations

from datetime import UTC, datetime

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
# Demo 1: Parse a requirements.txt string into DependencyInfo objects
# ---------------------------------------------------------------------------

def demo_dependency_scanning() -> list[DependencyInfo]:
    """Show how to parse various requirements.txt formats."""
    print("\n" + "=" * 60)
    print("Demo 1: Dependency Scanning")
    print("=" * 60)

    scanner = DependencyScanner()

    # Simulate a real requirements.txt with mixed formats
    requirements_content = """\
# Core dependencies
requests==2.28.0
pydantic>=1.10.0,<3.0.0
pillow==9.0.0        # image processing

# Optional extras
numpy>=1.23.0
langchain @ https://github.com/langchain-ai/langchain/archive/v0.1.0.tar.gz

# Dev dependencies (commented out in production)
# pytest==7.4.0
-r base-requirements.txt
"""

    deps = scanner.scan_requirements_txt(requirements_content)

    print(f"Parsed {len(deps)} dependencies from requirements.txt:")
    for dep in deps:
        print(f"  {dep.name:<30} version={dep.version}")

    # Show pyproject.toml parsing (Poetry format)
    pyproject_content = """\
[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.104.0"
pydantic = "^2.0.0"
httpx = "^0.25.0"
"""
    toml_deps = scanner.scan_pyproject_toml(pyproject_content)
    print(f"\nParsed {len(toml_deps)} dependencies from pyproject.toml (Poetry):")
    for dep in toml_deps:
        print(f"  {dep.name:<30} version={dep.version}")

    # Show pip freeze parsing
    freeze_content = """\
requests==2.31.0
urllib3==2.1.0
certifi==2024.2.2
"""
    freeze_deps = scanner.scan_pip_freeze(freeze_content)
    print(f"\nParsed {len(freeze_deps)} dependencies from pip freeze output:")
    for dep in freeze_deps:
        print(f"  {dep.name:<30} version={dep.version}")

    return deps


# ---------------------------------------------------------------------------
# Demo 2: Build a CVE database from synthetic records
# ---------------------------------------------------------------------------

def demo_cve_database() -> CVEDatabase:
    """Show how to build and query a CVEDatabase."""
    print("\n" + "=" * 60)
    print("Demo 2: CVE Database")
    print("=" * 60)

    database = CVEDatabase()

    # Create synthetic CVE records matching common AI stack packages
    synthetic_cves = [
        CVERecord(
            cve_id="CVE-2024-00001",
            description=(
                "Server-Side Request Forgery in requests library allows "
                "attackers to send arbitrary HTTP requests via crafted URLs."
            ),
            severity=CVESeverity.critical,
            cvss_score=9.1,
            published_date=datetime(2024, 3, 15, tzinfo=UTC),
            affected_packages=["requests"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-00001"],
        ),
        CVERecord(
            cve_id="CVE-2024-00002",
            description=(
                "Buffer overflow in Pillow PNG decoder allows remote code "
                "execution via a crafted PNG image file."
            ),
            severity=CVESeverity.high,
            cvss_score=7.5,
            published_date=datetime(2024, 1, 20, tzinfo=UTC),
            affected_packages=["pillow", "Pillow"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-00002"],
        ),
        CVERecord(
            cve_id="GHSA-abcd-efgh-1234",
            description=(
                "Pydantic validation bypass allows injection of arbitrary "
                "values through specially crafted JSON input."
            ),
            severity=CVESeverity.medium,
            cvss_score=5.3,
            published_date=datetime(2024, 6, 1, tzinfo=UTC),
            affected_packages=["pydantic"],
            references=["https://github.com/advisories/GHSA-abcd-efgh-1234"],
        ),
        CVERecord(
            cve_id="CVE-2024-00003",
            description="Denial of service in numpy via memory allocation exhaustion.",
            severity=CVESeverity.low,
            cvss_score=2.4,
            published_date=datetime(2024, 2, 28, tzinfo=UTC),
            affected_packages=["numpy"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-00003"],
        ),
    ]

    added = database.add_bulk(synthetic_cves)
    print(f"Loaded {added} CVE records into database (total: {database.count})")

    # Demonstrate search and filter
    requests_cves = database.search_by_package("requests")
    print(f"\nCVEs affecting 'requests': {len(requests_cves)}")
    for r in requests_cves:
        print(f"  {r.cve_id}: {r.severity.value} (CVSS {r.cvss_score})")

    critical_cves = database.filter_by_severity(CVESeverity.critical)
    print(f"\nCritical CVEs in database: {len(critical_cves)}")
    for r in critical_cves:
        print(f"  {r.cve_id}: {r.description[:60]}...")

    return database


# ---------------------------------------------------------------------------
# Demo 3: Match dependencies against the CVE database
# ---------------------------------------------------------------------------

def demo_vulnerability_matching(
    deps: list[DependencyInfo],
    database: CVEDatabase,
) -> list[VulnerabilityMatch]:
    """Show how VulnerabilityMatcher links CVEs to dependencies."""
    print("\n" + "=" * 60)
    print("Demo 3: Vulnerability Matching")
    print("=" * 60)

    matcher = VulnerabilityMatcher(database)

    # Use the deps from demo 1, plus add the exact packages from our CVEs
    # to ensure we get matches in this standalone demo
    demo_deps = deps + [
        DependencyInfo(name="requests", version="2.28.0"),
        DependencyInfo(name="pillow", version="9.0.0"),
        DependencyInfo(name="pydantic", version="1.10.5"),
        DependencyInfo(name="numpy", version="1.23.4"),
    ]
    # Deduplicate by name for clean output
    seen: set[str] = set()
    unique_deps: list[DependencyInfo] = []
    for dep in demo_deps:
        if dep.name not in seen:
            seen.add(dep.name)
            unique_deps.append(dep)

    print(f"Matching {len(unique_deps)} dependencies against {database.count} CVEs...")

    # Match with default 50% confidence threshold
    matches = matcher.match(unique_deps, min_confidence=0.5)

    print(f"\nFound {len(matches)} vulnerability match(es):")
    for match in sorted(matches, key=lambda m: m.match_confidence, reverse=True):
        print(
            f"  [{match.cve.severity.value.upper():<10}] "
            f"{match.cve.cve_id}  "
            f"{match.dependency.name}=={match.dependency.version}  "
            f"confidence={match.match_confidence:.0%}"
        )

    return matches


# ---------------------------------------------------------------------------
# Demo 4: Generate and render a vulnerability report
# ---------------------------------------------------------------------------

def demo_report_generation(
    deps: list[DependencyInfo],
    matches: list[VulnerabilityMatch],
) -> VulnerabilityReport:
    """Show how to generate, render, and serialize a VulnerabilityReport."""
    print("\n" + "=" * 60)
    print("Demo 4: Report Generation")
    print("=" * 60)

    generator = ReportGenerator()

    report = generator.generate(
        project_name="my-ai-agent",
        dependencies=deps,
        matches=matches,
    )

    print(f"Report generated:")
    print(f"  scan_id   : {report.scan_id}")
    print(f"  timestamp : {report.timestamp.isoformat()}")
    print(f"  total deps: {report.total_dependencies}")
    print(f"  vulnerable: {report.vulnerable_dependencies}")
    print(f"  summary   : {report.summary}")

    # Render as text
    print("\n--- Text report ---")
    print(generator.to_text(report))

    # Serialize to JSON
    json_output = generator.to_json(report)
    print(f"--- JSON report (first 300 chars) ---")
    print(json_output[:300] + "...")

    # Demonstrate round-trip: serialize → deserialize
    reloaded = VulnerabilityReport.model_validate_json(json_output)
    assert reloaded.scan_id == report.scan_id, "Round-trip failed!"
    print(f"\nJSON round-trip verified: scan_id={reloaded.scan_id}")

    return report


# ---------------------------------------------------------------------------
# Demo 5: Working with models directly
# ---------------------------------------------------------------------------

def demo_model_validation() -> None:
    """Show Pydantic model validation and normalization."""
    print("\n" + "=" * 60)
    print("Demo 5: Model Validation and Normalization")
    print("=" * 60)

    # Package name normalization
    dep = DependencyInfo(name="PyYAML", version="6.0.1")
    print(f"Input name 'PyYAML' → normalized: '{dep.name}'")

    dep2 = DependencyInfo(name="scikit_learn", version="1.3.0")
    print(f"Input name 'scikit_learn' → normalized: '{dep2.name}'")

    # CVE ID validation
    try:
        CVERecord(
            cve_id="INVALID-123",
            description="test",
            published_date=datetime.now(UTC),
        )
    except ValueError as e:
        print(f"\nCVE ID validation caught: {e}")

    # Valid GHSA identifier
    ghsa = CVERecord(
        cve_id="ghsa-xxxx-yyyy-zzzz",   # lowercase — gets normalized to uppercase
        description="Test advisory",
        published_date=datetime.now(UTC),
    )
    print(f"Lowercase GHSA ID normalized: '{ghsa.cve_id}'")

    # Severity is optional — defaults to unknown
    minimal_cve = CVERecord(
        cve_id="CVE-2024-99999",
        description="Minimal CVE record",
        published_date=datetime.now(UTC),
    )
    print(f"Default severity: {minimal_cve.severity.value}")
    print(f"Default cvss_score: {minimal_cve.cvss_score}")
    print(f"Default affected_packages: {minimal_cve.affected_packages}")


# ---------------------------------------------------------------------------
# Main: run all demos in sequence
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all quickstart demos."""
    print("aumai-agentcve Quickstart")
    print("=" * 60)
    print("Running 5 demos to exercise the core API...\n")

    # Demo 1: Parse dependencies
    deps = demo_dependency_scanning()

    # Demo 2: Build CVE database
    database = demo_cve_database()

    # Demo 3: Match vulnerabilities
    matches = demo_vulnerability_matching(deps, database)

    # Demo 4: Generate report
    demo_report_generation(deps + [
        DependencyInfo(name="requests", version="2.28.0"),
        DependencyInfo(name="pillow", version="9.0.0"),
    ], matches)

    # Demo 5: Model validation
    demo_model_validation()

    print("\n" + "=" * 60)
    print("All demos completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
