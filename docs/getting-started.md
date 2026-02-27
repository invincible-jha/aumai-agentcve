# Getting Started with aumai-agentcve

This guide walks you from zero to a working vulnerability scan in under five minutes,
then covers common patterns for integrating `aumai-agentcve` into real projects.

---

## Prerequisites

- Python 3.11 or newer
- `pip` package manager
- A CVE feed file (NVD JSON export or GitHub Security Advisory bulk export)

You do not need a running database, a network connection at scan time, or any cloud
services. Everything runs locally.

---

## Installation

### From PyPI (recommended)

```bash
pip install aumai-agentcve
```

Verify the installation:

```bash
agentcve --version
# aumai-agentcve, version 0.1.0
```

### From source

```bash
git clone https://github.com/aumai/aumai-agentcve.git
cd aumai-agentcve
pip install .
```

### Developer mode (editable install)

Use this if you are contributing to the library or want to test local changes without
reinstalling.

```bash
git clone https://github.com/aumai/aumai-agentcve.git
cd aumai-agentcve
pip install -e ".[dev]"
```

The `[dev]` extra installs `pytest`, `hypothesis`, `ruff`, and `mypy`.

Confirm everything works:

```bash
make test
```

---

## Your First Scan

This section walks you through a complete scan in five steps.

### Step 1: Get a CVE feed

You need CVE data before you can scan. The two main sources are:

**Option A — NVD JSON feed** (comprehensive, updated daily)

Download from the NVD data feeds page:
```bash
# Download recent CVEs (last 8 days)
curl -o nvd-recent.json \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
```

The NVD API returns a dict with a `"vulnerabilities"` key. `aumai-agentcve` handles this
structure automatically via `NVDFeedParser`.

**Option B — GitHub Security Advisory (GHSA) bulk export**

GHSA exports are JSON arrays. Each element is an advisory object. Download from:
`https://github.com/advisories?type=reviewed&ecosystem=pip`

### Step 2: Create a requirements.txt (or use an existing one)

If you do not have a project to scan, create a minimal test file:

```bash
cat > /tmp/test-project/requirements.txt << 'EOF'
requests==2.28.0
pydantic==1.10.0
pillow==9.0.0
numpy>=1.23.0
EOF
```

### Step 3: Run the scan

```bash
agentcve scan \
  --feed nvd-recent.json \
  --project-dir /tmp/test-project
```

You will see output like:

```
Loaded 200 CVEs from nvd-recent.json
Scanned 4 dependencies in test-project
=== Vulnerability Report: test-project ===
Scan ID   : 7f3a1c2d-...
Timestamp : 2025-01-15T10:30:00+00:00
Total deps: 4
Vulnerable: 0
Summary   : No vulnerabilities detected.
```

### Step 4: Save a JSON report

```bash
agentcve scan \
  --feed nvd-recent.json \
  --project-dir /tmp/test-project \
  --output /tmp/vuln-report.json
```

The JSON report is a serialized `VulnerabilityReport` Pydantic model. It can be
loaded back in Python or passed to other tools.

### Step 5: Re-display the report

```bash
agentcve report \
  --scan-id 7f3a1c2d-... \
  --report-file /tmp/vuln-report.json
```

Copy the `scan_id` from the scan output (Step 3) or from the `scan_id` field of the
JSON file.

---

## Common Patterns

### Pattern 1: CI/CD pipeline gate

Integrate `agentcve scan` as a step that fails the build when vulnerabilities are found.

```yaml
# GitHub Actions example
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install agentcve
        run: pip install aumai-agentcve
      - name: Download CVE feed
        run: |
          curl -o nvd-feed.json \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=500"
      - name: Scan dependencies
        run: |
          agentcve scan \
            --feed nvd-feed.json \
            --project-dir . \
            --output vulnerability-report.json \
            --min-confidence 0.7
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnerability-report
          path: vulnerability-report.json
```

`agentcve scan` exits with code 1 when vulnerabilities are found, which causes the
GitHub Actions step to fail. Use `if: always()` on the upload step so the report is
saved even when the scan fails.

---

### Pattern 2: Python API in a deployment health check

Use the Python API in a startup check to block deployment if critical vulnerabilities
are present.

```python
import sys
import json
from pathlib import Path
from aumai_agentcve.core import (
    CVEDatabase,
    DependencyScanner,
    VulnerabilityMatcher,
    ReportGenerator,
)
from aumai_agentcve.models import CVESeverity


def check_vulnerabilities_on_startup(
    feed_path: str,
    project_dir: str,
    block_on_severity: CVESeverity = CVESeverity.critical,
) -> None:
    """Raise RuntimeError if critical vulnerabilities are found."""
    database = CVEDatabase()
    with open(feed_path) as f:
        database.load_json(json.load(f))

    scanner = DependencyScanner()
    deps = scanner.scan_directory(Path(project_dir))

    matcher = VulnerabilityMatcher(database)
    matches = matcher.match(deps, min_confidence=0.7)

    blocking = [
        m for m in matches
        if m.cve.severity == block_on_severity
    ]
    if blocking:
        names = ", ".join(m.cve.cve_id for m in blocking)
        raise RuntimeError(
            f"Deployment blocked: {len(blocking)} critical CVEs found: {names}"
        )


# Call this at application startup
check_vulnerabilities_on_startup(
    feed_path="/data/nvd-latest.json",
    project_dir=".",
)
```

---

### Pattern 3: Scanning multiple projects and aggregating results

```python
from pathlib import Path
from aumai_agentcve.core import (
    CVEDatabase,
    DependencyScanner,
    VulnerabilityMatcher,
    ReportGenerator,
)
import json

# Load CVE data once and reuse across all scans
database = CVEDatabase()
with open("nvd-feed.json") as f:
    database.load_json(json.load(f))

scanner = DependencyScanner()
matcher = VulnerabilityMatcher(database)
generator = ReportGenerator()

project_dirs = [
    Path("/srv/agent-one"),
    Path("/srv/agent-two"),
    Path("/srv/agent-three"),
]

all_reports = []
for project_dir in project_dirs:
    deps = scanner.scan_directory(project_dir)
    matches = matcher.match(deps, min_confidence=0.6)
    report = generator.generate(
        project_name=project_dir.name,
        dependencies=deps,
        matches=matches,
    )
    all_reports.append(report)
    print(f"{project_dir.name}: {report.vulnerable_dependencies} vulnerable packages")

# Find the worst offenders
total_vulns = sum(r.vulnerable_dependencies for r in all_reports)
print(f"\nTotal across all projects: {total_vulns} vulnerable packages")
```

---

### Pattern 4: Pre-processing and caching feeds

Downloading and parsing an NVD feed on every CI run is slow. Pre-process the feed once
and cache the normalized output.

```bash
# One-time setup: normalize the NVD feed
agentcve ingest \
  --feed nvd-full-2024.json \
  --format nvd \
  --output cves-normalized.json

# Subsequent scans use the pre-normalized file (much faster to load)
agentcve scan \
  --feed cves-normalized.json \
  --project-dir .
```

The normalized output is a JSON array of `CVERecord` objects, which loads faster than
the raw NVD format because the `NVDFeedParser` step is skipped.

---

### Pattern 5: Using multiple feeds together

Combine NVD and GHSA data for broader coverage. `CVEDatabase.add_bulk()` deduplicates
by `cve_id`, so overlapping entries are handled safely.

```bash
agentcve scan \
  --feed feeds/nvd-recent.json \
  --feed feeds/ghsa-python.json \
  --feed feeds/ghsa-actions.json \
  --project-dir . \
  --min-confidence 0.6
```

In Python:

```python
from aumai_agentcve.scraper import NVDFeedParser, GitHubAdvisoryParser

database = CVEDatabase()

# Load NVD feed
with open("nvd.json") as f:
    nvd_data = json.load(f)
database.load_json(nvd_data)

# Load GHSA feed
parser = GitHubAdvisoryParser()
with open("ghsa.json") as f:
    ghsa_data = json.load(f)
records = parser.parse_bulk(ghsa_data)
added = database.add_bulk(records)
print(f"GHSA added {added} unique records")
```

---

## Troubleshooting FAQ

**Q: `agentcve scan` reports "No CVE data loaded" even though I passed `--feed`.**

Check that the feed file exists and is valid JSON:
```bash
python -c "import json; json.load(open('nvd.json'))" && echo "Valid JSON"
```
Also verify the path is correct — `--feed` requires the file to exist (`click.Path(exists=True)`).

---

**Q: The scan completes but finds zero dependencies.**

The scanner looks for `requirements-freeze.txt`, `requirements.txt`, and `pyproject.toml`
in the directory. Check that at least one of these files exists:
```bash
ls -la /your/project/ | grep -E "requirements|pyproject"
```
If your project uses a different file name, use `scan_requirements_txt()` directly in
the Python API and pass the file contents.

---

**Q: I get `ValueError: Invalid CVE ID format` when loading a feed.**

A record in the feed has a CVE ID that does not start with `CVE-` or `GHSA-`. This is
a data quality issue in the feed. The `CVERecord` validator enforces this constraint.
Open the feed file and find the offending record, then either fix the ID or filter it
out before passing to `database.load_json()`.

---

**Q: Lots of false positives — unrelated packages are being matched.**

Lower the `min_confidence` threshold cautiously. Instead, try increasing it:
```bash
agentcve scan --feed nvd.json --min-confidence 0.8
```
High-confidence matches (>= 0.8) are based on strong name matches. Lower thresholds
may match packages with similar substrings in their names.

---

**Q: The `report` command says "Warning: scan_id mismatch".**

You passed a `--scan-id` value that does not match the `scan_id` stored in the report
file. The tool still displays the report. To get the correct scan ID, read it directly
from the file:
```bash
python -c "import json; print(json.load(open('report.json'))['scan_id'])"
```

---

**Q: How do I run this in a Docker container?**

```dockerfile
FROM python:3.11-slim
RUN pip install aumai-agentcve
COPY . /app
WORKDIR /app
# Mount or COPY your CVE feed as /feeds/nvd.json
CMD ["agentcve", "scan", "--feed", "/feeds/nvd.json", "--project-dir", "/app"]
```

---

**Q: `pip install aumai-agentcve` fails with a build error on Python 3.10.**

Python 3.11 is required (the code uses `str | None` union syntax and `datetime(tz=UTC)`
which require 3.10+ syntax but some features require 3.11 stdlib improvements). Upgrade:
```bash
python --version  # must be 3.11 or newer
```
