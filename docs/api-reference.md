# API Reference — aumai-agentcve

Complete reference for all public classes, functions, and models in `aumai-agentcve`.

---

## Module: `aumai_agentcve.models`

Pydantic data models used throughout the library. All models are validated at
instantiation time.

---

### `CVESeverity`

```python
class CVESeverity(str, Enum):
```

CVSS-aligned severity classification for CVE records.

**Values:**

| Value | String | Description |
|---|---|---|
| `CVESeverity.critical` | `"critical"` | CVSS base score >= 9.0; highest risk |
| `CVESeverity.high` | `"high"` | CVSS base score 7.0–8.9 |
| `CVESeverity.medium` | `"medium"` | CVSS base score 4.0–6.9 |
| `CVESeverity.low` | `"low"` | CVSS base score 0.1–3.9 |
| `CVESeverity.unknown` | `"unknown"` | Severity not yet assessed |

Being a `str` Enum, values serialize to their string representation in JSON.

---

### `CVERecord`

```python
class CVERecord(BaseModel):
```

Represents a single CVE entry from NVD or GitHub Security Advisories.

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `cve_id` | `str` | Yes | CVE identifier. Validated: must start with `CVE-` or `GHSA-`. Normalized to uppercase on input. |
| `description` | `str` | Yes | Human-readable vulnerability description. |
| `severity` | `CVESeverity` | No | Severity level. Defaults to `CVESeverity.unknown`. |
| `cvss_score` | `float \| None` | No | Numeric CVSS score. Constrained to range [0.0, 10.0]. Defaults to `None`. |
| `published_date` | `datetime` | Yes | UTC publication date of the CVE. |
| `affected_packages` | `list[str]` | No | List of affected package names. Defaults to `[]`. |
| `references` | `list[str]` | No | List of reference URLs. Defaults to `[]`. |

**Validation:**

- `cve_id` is stripped of whitespace and uppercased automatically.
- If `cve_id` does not start with `CVE-` or `GHSA-`, a `ValueError` is raised.

**Example:**

```python
from datetime import datetime, UTC
from aumai_agentcve.models import CVERecord, CVESeverity

record = CVERecord(
    cve_id="CVE-2024-12345",
    description="Remote code execution via crafted HTTP request",
    severity=CVESeverity.critical,
    cvss_score=9.8,
    published_date=datetime(2024, 6, 1, tzinfo=UTC),
    affected_packages=["mypackage", "mypackage-core"],
    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
)

# GHSA identifiers are also valid
ghsa = CVERecord(
    cve_id="GHSA-abcd-efgh-1234",
    description="SQL injection in ORM layer",
    severity=CVESeverity.high,
    published_date=datetime.now(UTC),
)
```

---

### `DependencyInfo`

```python
class DependencyInfo(BaseModel):
```

Represents a single Python package dependency extracted from a project.

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `str` | Yes | Package name. Automatically normalized to lowercase with hyphens (underscore-to-hyphen). |
| `version` | `str` | Yes | Installed version string. May be an exact version (`"1.2.3"`), a range specifier (`">=1.0,<2.0"`), or `"unknown"`. |
| `source` | `str` | No | Package index source. Defaults to `"pypi"`. |

**Normalization:**

`name` is automatically normalized: `.strip().lower().replace("_", "-")`. This means
`"PyYAML"` becomes `"pyyaml"`, `"scikit_learn"` becomes `"scikit-learn"`.

**Example:**

```python
from aumai_agentcve.models import DependencyInfo

dep = DependencyInfo(name="PyYAML", version="5.4.1")
print(dep.name)    # "pyyaml"
print(dep.version) # "5.4.1"

dep2 = DependencyInfo(name="requests", version=">=2.28.0,<3.0.0")
print(dep2.version) # ">=2.28.0,<3.0.0"
```

---

### `VulnerabilityMatch`

```python
class VulnerabilityMatch(BaseModel):
```

Links a `CVERecord` to a `DependencyInfo` with a confidence score.

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `cve` | `CVERecord` | Yes | The matched CVE record. |
| `dependency` | `DependencyInfo` | Yes | The matched dependency. |
| `match_confidence` | `float` | Yes | Match confidence score, constrained to [0.0, 1.0]. Higher is more certain. |

**Example:**

```python
from aumai_agentcve.models import VulnerabilityMatch

match = VulnerabilityMatch(
    cve=record,
    dependency=dep,
    match_confidence=0.9,
)
print(f"{match.cve.cve_id} matched {match.dependency.name} at {match.match_confidence:.0%}")
```

---

### `VulnerabilityReport`

```python
class VulnerabilityReport(BaseModel):
```

Complete scan report for a project. Self-contained: includes all matched CVEs and
dependency data. Can be serialized to JSON and reloaded without information loss.

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `scan_id` | `str` | Yes | UUID string generated at report creation time. Used for report replay. |
| `timestamp` | `datetime` | Yes | UTC timestamp when the report was generated. |
| `project_name` | `str` | Yes | Name of the scanned project. |
| `total_dependencies` | `int` | Yes | Total number of dependencies scanned. Must be >= 0. |
| `vulnerable_dependencies` | `int` | Yes | Number of packages with at least one vulnerability match. Must be >= 0. |
| `matches` | `list[VulnerabilityMatch]` | No | All vulnerability matches. Defaults to `[]`. |
| `summary` | `str` | No | Human-readable summary sentence. Defaults to `""`. |

**Example:**

```python
import json
from aumai_agentcve.models import VulnerabilityReport

# Reload from JSON
with open("report.json") as f:
    data = json.load(f)
report = VulnerabilityReport.model_validate(data)
print(f"Report {report.scan_id}: {report.summary}")
```

---

## Module: `aumai_agentcve.core`

The four main operational classes. Import them from `aumai_agentcve.core`.

---

### `DependencyScanner`

```python
class DependencyScanner:
```

Extracts `DependencyInfo` objects from Python project dependency files.

**Constructor:**

```python
DependencyScanner()
```

No arguments. Stateless — the same instance can scan multiple projects.

---

#### `scan_requirements_txt(content: str) -> list[DependencyInfo]`

Parse the string content of a `requirements.txt` file.

**Parameters:**
- `content` (`str`) — The raw text content of a `requirements.txt` file.

**Returns:** `list[DependencyInfo]` — One entry per valid dependency line.

**Handles:**
- Exact pins: `package==1.2.3`
- Range constraints: `package>=1.0,<2.0` (version stored as the full specifier)
- PEP 440 direct references: `package @ https://...` (version set to `"unknown"`)
- Inline comments stripped
- Blank lines, comment lines, and `-r` include directives are skipped
- Lines starting with `http://` or `https://` are skipped

**Example:**

```python
scanner = DependencyScanner()
content = """
requests==2.28.0
pydantic>=1.10,<2.0  # runtime validation
# numpy is optional
-r base-requirements.txt
"""
deps = scanner.scan_requirements_txt(content)
# [DependencyInfo(name='requests', version='2.28.0'),
#  DependencyInfo(name='pydantic', version='>=1.10,<2.0')]
```

---

#### `scan_pip_freeze(content: str) -> list[DependencyInfo]`

Parse the string output of `pip freeze`.

**Parameters:**
- `content` (`str`) — Output of `pip freeze`, one `name==version` per line.

**Returns:** `list[DependencyInfo]` — One entry per `name==version` line. Lines without
`==` (e.g., editable installs `-e .`) are skipped.

**Example:**

```python
import subprocess
freeze_output = subprocess.check_output(["pip", "freeze"]).decode()
deps = scanner.scan_pip_freeze(freeze_output)
```

---

#### `scan_pyproject_toml(content: str) -> list[DependencyInfo]`

Parse the string content of a `pyproject.toml` file.

**Parameters:**
- `content` (`str`) — The raw text content of a `pyproject.toml` file.

**Returns:** `list[DependencyInfo]`

**Handles:**
- PEP 517 `[project] dependencies` arrays (inline or multiline)
- Poetry `[tool.poetry.dependencies]` key-value tables
- Poetry `[tool.poetry.dev-dependencies]` tables
- Version constraints are normalized: leading `^`, `~`, `>=`, `<`, `=`, `!` characters
  stripped for Poetry versions; for PEP 517, the full specifier is preserved unless it
  is an exact pin (`==`)
- The `python` key in Poetry sections is skipped
- Extras in package names (e.g., `requests[security]`) are stripped

---

#### `scan_directory(project_dir: Path) -> list[DependencyInfo]`

Auto-discover and scan all dependency files within a project directory.

**Parameters:**
- `project_dir` (`Path`) — Path to the project root directory.

**Returns:** `list[DependencyInfo]` — Deduplicated union of all found dependencies.

**Discovery priority (highest to lowest):**
1. `requirements-freeze.txt` — `pip freeze` format, exact versions
2. `requirements.txt` — PEP 440 format
3. `pyproject.toml` — PEP 517 and Poetry format

Duplicates (same `name==version`) are removed; earlier-priority sources win.

**Example:**

```python
from pathlib import Path
deps = scanner.scan_directory(Path("/srv/my-agent"))
print(f"Found {len(deps)} dependencies")
```

---

### `CVEDatabase`

```python
class CVEDatabase:
```

In-memory store of `CVERecord` objects with search and filter capabilities. Not
thread-safe by default; wrap with a lock for concurrent access.

**Constructor:**

```python
CVEDatabase()
```

Starts empty.

---

#### `add(record: CVERecord) -> None`

Add or overwrite a CVE record by its `cve_id`.

**Parameters:**
- `record` (`CVERecord`) — The CVE record to store.

---

#### `add_bulk(records: list[CVERecord]) -> int`

Add multiple CVE records. Returns the count of **newly added** entries (records whose
`cve_id` was not already present).

**Parameters:**
- `records` (`list[CVERecord]`)

**Returns:** `int` — Count of newly added records.

---

#### `get(cve_id: str) -> CVERecord | None`

Retrieve a single CVE by ID. Returns `None` if not found.

**Parameters:**
- `cve_id` (`str`) — The CVE ID to look up (case-sensitive; use uppercase `CVE-...`).

**Returns:** `CVERecord | None`

---

#### `search_by_package(package_name: str) -> list[CVERecord]`

Return all CVEs whose `affected_packages` list contains the given package name.

**Parameters:**
- `package_name` (`str`) — Package name to search for. Both the query and each package
  in `affected_packages` are normalized (lowercase, underscore-to-hyphen) before
  comparison. Matching is by substring containment.

**Returns:** `list[CVERecord]`

---

#### `filter_by_severity(severity: CVESeverity) -> list[CVERecord]`

Return all CVEs with the given severity level. Exact match.

**Parameters:**
- `severity` (`CVESeverity`)

**Returns:** `list[CVERecord]`

---

#### `all_records() -> list[CVERecord]`

Return all stored CVE records as a list. Order is insertion order (Python dict).

**Returns:** `list[CVERecord]`

---

#### `count` (property)

```python
@property
def count(self) -> int:
```

Total number of stored CVE records.

---

#### `load_json(data: dict[str, Any]) -> int`

Load CVE records from a raw NVD JSON feed dict. Delegates to `NVDFeedParser.parse_dict`.

**Parameters:**
- `data` (`dict[str, Any]`) — Parsed JSON from an NVD feed file.

**Returns:** `int` — Count of newly added records.

---

### `VulnerabilityMatcher`

```python
class VulnerabilityMatcher:
```

Matches project dependencies against CVE database records using confidence scoring.

**Constructor:**

```python
VulnerabilityMatcher(database: CVEDatabase)
```

**Parameters:**
- `database` (`CVEDatabase`) — The CVE database to match against.

---

#### `match(dependencies: list[DependencyInfo], min_confidence: float = 0.5) -> list[VulnerabilityMatch]`

Find all vulnerability matches above the confidence threshold.

**Parameters:**
- `dependencies` (`list[DependencyInfo]`) — Dependencies to check.
- `min_confidence` (`float`) — Minimum confidence score to include in results. Range
  [0.0, 1.0]. Default `0.5`.

**Returns:** `list[VulnerabilityMatch]` — Matches with `match_confidence >= min_confidence`.

---

### `ReportGenerator`

```python
class ReportGenerator:
```

Assembles and renders `VulnerabilityReport` objects. Stateless.

**Constructor:**

```python
ReportGenerator()
```

No arguments.

---

#### `generate(project_name: str, dependencies: list[DependencyInfo], matches: list[VulnerabilityMatch]) -> VulnerabilityReport`

Assemble a `VulnerabilityReport` from scan inputs.

**Parameters:**
- `project_name` (`str`) — The name of the scanned project.
- `dependencies` (`list[DependencyInfo]`) — Full list of scanned dependencies.
- `matches` (`list[VulnerabilityMatch]`) — Matches from `VulnerabilityMatcher.match()`.

**Returns:** `VulnerabilityReport` — A fully populated report with a generated `scan_id`
(UUIDv4) and UTC `timestamp`.

---

#### `to_text(report: VulnerabilityReport) -> str`

Render a report as a human-readable plain-text string.

**Parameters:**
- `report` (`VulnerabilityReport`)

**Returns:** `str` — Multi-line text including header, counts, summary, and per-match
blocks sorted by `match_confidence` descending. Each match includes CVE ID, severity,
dependency name and version, confidence percentage, optional CVSS score, and the first
160 characters of the description.

---

#### `to_json(report: VulnerabilityReport) -> str`

Serialize a report to a JSON string.

**Parameters:**
- `report` (`VulnerabilityReport`)

**Returns:** `str` — Pretty-printed JSON (2-space indent). Uses Pydantic v2's
`model_dump(mode="json")` which serializes `datetime` as ISO 8601 strings and `Enum`
values as their string representation.

---

## Module: `aumai_agentcve` (top-level)

The package `__init__.py` re-exports the five core models for convenient top-level access.

```python
from aumai_agentcve import (
    CVERecord,
    CVESeverity,
    DependencyInfo,
    VulnerabilityMatch,
    VulnerabilityReport,
)
```

**`__version__`** (`str`) — Package version string, e.g. `"0.1.0"`.

---

## Supporting modules

### `aumai_agentcve.scraper`

Parsers for raw CVE feed formats. Not typically called directly — use
`CVEDatabase.load_json()` instead.

**`NVDFeedParser`**

- `parse_dict(data: dict[str, Any]) -> list[CVERecord]` — Parse an NVD JSON API v2
  response dict. Expects a `"vulnerabilities"` key.

**`GitHubAdvisoryParser`**

- `parse_bulk(data: list[dict[str, Any]]) -> list[CVERecord]` — Parse a list of GHSA
  advisory dicts.

### `aumai_agentcve.matcher`

Low-level matching logic. Not typically called directly — use `VulnerabilityMatcher`
instead.

**`find_matches(dependencies: list[DependencyInfo], cve_records: list[CVERecord]) -> list[VulnerabilityMatch]`**

Core matching function. Computes confidence scores for all (dependency, CVE) pairs and
returns all matches with non-zero confidence.

### `aumai_agentcve.notifier`

Output sink classes.

**`ConsoleNotifier`**
- `notify(report: VulnerabilityReport) -> None` — Print a text report to stdout.

**`JSONFileNotifier(output_path: Path)`**
- `notify(report: VulnerabilityReport) -> None` — Write a JSON report to `output_path`.
