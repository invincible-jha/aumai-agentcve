"""Package name and version matching logic for vulnerability detection."""

from __future__ import annotations

import re

from aumai_agentcve.models import CVERecord, DependencyInfo, VulnerabilityMatch


def _normalize(name: str) -> str:
    """Normalize a package name: lowercase, replace separators."""
    return re.sub(r"[-_. ]+", "-", name.strip().lower())


def match_package_name(cve_package: str, dep_name: str) -> float:
    """Fuzzy-match a CVE-referenced package name against a dependency name.

    Returns a confidence score between 0.0 and 1.0.

    Scoring rules:
    - Exact match after normalization: 1.0
    - One name is a prefix/suffix of the other: 0.7
    - Substring containment: 0.5
    - No match: 0.0
    """
    normalized_cve = _normalize(cve_package)
    normalized_dep = _normalize(dep_name)

    if normalized_cve == normalized_dep:
        return 1.0

    # Check prefix / suffix containment (e.g. "langchain-core" vs "langchain")
    if normalized_dep.startswith(normalized_cve) or normalized_cve.startswith(
        normalized_dep
    ):
        return 0.7

    if normalized_dep.endswith(normalized_cve) or normalized_cve.endswith(
        normalized_dep
    ):
        return 0.7

    # Substring containment
    if normalized_cve in normalized_dep or normalized_dep in normalized_cve:
        return 0.5

    return 0.0


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers, ignoring pre/post parts."""
    # Strip common suffixes like .post1, .dev0, rc1, a1, b2
    clean = re.sub(r"[._-]?(post|dev|rc|a|b|alpha|beta)\w*$", "", version.strip())
    parts = re.split(r"[._-]", clean)
    result: list[int] = []
    for part in parts:
        digits = re.match(r"(\d+)", part)
        if digits:
            result.append(int(digits.group(1)))
    return tuple(result) if result else (0,)


def version_in_range(version: str, affected_range: str) -> bool:
    """Check whether a version string falls within an affected range expression.

    Supported range formats:
    - ``<1.2.3``         strictly less than
    - ``<=1.2.3``        less than or equal
    - ``>1.2.3``         strictly greater than
    - ``>=1.2.3``        greater than or equal
    - ``==1.2.3``        exact match
    - ``!=1.2.3``        not equal
    - ``>=1.0,<2.0``     compound (comma-separated)
    - ``1.2.3``          bare version treated as exact match

    Returns True if the version is in the affected range (i.e. vulnerable).
    """
    version_tuple = _parse_version_tuple(version)

    def _check_single(spec: str) -> bool:
        spec = spec.strip()
        if not spec:
            return True

        for operator in ("<=", ">=", "!=", "==", "<", ">"):
            if spec.startswith(operator):
                bound_str = spec[len(operator) :].strip()
                bound_tuple = _parse_version_tuple(bound_str)
                if operator == "<":
                    return version_tuple < bound_tuple
                if operator == "<=":
                    return version_tuple <= bound_tuple
                if operator == ">":
                    return version_tuple > bound_tuple
                if operator == ">=":
                    return version_tuple >= bound_tuple
                if operator == "==":
                    return version_tuple == bound_tuple
                if operator == "!=":
                    return version_tuple != bound_tuple

        # Bare version string — exact match
        return version_tuple == _parse_version_tuple(spec)

    # Compound range: all sub-specs must be satisfied for the version to be affected
    parts = [p.strip() for p in affected_range.split(",") if p.strip()]
    return all(_check_single(part) for part in parts)


def find_matches(
    deps: list[DependencyInfo], cves: list[CVERecord]
) -> list[VulnerabilityMatch]:
    """Find all vulnerability matches between dependencies and CVEs.

    A match is produced when:
    1. A CVE affected_package fuzzy-matches a dependency (confidence >= 0.5).
    2. No version range info available (we flag with confidence = name_score * 0.8)
       OR the installed version falls within an affected range.

    The final confidence combines name similarity and version certainty.
    """
    matches: list[VulnerabilityMatch] = []

    for dep in deps:
        for cve in cves:
            best_name_score = 0.0

            for affected_pkg in cve.affected_packages:
                # affected_packages may carry version range info after a space/colon
                # Format examples: "requests", "requests<2.32.0", "requests>=2.0,<2.32"
                pkg_name_part = re.split(r"[<>=!,]", affected_pkg)[0].strip()
                version_range_part = affected_pkg[len(pkg_name_part) :].strip()

                name_score = match_package_name(pkg_name_part, dep.name)
                if name_score < 0.5:
                    continue

                if version_range_part:
                    in_range = version_in_range(dep.version, version_range_part)
                    if not in_range:
                        continue
                    # High confidence — name matched AND version confirmed in range
                    confidence = name_score * 1.0
                else:
                    # No version range info — reduce confidence slightly
                    confidence = name_score * 0.8

                if confidence > best_name_score:
                    best_name_score = confidence

            if best_name_score >= 0.4:
                matches.append(
                    VulnerabilityMatch(
                        cve=cve,
                        dependency=dep,
                        match_confidence=round(min(best_name_score, 1.0), 4),
                    )
                )

    return matches


__all__ = [
    "match_package_name",
    "version_in_range",
    "find_matches",
]
