"""Tests for aumai_agentcve.matcher — package name matching and version ranges."""

from __future__ import annotations

from datetime import UTC

import pytest

from aumai_agentcve.matcher import (
    _normalize,
    _parse_version_tuple,
    find_matches,
    match_package_name,
    version_in_range,
)
from aumai_agentcve.models import CVERecord, DependencyInfo

# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


class TestNormalize:
    @pytest.mark.parametrize(
        ("input_name", "expected"),
        [
            ("requests", "requests"),
            ("LangChain", "langchain"),
            ("langchain_core", "langchain-core"),
            ("langchain.core", "langchain-core"),
            ("langchain  core", "langchain-core"),
            ("  pydantic  ", "pydantic"),
            ("My_Package.Name", "my-package-name"),
        ],
    )
    def test_normalize(self, input_name: str, expected: str) -> None:
        assert _normalize(input_name) == expected


# ---------------------------------------------------------------------------
# match_package_name
# ---------------------------------------------------------------------------


class TestMatchPackageName:
    def test_exact_match_returns_1(self) -> None:
        assert match_package_name("requests", "requests") == 1.0

    def test_exact_match_after_normalization(self) -> None:
        assert match_package_name("langchain_core", "langchain-core") == 1.0

    def test_prefix_match_returns_0_7(self) -> None:
        # "langchain" is a prefix of "langchain-core"
        score = match_package_name("langchain", "langchain-core")
        assert score == 0.7

    def test_suffix_match_returns_0_7(self) -> None:
        # dep contains the CVE name as a suffix
        score = match_package_name("core", "langchain-core")
        assert score == 0.7

    def test_substring_containment_returns_0_5(self) -> None:
        score = match_package_name("chain", "langchain-core")
        assert score == 0.5

    def test_no_match_returns_0(self) -> None:
        assert match_package_name("boto3", "requests") == 0.0

    def test_case_insensitive(self) -> None:
        assert match_package_name("REQUESTS", "requests") == 1.0

    def test_both_normalized_before_comparison(self) -> None:
        assert match_package_name("Pydantic_Core", "pydantic-core") == 1.0

    def test_symmetric_prefix(self) -> None:
        """dep is prefix of cve_package — still 0.7."""
        score = match_package_name("langchain-core-extended", "langchain-core")
        assert score == 0.7


# ---------------------------------------------------------------------------
# _parse_version_tuple
# ---------------------------------------------------------------------------


class TestParseVersionTuple:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("1.2.3", (1, 2, 3)),
            ("0.1.0", (0, 1, 0)),
            ("10.0", (10, 0)),
            ("1", (1,)),
            ("2.0.0.post1", (2, 0, 0)),
            ("1.0.0.dev0", (1, 0, 0)),
            ("1.0.0rc1", (1, 0, 0)),
            ("1.0.0a1", (1, 0, 0)),
            ("1.0.0b2", (1, 0, 0)),
            ("", (0,)),
            ("garbage", (0,)),
        ],
    )
    def test_parse_version(self, version: str, expected: tuple[int, ...]) -> None:
        assert _parse_version_tuple(version) == expected


# ---------------------------------------------------------------------------
# version_in_range
# ---------------------------------------------------------------------------


class TestVersionInRange:
    @pytest.mark.parametrize(
        ("version", "affected_range", "expected"),
        [
            # Strict less-than
            ("2.28.0", "<2.32.0", True),
            ("2.32.0", "<2.32.0", False),
            ("2.33.0", "<2.32.0", False),
            # Less-than-or-equal
            ("2.32.0", "<=2.32.0", True),
            ("2.32.1", "<=2.32.0", False),
            # Greater-than
            ("3.0.0", ">2.0.0", True),
            ("2.0.0", ">2.0.0", False),
            # Greater-than-or-equal
            ("2.0.0", ">=2.0.0", True),
            ("1.9.9", ">=2.0.0", False),
            # Exact match
            ("1.2.3", "==1.2.3", True),
            ("1.2.4", "==1.2.3", False),
            # Not-equal
            ("1.2.3", "!=1.2.3", False),
            ("1.2.4", "!=1.2.3", True),
            # Bare version (exact match)
            ("1.0.0", "1.0.0", True),
            ("1.0.1", "1.0.0", False),
            # Compound range — both conditions must hold
            ("1.5.0", ">=1.0,<2.0", True),
            ("2.0.0", ">=1.0,<2.0", False),
            ("0.9.0", ">=1.0,<2.0", False),
            # Empty range — always True
            ("1.0.0", "", True),
        ],
    )
    def test_version_in_range(
        self, version: str, affected_range: str, expected: bool
    ) -> None:
        assert version_in_range(version, affected_range) == expected

    def test_pre_release_version_handled(self) -> None:
        # 2.0.0rc1 should parse as (2, 0, 0) — within <2.1.0
        assert version_in_range("2.0.0rc1", "<2.1.0") is True

    def test_post_release_version_handled(self) -> None:
        # 2.31.0.post1 parses as (2, 31, 0) — within <2.32.0
        assert version_in_range("2.31.0.post1", "<2.32.0") is True


# ---------------------------------------------------------------------------
# find_matches
# ---------------------------------------------------------------------------


class TestFindMatches:
    def test_exact_name_match_no_version_range(
        self,
        cve_critical: CVERecord,
        dep_langchain: DependencyInfo,
    ) -> None:
        matches = find_matches([dep_langchain], [cve_critical])
        assert len(matches) == 1
        match = matches[0]
        assert match.cve.cve_id == "CVE-2024-10001"
        assert match.dependency.name == "langchain-core"
        # Exact name (1.0) * 0.8 = 0.8
        assert match.match_confidence == pytest.approx(0.8, abs=0.001)

    def test_version_in_range_match(
        self,
        cve_high: CVERecord,
        dep_requests_old: DependencyInfo,
    ) -> None:
        """requests 2.28.0 is within <2.32.0 — should match."""
        matches = find_matches([dep_requests_old], [cve_high])
        assert len(matches) == 1
        # Exact name (1.0) * 1.0 = 1.0
        assert matches[0].match_confidence == pytest.approx(1.0, abs=0.001)

    def test_version_outside_range_no_match(
        self,
        cve_high: CVERecord,
        dep_requests_new: DependencyInfo,
    ) -> None:
        """requests 2.32.1 is NOT within <2.32.0 — should not match."""
        matches = find_matches([dep_requests_new], [cve_high])
        assert matches == []

    def test_pydantic_v1_in_range(
        self,
        cve_medium: CVERecord,
        dep_pydantic_v1: DependencyInfo,
    ) -> None:
        matches = find_matches([dep_pydantic_v1], [cve_medium])
        assert len(matches) == 1

    def test_pydantic_v2_out_of_range(
        self,
        cve_medium: CVERecord,
        dep_pydantic_v2: DependencyInfo,
    ) -> None:
        matches = find_matches([dep_pydantic_v2], [cve_medium])
        assert matches == []

    def test_unrelated_dep_no_match(
        self,
        sample_cves: list[CVERecord],
        dep_unrelated: DependencyInfo,
    ) -> None:
        matches = find_matches([dep_unrelated], sample_cves)
        assert matches == []

    def test_cve_with_no_packages_no_match(
        self,
        cve_no_packages: CVERecord,
        dep_langchain: DependencyInfo,
    ) -> None:
        matches = find_matches([dep_langchain], [cve_no_packages])
        assert matches == []

    def test_multiple_deps_multiple_cves(
        self,
        sample_deps: list[DependencyInfo],
        sample_cves: list[CVERecord],
    ) -> None:
        matches = find_matches(sample_deps, sample_cves)
        # langchain-core matches cve_critical, requests matches cve_high (version in range),
        # pydantic matches cve_medium (v1 in range)
        cve_ids = {m.cve.cve_id for m in matches}
        assert "CVE-2024-10001" in cve_ids
        assert "CVE-2024-20002" in cve_ids
        assert "CVE-2024-30003" in cve_ids

    def test_best_confidence_used_when_multiple_packages_in_cve(self) -> None:
        """CVE with two affected package entries — best score wins."""
        from datetime import datetime

        cve = CVERecord(
            cve_id="CVE-2024-MULTI",
            description="Multi-package CVE.",
            published_date=datetime(2024, 1, 1, tzinfo=UTC),
            affected_packages=["langchain", "langchain-core"],
        )
        dep = DependencyInfo(name="langchain-core", version="0.1.0")
        matches = find_matches([dep], [cve])
        assert len(matches) == 1
        # "langchain-core" exact match → 1.0 * 0.8 = 0.8;
        # "langchain" prefix match → 0.7 * 0.8 = 0.56; best = 0.8
        assert matches[0].match_confidence == pytest.approx(0.8, abs=0.001)

    def test_confidence_rounds_to_4_decimal_places(
        self,
        cve_critical: CVERecord,
        dep_langchain: DependencyInfo,
    ) -> None:
        matches = find_matches([dep_langchain], [cve_critical])
        assert len(matches) == 1
        # Verify rounding behaviour (result should be rounded to 4dp)
        conf = matches[0].match_confidence
        assert conf == round(conf, 4)

    def test_empty_deps_returns_empty(self, sample_cves: list[CVERecord]) -> None:
        assert find_matches([], sample_cves) == []

    def test_empty_cves_returns_empty(self, sample_deps: list[DependencyInfo]) -> None:
        assert find_matches(sample_deps, []) == []

    def test_both_empty_returns_empty(self) -> None:
        assert find_matches([], []) == []

    def test_confidence_capped_at_1(self) -> None:
        """Match confidence should never exceed 1.0."""
        from datetime import datetime

        cve = CVERecord(
            cve_id="CVE-2024-CAP",
            description="Confidence cap test.",
            published_date=datetime(2024, 1, 1, tzinfo=UTC),
            affected_packages=["exact-pkg<2.0"],
        )
        dep = DependencyInfo(name="exact-pkg", version="1.0.0")
        matches = find_matches([dep], [cve])
        assert len(matches) == 1
        assert matches[0].match_confidence <= 1.0
