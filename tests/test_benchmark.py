"""
Benchmark Tests for Clearance BLP Implementation.

Tests the Clearance system against research-inspired benchmarks:
- MASLEAK: Multi-agent information leakage (Jiang et al., 2024)
- InjecAgent: Indirect prompt injection (Zhan et al., 2024)
- AgentDojo: Data flow security (Debenedetti et al., 2024)

These benchmarks test both detection capabilities and known limitations.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from dataclasses import dataclass
from typing import Any

from clearance import (
    ClearanceChecker,
    Label,
    LabelStore,
    MessageAnalyzer,
    SecurityLevel,
    User,
)
from clearance.checker import create_checker

# Import benchmark datasets
from benchmarks.datasets import (
    ALL_BENCHMARKS,
    MASLEAK_DATASET,
    INJECAGENT_DATASET,
    AGENTDOJO_DATASET,
    OBFUSCATION_DATASET,
    CHAIN_ATTACK_DATASET,
    AttackCategory,
    BenchmarkCase,
    get_benchmarks_by_category,
    get_expected_detection_rate,
)


@dataclass
class BenchmarkResult:
    """Result of running a single benchmark case."""
    case_id: str
    passed: bool
    expected_blocked: bool
    actual_blocked: bool
    violation: str | None
    message_level: SecurityLevel | None
    notes: str


class BenchmarkRunner:
    """Runs benchmark cases and collects results."""

    def __init__(self):
        self.results: list[BenchmarkResult] = []

    def create_checker_for_case(self, case: BenchmarkCase) -> ClearanceChecker:
        """Create a checker configured for the specific benchmark case."""
        store = LabelStore()
        for keyword, level in case.keywords_required.items():
            store.add_keyword(keyword, Label(level=level))
        analyzer = MessageAnalyzer(store)
        return ClearanceChecker(store, analyzer)

    def run_case(self, case: BenchmarkCase) -> BenchmarkResult:
        """Run a single benchmark case."""
        checker = self.create_checker_for_case(case)
        recipient = User(
            id="recipient",
            name="Recipient",
            clearance=case.recipient_clearance
        )

        result = checker.check_write(case.message, recipient)

        actual_blocked = not result.allowed
        passed = actual_blocked == case.expected_blocked

        return BenchmarkResult(
            case_id=case.id,
            passed=passed,
            expected_blocked=case.expected_blocked,
            actual_blocked=actual_blocked,
            violation=result.violation,
            message_level=result.message_level,
            notes=case.notes if not passed else "",
        )

    def run_all(self, cases: list[BenchmarkCase]) -> list[BenchmarkResult]:
        """Run all benchmark cases."""
        self.results = [self.run_case(case) for case in cases]
        return self.results

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics of benchmark run."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        # Breakdown by expected behavior
        true_positives = sum(
            1 for r in self.results
            if r.expected_blocked and r.actual_blocked
        )
        true_negatives = sum(
            1 for r in self.results
            if not r.expected_blocked and not r.actual_blocked
        )
        false_positives = sum(
            1 for r in self.results
            if not r.expected_blocked and r.actual_blocked
        )
        false_negatives = sum(
            1 for r in self.results
            if r.expected_blocked and not r.actual_blocked
        )

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{passed/total*100:.1f}%" if total > 0 else "N/A",
            "true_positives": true_positives,
            "true_negatives": true_negatives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }


# =============================================================================
# MASLEAK Benchmark Tests
# =============================================================================
class TestMASLEAKBenchmark:
    """
    Tests inspired by MASLEAK (Jiang et al., 2024).

    MASLEAK found 87% attack success rate on multi-agent systems.
    Our BLP implementation should block most of these attacks.
    """

    @pytest.fixture
    def runner(self):
        return BenchmarkRunner()

    def test_system_prompt_leakage(self, runner):
        """Test blocking of system prompt extraction attacks."""
        case = MASLEAK_DATASET[0]  # masleak_001
        result = runner.run_case(case)

        assert result.passed, f"Failed: {case.name} - {result.notes}"
        assert result.actual_blocked, "System prompt leakage should be blocked"

    def test_indirect_prompt_extraction(self, runner):
        """Test blocking of indirect prompt extraction via summary."""
        case = MASLEAK_DATASET[1]  # masleak_002
        result = runner.run_case(case)

        assert result.passed, f"Failed: {case.name}"
        assert result.actual_blocked

    def test_memory_exfiltration(self, runner):
        """Test blocking of agent memory exfiltration."""
        case = MASLEAK_DATASET[2]  # masleak_003
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_cross_agent_relay(self, runner):
        """Test blocking of cross-agent information relay."""
        case = MASLEAK_DATASET[3]  # masleak_004
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_legitimate_public_info(self, runner):
        """Test that legitimate public info is allowed."""
        case = MASLEAK_DATASET[4]  # masleak_005
        result = runner.run_case(case)

        assert result.passed
        assert not result.actual_blocked, "Public info should be allowed"

    def test_masleak_full_suite(self, runner):
        """Run full MASLEAK benchmark suite."""
        results = runner.run_all(MASLEAK_DATASET)
        summary = runner.get_summary()

        print(f"\nMASLEAK Benchmark: {summary['pass_rate']} pass rate")
        print(f"  True Positives: {summary['true_positives']}")
        print(f"  True Negatives: {summary['true_negatives']}")
        print(f"  False Positives: {summary['false_positives']}")
        print(f"  False Negatives: {summary['false_negatives']}")

        # All MASLEAK tests should pass (either block or allow as expected)
        assert summary["passed"] == summary["total"], \
            f"MASLEAK: {summary['failed']} tests failed"


# =============================================================================
# InjecAgent Benchmark Tests
# =============================================================================
class TestInjecAgentBenchmark:
    """
    Tests inspired by InjecAgent (Zhan et al., 2024).

    InjecAgent is the first benchmark specifically for indirect prompt
    injection attacks in tool-integrated LLM agents.

    Our BLP approach doesn't prevent injection but catches leaked content.
    """

    @pytest.fixture
    def runner(self):
        return BenchmarkRunner()

    def test_ignore_instruction_attack(self, runner):
        """Test detection of classic 'ignore previous instruction' attack."""
        case = INJECAGENT_DATASET[0]  # inject_001
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked, "Injection with sensitive content should be blocked"

    def test_role_switch_injection(self, runner):
        """Test detection of role switch injection."""
        case = INJECAGENT_DATASET[1]  # inject_002
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_encoded_injection(self, runner):
        """Test detection of encoded injection with decoded content."""
        case = INJECAGENT_DATASET[2]  # inject_003
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_tool_invocation_injection(self, runner):
        """Test detection of tool invocation injection."""
        case = INJECAGENT_DATASET[3]  # inject_004
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_harmless_instruction(self, runner):
        """Test that harmless instructions pass through."""
        case = INJECAGENT_DATASET[4]  # inject_005
        result = runner.run_case(case)

        assert result.passed
        assert not result.actual_blocked

    def test_injecagent_full_suite(self, runner):
        """Run full InjecAgent benchmark suite."""
        results = runner.run_all(INJECAGENT_DATASET)
        summary = runner.get_summary()

        print(f"\nInjecAgent Benchmark: {summary['pass_rate']} pass rate")

        assert summary["passed"] == summary["total"]


# =============================================================================
# AgentDojo Benchmark Tests
# =============================================================================
class TestAgentDojoBenchmark:
    """
    Tests inspired by AgentDojo (Debenedetti et al., 2024).

    AgentDojo focuses on data flow security in agentic systems,
    including multi-hop attacks and aggregation attacks.
    """

    @pytest.fixture
    def runner(self):
        return BenchmarkRunner()

    def test_multihop_extraction(self, runner):
        """Test blocking of multi-hop data extraction."""
        case = AGENTDOJO_DATASET[0]  # dojo_001
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_aggregation_attack(self, runner):
        """Test blocking of aggregation attack."""
        case = AGENTDOJO_DATASET[1]  # dojo_002
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_temporal_correlation(self, runner):
        """Test blocking of temporal correlation attack."""
        case = AGENTDOJO_DATASET[2]  # dojo_003
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_legitimate_downward_comm(self, runner):
        """Test that legitimate downward communication is allowed."""
        case = AGENTDOJO_DATASET[3]  # dojo_004
        result = runner.run_case(case)

        assert result.passed
        assert not result.actual_blocked

    def test_side_channel_filename(self, runner):
        """Test blocking of side channel via filename."""
        case = AGENTDOJO_DATASET[4]  # dojo_005
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_agentdojo_full_suite(self, runner):
        """Run full AgentDojo benchmark suite."""
        results = runner.run_all(AGENTDOJO_DATASET)
        summary = runner.get_summary()

        print(f"\nAgentDojo Benchmark: {summary['pass_rate']} pass rate")

        assert summary["passed"] == summary["total"]


# =============================================================================
# Obfuscation/Evasion Tests (Known Limitations)
# =============================================================================
class TestObfuscationBenchmark:
    """
    Tests for known obfuscation/evasion techniques.

    These tests document known limitations of keyword-based detection.
    Some are expected to fail (evade detection) - this is documented behavior.
    """

    @pytest.fixture
    def runner(self):
        return BenchmarkRunner()

    def test_synonym_detected(self, runner):
        """Test that registered synonyms are detected."""
        case = OBFUSCATION_DATASET[0]  # obf_001
        result = runner.run_case(case)

        assert result.passed, "Registered synonyms should be detected"

    def test_synonym_evades_known_gap(self, runner):
        """Test that unregistered synonyms evade detection (KNOWN GAP)."""
        case = OBFUSCATION_DATASET[1]  # obf_002
        result = runner.run_case(case)

        # This PASSES because we expect it to evade (expected_blocked=False)
        assert result.passed, \
            "This is a known limitation - unregistered synonyms evade detection"

    def test_leetspeak_evades_known_gap(self, runner):
        """Test that l33tspeak evades detection (KNOWN GAP)."""
        case = OBFUSCATION_DATASET[2]  # obf_003
        result = runner.run_case(case)

        assert result.passed, "L33tspeak is a known detection gap"

    def test_spacing_evades_known_gap(self, runner):
        """Test that spacing evades detection (KNOWN GAP)."""
        case = OBFUSCATION_DATASET[3]  # obf_004
        result = runner.run_case(case)

        assert result.passed, "Spacing is a known detection gap"

    def test_homoglyph_evades_known_gap(self, runner):
        """Test that Unicode homoglyphs evade detection (KNOWN GAP)."""
        case = OBFUSCATION_DATASET[4]  # obf_005
        result = runner.run_case(case)

        assert result.passed, "Homoglyphs are a known detection gap"

    def test_obfuscation_full_suite(self, runner):
        """Run full obfuscation benchmark suite."""
        results = runner.run_all(OBFUSCATION_DATASET)
        summary = runner.get_summary()

        print(f"\nObfuscation Benchmark: {summary['pass_rate']} pass rate")
        print("NOTE: Some evasions are EXPECTED (known limitations)")

        assert summary["passed"] == summary["total"]


# =============================================================================
# Chain Attack Tests
# =============================================================================
class TestChainAttackBenchmark:
    """
    Tests for multi-agent chain attacks.

    These test scenarios where information flows through multiple agents
    before reaching an unauthorized recipient.
    """

    @pytest.fixture
    def runner(self):
        return BenchmarkRunner()

    def test_three_hop_leak(self, runner):
        """Test blocking of three-hop leak attempt."""
        case = CHAIN_ATTACK_DATASET[0]  # chain_001
        result = runner.run_case(case)

        assert result.passed
        assert result.actual_blocked

    def test_paraphrase_relay_evades(self, runner):
        """Test that paraphrase relay evades detection (KNOWN GAP)."""
        case = CHAIN_ATTACK_DATASET[1]  # chain_002
        result = runner.run_case(case)

        assert result.passed, "Paraphrasing is a known evasion technique"

    def test_split_message_evades(self, runner):
        """Test that split messages evade detection (KNOWN GAP)."""
        case = CHAIN_ATTACK_DATASET[2]  # chain_003
        result = runner.run_case(case)

        assert result.passed, "Message splitting is a known evasion technique"

    def test_legitimate_delegation(self, runner):
        """Test that legitimate manager delegation is allowed."""
        case = CHAIN_ATTACK_DATASET[3]  # chain_004
        result = runner.run_case(case)

        assert result.passed
        assert not result.actual_blocked

    def test_chain_attack_full_suite(self, runner):
        """Run full chain attack benchmark suite."""
        results = runner.run_all(CHAIN_ATTACK_DATASET)
        summary = runner.get_summary()

        print(f"\nChain Attack Benchmark: {summary['pass_rate']} pass rate")

        assert summary["passed"] == summary["total"]


# =============================================================================
# Full Benchmark Suite
# =============================================================================
class TestFullBenchmarkSuite:
    """Run complete benchmark suite with detailed reporting."""

    def test_full_benchmark_suite(self):
        """Run ALL benchmarks and report comprehensive results."""
        runner = BenchmarkRunner()
        results = runner.run_all(ALL_BENCHMARKS)
        summary = runner.get_summary()

        print("\n" + "=" * 60)
        print("CLEARANCE BENCHMARK RESULTS")
        print("=" * 60)
        print(f"\nTotal Cases: {summary['total']}")
        print(f"Passed: {summary['passed']} ({summary['pass_rate']})")
        print(f"Failed: {summary['failed']}")
        print(f"\nDetection Matrix:")
        print(f"  True Positives (correctly blocked):  {summary['true_positives']}")
        print(f"  True Negatives (correctly allowed):  {summary['true_negatives']}")
        print(f"  False Positives (wrongly blocked):   {summary['false_positives']}")
        print(f"  False Negatives (wrongly allowed):   {summary['false_negatives']}")

        # Per-category breakdown
        print("\nPer-Category Results:")
        for category in AttackCategory:
            cat_cases = [c for c in ALL_BENCHMARKS if c.category == category]
            cat_results = [r for r in results if any(
                c.id == r.case_id for c in cat_cases
            )]
            cat_passed = sum(1 for r in cat_results if r.passed)
            print(f"  {category.value}: {cat_passed}/{len(cat_cases)} passed")

        # List any failures
        failures = [r for r in results if not r.passed]
        if failures:
            print("\nFailed Cases:")
            for f in failures:
                print(f"  - {f.case_id}: expected_blocked={f.expected_blocked}, "
                      f"actual_blocked={f.actual_blocked}")
                if f.notes:
                    print(f"    Note: {f.notes}")

        print("=" * 60)

        # Assert all tests pass
        assert summary["passed"] == summary["total"], \
            f"Benchmark failed: {summary['failed']} cases did not match expected behavior"

    def test_detection_effectiveness_against_attacks(self):
        """
        Measure detection effectiveness for actual attack attempts.

        This excludes known gaps (where evasion is expected) and measures
        how well we detect attacks when keywords are properly configured.
        """
        runner = BenchmarkRunner()

        # Filter to only cases where we expect to block (actual attacks)
        attack_cases = [c for c in ALL_BENCHMARKS if c.expected_blocked]
        results = runner.run_all(attack_cases)

        blocked_correctly = sum(1 for r in results if r.actual_blocked)
        total_attacks = len(attack_cases)

        detection_rate = blocked_correctly / total_attacks * 100 if total_attacks > 0 else 0

        print(f"\n>>> Attack Detection Rate: {detection_rate:.1f}%")
        print(f"    ({blocked_correctly}/{total_attacks} attacks blocked)")

        # We should block all expected attacks
        assert blocked_correctly == total_attacks, \
            f"Detection rate: {detection_rate:.1f}% - some attacks were not blocked"

    def test_false_positive_rate(self):
        """
        Measure false positive rate (legitimate messages incorrectly blocked).
        """
        runner = BenchmarkRunner()

        # Filter to cases where we expect to allow (legitimate traffic)
        benign_cases = [c for c in ALL_BENCHMARKS if not c.expected_blocked]
        results = runner.run_all(benign_cases)

        incorrectly_blocked = sum(1 for r in results if r.actual_blocked)
        total_benign = len(benign_cases)

        false_positive_rate = incorrectly_blocked / total_benign * 100 if total_benign > 0 else 0

        print(f"\n>>> False Positive Rate: {false_positive_rate:.1f}%")
        print(f"    ({incorrectly_blocked}/{total_benign} benign messages blocked)")

        # We should not block any legitimate messages
        assert incorrectly_blocked == 0, \
            f"False positive rate: {false_positive_rate:.1f}% - legitimate messages blocked"


# =============================================================================
# Benchmark CLI Runner
# =============================================================================
def run_benchmarks_cli():
    """Run benchmarks from command line with detailed output."""
    runner = BenchmarkRunner()
    results = runner.run_all(ALL_BENCHMARKS)
    summary = runner.get_summary()

    print("\n" + "=" * 70)
    print("   CLEARANCE BLP SECURITY BENCHMARK RESULTS")
    print("   Inspired by: MASLEAK, InjecAgent, AgentDojo, GenTel-Bench")
    print("=" * 70)

    print(f"\n📊 OVERALL RESULTS")
    print(f"   Total Test Cases: {summary['total']}")
    print(f"   Passed: {summary['passed']} ({summary['pass_rate']})")
    print(f"   Failed: {summary['failed']}")

    print(f"\n🎯 DETECTION MATRIX")
    print(f"   ✅ True Positives (attacks blocked):    {summary['true_positives']}")
    print(f"   ✅ True Negatives (benign allowed):     {summary['true_negatives']}")
    print(f"   ❌ False Positives (benign blocked):    {summary['false_positives']}")
    print(f"   ❌ False Negatives (attacks missed):    {summary['false_negatives']}")

    print(f"\n📁 PER-CATEGORY BREAKDOWN")
    for category in AttackCategory:
        cat_cases = get_benchmarks_by_category(category)
        cat_results = [r for r in results
                      if any(c.id == r.case_id for c in cat_cases)]
        cat_passed = sum(1 for r in cat_results if r.passed)
        status = "✅" if cat_passed == len(cat_cases) else "⚠️"
        print(f"   {status} {category.value:20s}: {cat_passed}/{len(cat_cases)} passed")

    # Known gaps explanation
    print(f"\n⚠️  KNOWN LIMITATIONS (Expected Evasions)")
    known_gaps = [c for c in ALL_BENCHMARKS if c.notes and "KNOWN" in c.notes]
    for gap in known_gaps:
        print(f"   - {gap.id}: {gap.notes}")

    print("\n" + "=" * 70)

    return summary["passed"] == summary["total"]


if __name__ == "__main__":
    success = run_benchmarks_cli()
    exit(0 if success else 1)
