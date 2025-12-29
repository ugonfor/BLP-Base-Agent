"""
Benchmark datasets and utilities for testing Clearance BLP implementation.

Inspired by security research:
- MASLEAK: Multi-agent system IP leakage attacks
- InjecAgent: Indirect prompt injection benchmark
- AgentDojo: Agentic security benchmark
- GenTel-Bench: Prompt injection dataset
"""

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

__all__ = [
    "ALL_BENCHMARKS",
    "MASLEAK_DATASET",
    "INJECAGENT_DATASET",
    "AGENTDOJO_DATASET",
    "OBFUSCATION_DATASET",
    "CHAIN_ATTACK_DATASET",
    "AttackCategory",
    "BenchmarkCase",
    "get_benchmarks_by_category",
    "get_expected_detection_rate",
]
