from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.chacha_trace import chacha20_block
from o1_crypto_lab.full256_cnf import (
    ClauseCollector,
    build_full256_formula,
    clauses_satisfied,
)
from o1_crypto_lab.full256_forward_assignment import (
    compile_full256_forward_read_plan,
)


ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_MAP = (
    ROOT
    / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1"
    / "artifacts/cnf/full256_chacha20.map.json"
)


def test_forward_assignment_satisfies_complete_functional_formula() -> None:
    key = bytes(range(32))
    counter = 7
    nonce = bytes(range(12))
    plan = compile_full256_forward_read_plan(SEMANTIC_MAP, range(1, 32_129))
    spins = plan.evaluate(key=key, counter=counter, nonce=nonce)
    output = bytes(
        sum((1 << bit) if spins[385 + 8 * byte + bit] > 0 else 0 for bit in range(8))
        for byte in range(64)
    )
    assert output == chacha20_block(key, counter, nonce)

    collector = ClauseCollector()
    stats = build_full256_formula(collector)
    assert stats.variable_count == 32_128
    assignment = {variable: spin > 0 for variable, spin in spins.items()}
    assert clauses_satisfied(collector.clauses, assignment)
