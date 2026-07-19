from __future__ import annotations

import inspect
import itertools
import json
from pathlib import Path

import pytest

from o1_crypto_lab.criticality_pair_groups import compile_primary_pair_groups
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
    score_potential_assignment,
)
from o1_crypto_lab.global_factor_bound_scout import (
    LOGICAL_NODE_BYTES,
    GlobalFactorBoundError,
    LogicalBeamNode,
    compile_factor_bound_index,
    compile_pair_order,
    run_certified_bound_queue,
    run_full256_bound_beam,
)
from o1_crypto_lab.proof_parent_criticality import ParentCriticalityField


ROOT = Path(__file__).resolve().parents[1]


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.25,
        source_sha256="12" * 32,
        factors=(
            CriticalityPotentialFactor(
                (1, 2, 258),
                (-1.0, 0.5, 0.25, 1.25, 0.75, -0.25, 1.5, -0.5),
            ),
            CriticalityPotentialFactor(
                (1, 257),
                (-0.5, 0.25, 1.0, -0.75),
            ),
        ),
    )


def _key(first: int, second: int) -> bytes:
    value = (first > 0) | ((second > 0) << 1)
    return bytes((value,)) + bytes(31)


def _exact(field: CriticalityPotentialField, key: bytes, internal: int) -> float:
    return score_potential_assignment(
        field,
        {
            1: 1 if key[0] & 1 else -1,
            2: 1 if key[0] & 2 else -1,
            257: internal,
            258: internal,
        },
    )


def test_pair_order_keeps_frozen_pairs_and_covers_all_bits_once() -> None:
    frozen = tuple(range(1, 127))
    pairs = compile_pair_order(frozen)
    assert pairs[:63] == tuple(zip(frozen[::2], frozen[1::2], strict=True))
    assert pairs[63:] == tuple(zip(range(127, 257, 2), range(128, 257, 2), strict=True))
    assert len(pairs) == 128
    assert {variable for pair in pairs for variable in pair} == set(range(1, 257))
    with pytest.raises(GlobalFactorBoundError, match="frozen pair"):
        compile_pair_order((*frozen[:-1], frozen[0]))


def test_conditional_index_is_sound_for_every_partial_synthetic_assignment() -> None:
    field = _field()
    index = compile_factor_bound_index(field)
    assert index.conditional_entries == 12
    assert index.conditional_table_bytes == 96
    assert index.describe()["unary_key_factors"] == 1
    assert index.describe()["binary_key_factors"] == 1
    for assigned_size in range(3):
        for assigned in itertools.combinations((1, 2), assigned_size):
            for first, second in itertools.product((-1, 1), repeat=2):
                key = _key(first, second)
                bound = index.bound(key, assigned)
                completions = []
                for full_first, full_second in itertools.product((-1, 1), repeat=2):
                    if 1 in assigned and full_first != first:
                        continue
                    if 2 in assigned and full_second != second:
                        continue
                    full = _key(full_first, full_second)
                    completions.extend(_exact(field, full, spin) for spin in (-1, 1))
                assert bound >= max(completions)


def test_real_primary_index_has_exact_frozen_ternary_ledger() -> None:
    config = json.loads(
        (ROOT / "configs/o1c48_pair_envelope_search_v1.json").read_text()
    )
    potential = CriticalityPotentialField.from_bytes(
        (ROOT / config["source"]["primary_potential"]).read_bytes()
    )
    first = compile_factor_bound_index(potential)
    replay = compile_factor_bound_index(potential)
    description = first.describe()
    assert description["factor_count"] == 836
    assert description["unary_key_factors"] == 636
    assert description["binary_key_factors"] == 200
    assert description["conditional_entries"] == 3708
    assert description["conditional_table_bytes"] == 29664
    assert first.table_sha256 == replay.table_sha256
    assert first.serialized_sha256 == replay.serialized_sha256


def test_real_primary_pair_order_matches_the_frozen_plan_then_completion() -> None:
    config = json.loads(
        (ROOT / "configs/o1c48_pair_envelope_search_v1.json").read_text()
    )
    source = config["source"]
    field = ParentCriticalityField.from_bytes((ROOT / source["field"]).read_bytes())
    potential = CriticalityPotentialField.from_bytes(
        (ROOT / source["primary_potential"]).read_bytes()
    )
    plan = compile_primary_pair_groups(field, potential)
    pairs = compile_pair_order(plan.ordered_variables)
    assert pairs[:63] == plan.groups
    remaining = sorted(set(range(1, 257)).difference(plan.ordered_variables))
    assert pairs[63:] == tuple(zip(remaining[::2], remaining[1::2], strict=True))


def test_logical_node_encoding_is_exactly_48_bytes_and_round_trips() -> None:
    node = LogicalBeamNode(bytes(range(32)), 1.25, 17, 91, 3, 4)
    payload = node.to_bytes()
    assert LOGICAL_NODE_BYTES == 48
    assert len(payload) == 48
    assert LogicalBeamNode.from_bytes(payload) == node
    with pytest.raises(GlobalFactorBoundError, match="node payload"):
        LogicalBeamNode.from_bytes(payload[:-1])


def test_small_full256_beam_is_truth_free_deterministic_and_sound() -> None:
    field = _field()
    index = compile_factor_bound_index(field)
    pairs = tuple((2 * i + 1, 2 * i + 2) for i in range(128))

    def evaluate(key: bytes) -> float:
        return _exact(field, key, -1)

    def verify(key: bytes) -> bool:
        return key[0] & 3 == 3

    first = run_full256_bound_beam(index, pairs, evaluate, verify, width=2)
    replay = run_full256_bound_beam(index, pairs, evaluate, verify, width=2)
    assert first.parent_expansions == 255
    assert first.child_bound_evaluations == 1020
    assert first.forward_evaluations == 2
    assert first.public_verifications == 2
    assert first.logical_mutable_state_bytes == 240
    assert first.final_trace_sha256 == replay.final_trace_sha256
    assert first.retained_masks_by_stage == replay.retained_masks_by_stage
    assert all(
        candidate.exact_score <= candidate.originating_bound
        for candidate in first.candidates
    )
    assert "truth" not in inspect.signature(run_full256_bound_beam).parameters


def test_production_width_has_exact_work_counts_without_candidate_materialization() -> (
    None
):
    field = _field()
    index = compile_factor_bound_index(field)
    pairs = tuple((2 * i + 1, 2 * i + 2) for i in range(128))
    result = run_full256_bound_beam(
        index,
        pairs,
        lambda key: _exact(field, key, -1),
        lambda key: False,
    )
    assert result.parent_expansions == 31829
    assert result.child_bound_evaluations == 127316
    assert result.forward_evaluations == 256
    assert result.public_verifications == 256
    assert result.logical_mutable_state_bytes == 24624
    assert result.telemetry_prefix_bytes == sum(
        32 * min(256, 4**stage) for stage in range(1, 129)
    )


def test_exact_score_above_bound_is_a_hard_error() -> None:
    index = compile_factor_bound_index(_field())
    pairs = tuple((2 * i + 1, 2 * i + 2) for i in range(128))
    with pytest.raises(GlobalFactorBoundError, match="exceeds originating"):
        run_full256_bound_beam(
            index,
            pairs,
            lambda key: 1e9,
            lambda key: False,
            width=1,
        )


def test_certified_queue_emits_exact_global_order_without_truth_input() -> None:
    field = _field()
    index = compile_factor_bound_index(field)
    residual = (1, 2)
    fixed = {variable: -1 for variable in range(3, 257)}

    def evaluate(key: bytes) -> float:
        return _exact(field, key, -1)

    result = run_certified_bound_queue(
        index,
        residual,
        fixed,
        evaluate,
        lambda key: key[0] & 3 == 3,
        target_leaves=4,
        maximum_unscored_pops=16,
        maximum_forward_evaluations=4,
        maximum_live_nodes=8,
    )
    expected = sorted(
        range(4),
        key=lambda mask: (
            -evaluate(bytes((mask,)) + bytes(31)),
            mask,
        ),
    )
    assert result.completed
    assert result.limit_reason == "top-k-certified"
    assert [leaf.residual_mask for leaf in result.leaves] == expected
    assert result.forward_evaluations == 4
    assert result.public_verifications == 4
    assert len(result.recovered_keys) == 1
    assert "truth" not in inspect.signature(run_certified_bound_queue).parameters


def test_certified_queue_stops_at_unscored_cap_without_exhaustive_fallback() -> None:
    index = compile_factor_bound_index(_field())
    result = run_certified_bound_queue(
        index,
        (1, 2),
        {variable: -1 for variable in range(3, 257)},
        lambda key: _exact(_field(), key, -1),
        lambda key: False,
        maximum_unscored_pops=1,
        maximum_forward_evaluations=4,
        maximum_live_nodes=8,
    )
    assert not result.completed
    assert result.limit_reason == "unscored-pop-cap"
    assert result.unscored_pops == 1
    assert result.forward_evaluations == 0
