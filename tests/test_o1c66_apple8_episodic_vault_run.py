from __future__ import annotations

import json
import hashlib
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping, Sequence, cast

import pytest

import o1_crypto_lab.o1c66_apple8_episodic_vault_run as episodic
from o1_crypto_lab.chacha_trace import chacha20_blocks
from o1_crypto_lab.o1_relational_search import sha256_file


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c66_apple8_episodic_vault_v1.json"
OBSERVED = frozenset(range(1, 301))


def _identity(*, threshold: float = episodic.THRESHOLD) -> episodic.VaultIdentity:
    return episodic.VaultIdentity(
        cnf_sha256="1" * 64,
        potential_sha256="2" * 64,
        grouping_sha256="3" * 64,
        observed_variables_sha256="4" * 64,
        bound_rule_sha256="5" * 64,
        threshold=threshold,
    )


def _empty() -> episodic.ClauseVault:
    return episodic.ClauseVault(_identity(), OBSERVED)


def _memory(peak: int = 300_000_000) -> dict[str, object]:
    return {
        "memory_series_schema": episodic.NATIVE_MEMORY_SERIES_SCHEMA,
        "memory_sample_limit": episodic.MAXIMUM_NATIVE_MEMORY_SAMPLES,
        "memory_sample_count": 2,
        "memory_samples": [
            {"elapsed_seconds": 0.05, "rss_bytes": 200_000_000},
            {"elapsed_seconds": 0.20, "rss_bytes": peak},
        ],
        "memory_peak_bytes": peak,
        "memory_last_bytes": peak,
        "memory_last_elapsed_seconds": 0.20,
    }


def _fake_result(
    input_vault: episodic.ClauseVault,
    emitted: Sequence[tuple[int, ...]] = (),
    *,
    status: int = 0,
    key_model: bytes | None = None,
    terminal_reason: str | None = None,
    terminal_empty: bool = False,
    decisions: int = 4_000,
    propagations: int = 1_000_000,
    billed: int | None = None,
) -> SimpleNamespace:
    if terminal_empty:
        assert terminal_reason == "terminal_empty_clause"
        next_vault = None
    elif terminal_reason is not None:
        next_vault = None
    else:
        next_vault, _novel, _duplicates = input_vault.append_emitted(emitted)
    state = {
        0: (256, "INCONCLUSIVE"),
        10: (32, "SATISFIED"),
        20: (64, "UNSATISFIED"),
    }[status]
    cuts = len(emitted) + int(terminal_empty)
    effective_billed = 513 if billed is None and status == 0 else billed or 100
    input_seen = set(input_vault.clauses)
    episode_seen: set[tuple[int, ...]] = set()
    classifications: list[str] = []
    class_counts = {"new": 0, "input_duplicate": 0, "current_duplicate": 0}
    class_literals = {"new": 0, "input_duplicate": 0, "current_duplicate": 0}
    for clause in emitted:
        if clause in input_seen:
            classification = "input_duplicate"
        elif clause in episode_seen:
            classification = "current_duplicate"
        else:
            classification = "new"
            episode_seen.add(clause)
        classifications.append(classification)
        class_counts[classification] += 1
        class_literals[classification] += len(clause)
    telemetry = {
        "schema": episodic.NATIVE_VAULT_TELEMETRY_SCHEMA,
        "binary_magic_hex": episodic.VAULT_MAGIC.hex(),
        "semantic_rule": (episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE),
        "identity_rule": (episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE),
        "clause_encoding": (episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING),
        "input_certification_rule": (
            episodic._native_v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        ),
        "maximum_payload_bytes": episodic.VAULT_MAXIMUM_SERIALIZED_BYTES,
        "maximum_clause_count": episodic.VAULT_MAXIMUM_CLAUSES,
        "maximum_literal_count": episodic.VAULT_MAXIMUM_LITERALS,
        "input_sha256": input_vault.sha256,
        "input_serialized_bytes": input_vault.serialized_bytes,
        "input_clause_count": len(input_vault.clauses),
        "input_literal_count": input_vault.literal_count,
        "input_clause_aggregate_sha256": input_vault.aggregate_clause_sha256,
        "validated_input_clause_count": len(input_vault.clauses),
        "validated_input_literal_count": input_vault.literal_count,
        "validated_input_clause_aggregate_sha256": (
            input_vault.aggregate_clause_sha256
        ),
        "input_cnf_sha256": input_vault.identity.cnf_sha256,
        "input_potential_sha256": input_vault.identity.potential_sha256,
        "input_grouping_sha256": input_vault.identity.grouping_sha256,
        "input_observed_variables_sha256": (
            input_vault.identity.observed_variables_sha256
        ),
        "input_bound_rule_sha256": input_vault.identity.bound_rule_sha256,
        "input_threshold_f64le_hex": struct.pack(
            "<d", input_vault.identity.threshold
        ).hex(),
        "preloaded_clause_count": len(input_vault.clauses),
        "preloaded_literal_count": input_vault.literal_count,
        "fully_emitted_clause_count": cuts,
        "fully_emitted_literal_count": sum(len(clause) for clause in emitted),
        "emitted_new_clause_count": class_counts["new"],
        "emitted_new_literal_count": class_literals["new"],
        "emitted_input_duplicate_clause_count": class_counts["input_duplicate"],
        "emitted_input_duplicate_literal_count": class_literals["input_duplicate"],
        "emitted_current_duplicate_clause_count": class_counts["current_duplicate"],
        "emitted_current_duplicate_literal_count": class_literals["current_duplicate"],
        "terminal_empty_clause_count": int(terminal_empty),
        "pending_clause_exported": False,
        "next_vault_available": next_vault is not None,
        "next_vault_terminal_reason": terminal_reason,
        "next_vault_sha256": None if next_vault is None else next_vault.sha256,
        "next_serialized_bytes": (
            None if next_vault is None else next_vault.serialized_bytes
        ),
        "next_clause_count": None if next_vault is None else len(next_vault.clauses),
        "next_literal_count": None if next_vault is None else next_vault.literal_count,
    }
    raw = {
        "schema": episodic.NATIVE_RESULT_SCHEMA,
        "implementation_parent_schema": episodic.NATIVE_IMPLEMENTATION_PARENT_SCHEMA,
        "post_solve_state": state[0],
        "post_solve_state_name": state[1],
        "teardown_rule": episodic.TEARDOWN_RULE,
        "pending_backtrack_rule": episodic.PENDING_BACKTRACK_RULE,
        "status": status,
        "vault": telemetry,
    }
    return SimpleNamespace(
        status=status,
        conflict_limit=episodic.REQUESTED_CONFLICTS_PER_EPISODE,
        threshold=episodic.THRESHOLD,
        key_model=key_model,
        stats={
            "requested_conflicts": 512,
            "billed_conflicts": effective_billed,
            "conflict_limit_overshoot": max(0, effective_billed - 512),
            "solve_conflicts": effective_billed,
            "decisions": decisions,
            "propagations": propagations,
        },
        sieve={
            "state": {"schema": episodic.NATIVE_STATE_SCHEMA},
            "external_clauses_emitted": cuts,
            "pending_clause_count": 0,
            "trail_threshold_prunes": cuts,
            "model_threshold_prunes": 0,
            "root_upper_bound": 262.68644197084643,
            "minimum_upper_bound": 12.5,
            "grouping_sha256": episodic.GROUPING_SHA256,
            "grouping_input_sha256": episodic.GROUPING_SHA256,
            "grouping_width_cap": episodic.GROUPING_WIDTH_CAP,
            "grouping_serialized_bytes": episodic.GROUPING_SERIALIZED_BYTES,
            "bound_rule": episodic.COMPATIBILITY_GROUPING_BOUND_RULE,
            "source_sha256": episodic.APPLE8_POTENTIAL_SOURCE_SHA256,
        },
        resources={
            "wall_microseconds": 200_000,
            "cpu_microseconds": 180_000,
            "peak_rss_bytes": 300_000_000,
        },
        raw=raw,
        adapter_memory=_memory(),
        input_vault=input_vault,
        eligible_emitted_clauses=tuple(
            SimpleNamespace(literals=clause, classification=classification)
            for clause, classification in zip(emitted, classifications, strict=True)
        ),
        next_vault=next_vault,
        vault_telemetry=telemetry,
    )


def _frozen_geometry() -> episodic._o1c65.FrozenGrouping:
    potential = episodic._geometry_smoke_potential_path(ROOT)
    return episodic._o1c65.build_frozen_grouping(
        potential,
        {"input": {"potential_sha256": episodic.APPLE8_POTENTIAL_SHA256}},
    )


def _fake_geometry_result(
    frozen: episodic._o1c65.FrozenGrouping,
) -> tuple[episodic._vault_v1.ThresholdNoGoodVault, SimpleNamespace]:
    input_vault = episodic._geometry_smoke_empty_vault(frozen)
    root = episodic.GEOMETRY_SMOKE_GROUPED_ROOT_UPPER_BOUND
    empty_clause = struct.pack("<I", 0)
    clause_sha256 = hashlib.sha256(empty_clause).hexdigest()
    witness_sha256 = hashlib.sha256(
        b"\x01" + struct.pack("<d", root) + empty_clause
    ).hexdigest()
    telemetry: dict[str, object] = {
        name: None for name in episodic._native_v8._VAULT_FIELDS
    }
    telemetry.update(
        {
            "schema": episodic.NATIVE_VAULT_TELEMETRY_SCHEMA,
            "binary_magic_hex": episodic.VAULT_MAGIC.hex(),
            "semantic_rule": (episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE),
            "identity_rule": (episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE),
            "clause_encoding": (
                episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
            ),
            "witness_encoding": (
                episodic._vault_v1.THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING
            ),
            "maximum_payload_bytes": episodic.VAULT_MAXIMUM_SERIALIZED_BYTES,
            "maximum_clause_count": episodic.VAULT_MAXIMUM_CLAUSES,
            "maximum_literal_count": episodic.VAULT_MAXIMUM_LITERALS,
            "input_sha256": input_vault.sha256,
            "input_serialized_bytes": input_vault.serialized_bytes,
            "input_clause_count": 0,
            "input_literal_count": 0,
            "input_clause_aggregate_sha256": (input_vault.clause_aggregate_sha256),
            "input_certification_rule": (
                episodic._native_v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
            ),
            "validated_input_clause_count": 0,
            "validated_input_literal_count": 0,
            "validated_input_clause_aggregate_sha256": (
                input_vault.clause_aggregate_sha256
            ),
            "input_cnf_sha256": episodic.GEOMETRY_SMOKE_CNF_SHA256,
            "input_potential_sha256": episodic.APPLE8_POTENTIAL_SHA256,
            "input_grouping_sha256": episodic.GROUPING_SHA256,
            "input_observed_variables_sha256": (
                input_vault.identity.observed_variables_sha256
            ),
            "input_bound_rule_sha256": episodic.BOUND_RULE_SHA256,
            "input_threshold_f64le_hex": struct.pack(
                "<d", episodic.GEOMETRY_SMOKE_THRESHOLD
            ).hex(),
            "preloaded_clause_count": 0,
            "preloaded_literal_count": 0,
            "fully_emitted_clause_count": 1,
            "fully_emitted_literal_count": 0,
            "emitted_new_clause_count": 0,
            "emitted_new_literal_count": 0,
            "emitted_input_duplicate_clause_count": 0,
            "emitted_input_duplicate_literal_count": 0,
            "emitted_current_duplicate_clause_count": 0,
            "emitted_current_duplicate_literal_count": 0,
            "terminal_empty_clause_count": 1,
            "pending_clause_exported": False,
            "fully_emitted_aggregate_sha256": clause_sha256,
            "fully_emitted_clauses": [
                {
                    "index": 0,
                    "source": "trail_upper_bound",
                    "witness_score": root,
                    "witness_score_f64le_hex": struct.pack("<d", root).hex(),
                    "literal_count": 0,
                    "literals": [],
                    "clause_sha256": clause_sha256,
                    "witness_sha256": witness_sha256,
                    "classification": "terminal_empty",
                }
            ],
            "next_vault_available": False,
            "next_vault_terminal_reason": "terminal_empty_clause",
            "next_vault_sha256": None,
            "next_serialized_bytes": None,
            "next_clause_count": None,
            "next_literal_count": None,
        }
    )
    sieve = {
        "root_upper_bound": root,
        "root_upper_bound_f64le_hex": struct.pack("<d", root).hex(),
        "threshold": episodic.GEOMETRY_SMOKE_THRESHOLD,
        "source_sha256": episodic.APPLE8_POTENTIAL_SOURCE_SHA256,
        "grouping_sha256": episodic.GROUPING_SHA256,
        "grouping_input_sha256": episodic.GROUPING_SHA256,
        "grouping_width_cap": episodic.GROUPING_WIDTH_CAP,
        "grouping_serialized_bytes": episodic.GROUPING_SERIALIZED_BYTES,
        "bound_rule": episodic.COMPATIBILITY_GROUPING_BOUND_RULE,
        "external_clauses_queued": 1,
        "external_clauses_emitted": 1,
        "external_clause_literals": 0,
        "pending_clause_count": 0,
        "trail_threshold_prunes": 1,
        "model_threshold_prunes": 0,
    }
    resources = {
        "wall_microseconds": 200_000,
        "cpu_microseconds": 180_000,
        "peak_rss_bytes": 300_000_000,
    }
    raw: dict[str, object] = {
        name: None for name in episodic._native_v8._TOP_LEVEL_FIELDS
    }
    raw.update(
        {
            "schema": episodic.NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                episodic.NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "cadical_version": "3.0.0",
            "variables": episodic.GEOMETRY_SMOKE_VARIABLES,
            "conflict_limit": episodic.REQUESTED_CONFLICTS_PER_EPISODE,
            "seed": episodic.SEED,
            "threshold": episodic.GEOMETRY_SMOKE_THRESHOLD,
            "status": 20,
            "post_solve_state": 64,
            "post_solve_state_name": "UNSATISFIED",
            "teardown_rule": episodic.TEARDOWN_RULE,
            "pending_backtrack_rule": episodic.PENDING_BACKTRACK_RULE,
            "key_model_hex": None,
            "cnf_sha256": episodic.GEOMETRY_SMOKE_CNF_SHA256,
            "potential_sha256": episodic.APPLE8_POTENTIAL_SHA256,
            "stats": {"solve_conflicts": 0},
            "sieve": sieve,
            "resources": resources,
            "vault": telemetry,
        }
    )
    return input_vault, SimpleNamespace(
        status=20,
        conflict_limit=episodic.REQUESTED_CONFLICTS_PER_EPISODE,
        threshold=episodic.GEOMETRY_SMOKE_THRESHOLD,
        key_model=None,
        stats={
            "requested_conflicts": episodic.REQUESTED_CONFLICTS_PER_EPISODE,
            "billed_conflicts": 0,
            "conflict_limit_overshoot": 0,
            "solve_conflicts": 0,
        },
        sieve=sieve,
        resources=resources,
        raw=raw,
        adapter_memory=_memory(),
        input_vault=input_vault,
        eligible_emitted_clauses=(),
        next_vault=None,
        vault_telemetry=telemetry,
    )


def _execute(
    tmp_path: Path,
    builders: Sequence[Callable[[episodic.ClauseVault], object]],
    *,
    verifier: Callable[[bytes], bool] = lambda _key: False,
) -> tuple[episodic.EpisodeProtocolOutcome, list[int], Path]:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    initial = _empty()
    calls: list[int] = []

    def invoke(ordinal: int, vault_path: Path) -> object:
        calls.append(ordinal)
        current = episodic.read_vault(
            vault_path,
            identity=initial.identity,
            observed_variables=initial.observed_variables,
        )
        return builders[ordinal](current)

    outcome = episodic.execute_episodic_protocol(
        capsule=capsule,
        initial_vault=initial,
        adapter_initial_vault=initial,
        invoke_episode=invoke,
        verify_public_model=verifier,
        intent_bindings={
            "source_commit": "a" * 40,
            "native_source_sha256": "b" * 64,
            "native_executable_sha256": "c" * 64,
            "adapter_sha256": "d" * 64,
            "config_sha256": "e" * 64,
            "cnf_sha256": "1" * 64,
            "potential_sha256": "2" * 64,
            "grouping_sha256": "3" * 64,
            "threshold_f64le_hex": struct.pack("<d", episodic.THRESHOLD).hex(),
        },
    )
    return outcome, calls, capsule


def test_vault_round_trip_first_emission_dedup_and_identity_bits() -> None:
    empty = _empty()
    vault, novel, duplicate = empty.append_emitted(((1, -2), (1, -2), (-3, 4), (1, -2)))
    assert novel == ((1, -2), (-3, 4))
    assert duplicate == 2
    assert (
        episodic.ClauseVault.from_bytes(
            vault.to_bytes(),
            expected_identity=empty.identity,
            observed_variables=OBSERVED,
        )
        == vault
    )
    assert vault.serialized_bytes == 191 + 2 * 4 + 4 * 4

    negative_zero = episodic.ClauseVault(_identity(threshold=-0.0), OBSERVED)
    positive_zero_identity = _identity(threshold=0.0)
    with pytest.raises(episodic.O1C66VaultError, match="semantic identity"):
        episodic.ClauseVault.from_bytes(
            negative_zero.to_bytes(),
            expected_identity=positive_zero_identity,
            observed_variables=OBSERVED,
        )


@pytest.mark.parametrize(
    "clause",
    [(), (0,), (2, 1), (1, -1), (301,), (-(2**31),)],
)
def test_vault_rejects_empty_noncanonical_unobserved_and_i32_min(
    clause: tuple[int, ...],
) -> None:
    with pytest.raises(episodic.O1C66VaultError):
        episodic.ClauseVault(_identity(), OBSERVED, (clause,))


def test_zero_novel_episode_zero_saturates_after_one_call(tmp_path: Path) -> None:
    outcome, calls, capsule = _execute(tmp_path, [lambda vault: _fake_result(vault)])
    assert outcome.classification == episodic.SATURATED_NO_GAIN
    assert outcome.stop_reason == "zero-novel-eligible-clauses"
    assert calls == [0]
    assert outcome.totals["native_solver_calls"] == 1
    intent = json.loads((capsule / "episodes/00/intent.json").read_text())
    assert intent["episode_ordinal"] == 0
    assert intent["episode_is_retry"] is False
    assert intent["policy_state"]["sha256"] == episodic.POLICY_STATE_SHA256
    assert intent["cumulative_call_work_ledger_before"]["native_solver_calls"] == 0


def test_hash_chain_work_ledger_and_strict_post_zero_gain(tmp_path: Path) -> None:
    builders = [
        lambda vault: _fake_result(vault, ((1,),), decisions=4_000),
        lambda vault: _fake_result(vault, ((2,),), decisions=3_900),
        lambda vault: _fake_result(vault, ((2,),), decisions=3_900),
    ]
    outcome, calls, capsule = _execute(tmp_path, builders)
    assert outcome.classification == episodic.STRICT_CUMULATIVE_GAIN
    assert calls == [0, 1, 2]
    assert outcome.final_vault.clauses == ((1,), (2,))
    assert outcome.totals["native_solver_calls"] == 3
    assert outcome.totals["requested_conflicts"] == 1536
    assert outcome.totals["billed_conflicts"] == 1539
    second_intent = json.loads((capsule / "episodes/01/intent.json").read_text())
    first_episode = json.loads((capsule / "episodes/00/episode.json").read_text())
    assert (
        second_intent["previous_vault_sha256"]
        == first_episode["output_vault"]["sha256"]
    )
    assert second_intent["calls_before"] == 1
    assert (
        second_intent["cumulative_call_work_ledger_before"]["requested_conflicts"]
        == 512
    )
    second = outcome.episodes[1]
    assert second["search_delta"] == {
        "decisions_delta_from_episode_zero": -100,
        "propagations_delta_from_episode_zero": 0,
        "search_work_changed_from_episode_zero": True,
    }
    third_eligible = cast(Mapping[str, object], outcome.episodes[2]["eligible_emitted"])
    assert third_eligible["duplicate_clause_count"] == 1


def test_eight_calls_are_episodes_not_retries_and_totals_are_capped(
    tmp_path: Path,
) -> None:
    builders = [
        (lambda ordinal: lambda vault: _fake_result(vault, ((ordinal + 1,),)))(ordinal)
        for ordinal in range(8)
    ]
    outcome, calls, capsule = _execute(tmp_path, builders)
    assert outcome.classification == episodic.STRICT_CUMULATIVE_GAIN
    assert outcome.stop_reason == "maximum-eight-episodes-completed"
    assert calls == list(range(8))
    assert outcome.totals["requested_conflicts"] == 4096
    assert outcome.totals["billed_conflicts"] == 4104
    assert not (capsule / "episodes/08").exists()
    for ordinal in range(8):
        intent = json.loads(
            (capsule / f"episodes/{ordinal:02d}/intent.json").read_text()
        )
        assert intent["episode_is_retry"] is False
        assert intent["calls_before"] == ordinal


def test_crash_consumes_ordinal_and_never_retries(tmp_path: Path) -> None:
    def crash(_vault: episodic.ClauseVault) -> object:
        raise RuntimeError("child crashed")

    outcome, calls, capsule = _execute(
        tmp_path,
        [lambda vault: _fake_result(vault, ((1,),)), crash],
    )
    assert outcome.classification == episodic.OPERATIONAL_TERMINAL
    assert calls == [0, 1]
    assert outcome.totals["native_solver_calls"] == 2
    assert outcome.totals["requested_conflicts"] == 1024
    assert outcome.totals["billed_conflicts"] == 513
    assert outcome.operational_failure is not None
    assert outcome.operational_failure["retry_authorized"] is False
    assert not (capsule / "episodes/02").exists()


def test_timeout_is_resource_terminal_without_retry(tmp_path: Path) -> None:
    def timeout(_vault: episodic.ClauseVault) -> object:
        raise TimeoutError("episode timeout")

    outcome, calls, _capsule = _execute(tmp_path, [timeout])
    assert outcome.classification == episodic.RESOURCE_TERMINAL
    assert calls == [0]


def test_wrapped_watchdog_telemetry_is_resource_terminal_and_preserved(
    tmp_path: Path,
) -> None:
    class WrappedAdapterError(RuntimeError):
        def __init__(self) -> None:
            super().__init__("joint-score-sieve execution failed")
            self.failure_telemetry = {
                "classification_kind": "watchdog_memory",
                "memory_series_schema": episodic.NATIVE_MEMORY_SERIES_SCHEMA,
                "memory_samples": [{"elapsed_seconds": 0.2, "rss_bytes": 500_000_000}],
            }

    def fail(_vault: episodic.ClauseVault) -> object:
        raise WrappedAdapterError

    outcome, calls, _capsule = _execute(tmp_path, [fail])
    assert outcome.classification == episodic.RESOURCE_TERMINAL
    assert calls == [0]
    assert outcome.operational_failure is not None
    telemetry = outcome.operational_failure["adapter_failure_telemetry"]
    assert isinstance(telemetry, dict)
    assert telemetry["classification_kind"] == "watchdog_memory"


def test_capacity_crossing_terminalizes_without_eviction(tmp_path: Path) -> None:
    at_cap = tuple((variable,) for variable in range(1, 257)) + tuple(
        (-variable,) for variable in range(1, 257)
    )

    def capacity(vault: episodic.ClauseVault) -> object:
        assert len(vault.clauses) == episodic.VAULT_MAXIMUM_CLAUSES
        return _fake_result(
            vault,
            ((257,),),
            terminal_reason="capacity_clause_count",
            billed=7,
        )

    outcome, calls, capsule = _execute(
        tmp_path,
        [lambda vault: _fake_result(vault, at_cap), capacity],
    )
    assert outcome.classification == episodic.CAPACITY_TERMINAL
    assert calls == [0, 1]
    assert outcome.totals["billed_conflicts"] == 520
    assert len(outcome.final_vault.clauses) == episodic.VAULT_MAXIMUM_CLAUSES
    assert outcome.operational_failure is not None
    assert outcome.operational_failure["eviction_performed"] is False
    assert not (capsule / "episodes/01/vault-output.bin").exists()


def test_verified_sat_and_threshold_unsat_take_precedence_over_capacity(
    tmp_path: Path,
) -> None:
    key = b"k" * 32
    sat_root = tmp_path / "sat"
    sat_root.mkdir()
    sat, sat_calls, sat_capsule = _execute(
        sat_root,
        [
            lambda vault: _fake_result(
                vault,
                ((1,),),
                status=10,
                key_model=key,
                terminal_reason="capacity_clause_count",
            )
        ],
        verifier=lambda candidate: candidate == key,
    )
    assert sat.classification == episodic.PUBLIC_EXACT_RECOVERY
    assert sat_calls == [0]
    assert not (sat_capsule / "episodes/00/vault-output.bin").exists()

    unsat_root = tmp_path / "unsat"
    unsat_root.mkdir()
    unsat, unsat_calls, unsat_capsule = _execute(
        unsat_root,
        [
            lambda vault: _fake_result(
                vault,
                ((1,),),
                status=20,
                terminal_reason="capacity_clause_count",
            )
        ],
    )
    assert unsat.classification == episodic.THRESHOLD_REGION_EXHAUSTED
    assert unsat_calls == [0]
    assert not (unsat_capsule / "episodes/00/vault-output.bin").exists()


def test_root_empty_unsat_exhausts_threshold_region_not_key_space(
    tmp_path: Path,
) -> None:
    outcome, calls, capsule = _execute(
        tmp_path,
        [
            lambda vault: _fake_result(
                vault,
                status=20,
                terminal_reason="terminal_empty_clause",
                terminal_empty=True,
            )
        ],
    )
    assert outcome.classification == episodic.THRESHOLD_REGION_EXHAUSTED
    assert "threshold-region" in outcome.stop_reason
    assert calls == [0]
    assert outcome.final_vault.clauses == ()
    assert not (capsule / "episodes/00/vault-output.bin").exists()
    episode = outcome.episodes[0]
    assert str(episode["vault_semantic_scope"]).startswith("CNF-and-potential")
    work = cast(Mapping[str, object], episode["work_and_resources"])
    eligible = cast(Mapping[str, object], episode["eligible_emitted"])
    assert work["fully_emitted_cuts"] == 1
    assert eligible["clause_count"] == 0


def test_threshold_unsat_retains_valid_final_emitted_vault_without_sidecar(
    tmp_path: Path,
) -> None:
    outcome, calls, capsule = _execute(
        tmp_path,
        [lambda vault: _fake_result(vault, ((1,),), status=20)],
    )
    assert outcome.classification == episodic.THRESHOLD_REGION_EXHAUSTED
    assert calls == [0]
    assert outcome.final_vault.clauses == ((1,),)
    assert outcome.episodes[0]["output_vault"] == outcome.final_vault.describe()
    assert outcome.episodes[0]["output_vault_archived"] is False
    assert not (capsule / "episodes/00/vault-output.bin").exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("solve_conflicts", 999_999),
        ("billed_conflicts", 1),
        ("conflict_limit_overshoot", 0),
        ("requested_conflicts", 511),
    ],
)
def test_forged_conflict_ledger_is_invalid_and_never_retried(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    def forged(vault: episodic.ClauseVault) -> object:
        result = _fake_result(vault)
        stats = dict(result.stats)
        stats[field] = value
        return SimpleNamespace(**{**result.__dict__, "stats": stats})

    outcome, calls, capsule = _execute(tmp_path, [forged])
    assert outcome.classification == episodic.INVALID_RESULT_TERMINAL
    assert calls == [0]
    assert outcome.totals["native_solver_calls"] == 1
    assert outcome.operational_failure is not None
    assert outcome.operational_failure["retry_authorized"] is False
    assert not (capsule / "episodes/01").exists()


def test_public_verifier_and_recovery_precede_any_truth_diagnostic(
    tmp_path: Path,
) -> None:
    key = bytes(range(32))
    nonce = bytes(range(12))
    counters = tuple(range(8))
    outputs = tuple(chacha20_blocks(key, counter, nonce, 1)[0] for counter in counters)
    target = episodic.PublicTarget(nonce, counters, outputs)
    assert target.verify(key)
    assert not target.verify(bytes(reversed(key)))
    outcome, calls, _capsule = _execute(
        tmp_path,
        [lambda vault: _fake_result(vault, status=10, key_model=key)],
        verifier=target.verify,
    )
    assert outcome.classification == episodic.PUBLIC_EXACT_RECOVERY
    assert calls == [0]
    public = cast(Mapping[str, object], outcome.episodes[0]["public_model"])
    assert public["verified_8_of_8"] is True
    assert public["truth_key_sha256"] is None
    assert public["native_model_equals_committed_truth"] is None
    assert public["truth_key_bytes_read"] is False


def test_forged_sat_model_and_mismatched_next_vault_are_invalid_no_retry(
    tmp_path: Path,
) -> None:
    outcome, calls, _capsule = _execute(
        tmp_path,
        [lambda vault: _fake_result(vault, status=10, key_model=b"x" * 32)],
        verifier=lambda _key: False,
    )
    assert outcome.classification == episodic.INVALID_RESULT_TERMINAL
    assert calls == [0]

    def mismatched(vault: episodic.ClauseVault) -> object:
        result = _fake_result(vault, ((1,),))
        wrong, _novel, _duplicates = vault.append_emitted(((2,),))
        return SimpleNamespace(**{**result.__dict__, "next_vault": wrong})

    other = tmp_path / "other"
    other.mkdir()
    outcome, calls, _capsule = _execute(other, [mismatched])
    assert outcome.classification == episodic.INVALID_RESULT_TERMINAL
    assert calls == [0]


def test_publication_recovery_uses_complete_sidecars_without_new_call(
    tmp_path: Path,
) -> None:
    outcome, calls, capsule = _execute(tmp_path, [lambda vault: _fake_result(vault)])
    # Saturation is known from the complete first episode; its native/vault
    # sidecars are already independently readable.
    assert calls == [0]
    assert (capsule / "episodes/00/native_result.json").is_file()
    authoritative = tmp_path / "authoritative.json"
    result = {
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "resources": {
            "native_solver_calls": 1,
            "persistent_artifact_bytes": 0,
        },
    }
    with pytest.raises(RuntimeError, match="publish fault"):
        episodic.finalize_capsule(
            capsule=capsule,
            authoritative_result=authoritative,
            result=result,
            maximum_persistent_bytes=10_000_000,
            _after_capsule_seal=lambda: (_ for _ in ()).throw(
                RuntimeError("publish fault")
            ),
        )
    assert not authoritative.exists()
    assert not (capsule / "artifacts.sha256").exists()
    recovered = {
        **result,
        "classification": episodic.OPERATIONAL_TERMINAL,
        "stop_reason": "publication-recovery",
    }
    episodic.finalize_capsule(
        capsule=capsule,
        authoritative_result=authoritative,
        result=recovered,
        maximum_persistent_bytes=10_000_000,
    )
    assert calls == [0]
    assert authoritative.is_file()
    assert json.loads(authoritative.read_text())["classification"] == (
        episodic.OPERATIONAL_TERMINAL
    )


def test_geometry_smoke_fake_result_normalizes_and_rejects_circular_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_geometry()
    input_vault, result = _fake_geometry_result(frozen)
    native_build = episodic.NativeGuidedSearchBuild(
        executable=Path("native-joint-score-sieve"),
        command=(),
        source_sha256=episodic.EXPECTED_NATIVE_SOURCE_SHA256,
        cadical_header_sha256="a" * 64,
        cadical_library_sha256="b" * 64,
        executable_sha256=episodic.EXPECTED_NATIVE_EXECUTABLE_SHA256,
    )
    monkeypatch.setattr(episodic, "validate_native_build_identity", lambda _build: None)
    report = episodic._geometry_smoke_report(
        root=ROOT,
        frozen=frozen,
        native_build=native_build,
        input_vault=input_vault,
        result=result,
    )
    assert report["classification"] == episodic.GEOMETRY_SMOKE_CLASSIFICATION
    outcome = cast(Mapping[str, object], report["outcome"])
    claim = cast(Mapping[str, object], report["claim_boundary"])
    bindings = cast(Mapping[str, object], report["bindings"])
    assert outcome["status"] == 20
    assert outcome["eligible_archived_clause_count"] == 0
    assert outcome["next_vault"] is None
    assert claim["truth_key_bytes_read"] is False
    assert claim["scientific_full256_calls"] == 0
    assert {"runner_sha256", "config_sha256", "source_commit"}.isdisjoint(bindings)

    forged = json.loads(json.dumps(report))
    forged["bindings"]["runner_sha256"] = "0" * 64
    with pytest.raises(episodic.O1C66RunError, match="identity"):
        episodic._validate_geometry_smoke_report(
            forged,
            root=ROOT,
            frozen=frozen,
        )


@pytest.mark.skipif(
    episodic.sys.platform != "darwin"
    or not Path("/opt/homebrew/include/cadical.hpp").is_file()
    or not Path("/opt/homebrew/lib/libcadical.a").is_file(),
    reason="exact native-v6 CaDiCaL toolchain unavailable",
)
def test_geometry_smoke_real_native_root_prunes_without_target_or_truth(
    tmp_path: Path,
) -> None:
    output = tmp_path / "geometry-smoke.json"
    report = episodic.run_target_free_geometry_smoke(output)
    outcome = cast(Mapping[str, object], report["outcome"])
    claim = cast(Mapping[str, object], report["claim_boundary"])
    invocation = cast(Mapping[str, object], report["invocation"])
    assert output.read_bytes() == episodic._canonical_json_bytes(report)
    assert invocation["native_solver_calls"] == 1
    assert invocation["target_bytes_read"] == 0
    assert outcome["threshold_region_root_empty_unsat"] is True
    assert outcome["empty_clause_archived"] is False
    assert outcome["next_vault"] is None
    assert claim["truth_key_bytes_read"] is False
    assert claim["scientific_full256_calls"] == 0

    with pytest.raises(episodic.O1C66RunError, match="already exists"):
        episodic.run_target_free_geometry_smoke(output)


def test_config_hashes_and_preflight_are_zero_call_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def forbidden(**_kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("preflight made a solver call")

    monkeypatch.setattr(episodic._native_v8, "run_joint_score_sieve", forbidden)
    config = episodic.load_config(CONFIG)
    source = config["source"]
    assert isinstance(source, dict)
    expected = source["expected_sha256"]
    assert isinstance(expected, dict)
    for name, relative in source.items():
        if name != "expected_sha256":
            assert sha256_file(ROOT / str(relative)) == expected[name]
    observed = episodic.preflight(CONFIG)
    assert called is False
    assert observed["native_solver_calls"] == 0
    assert observed["files_written"] == 0
    assert observed["truth_key_bytes_read"] is False
    assert observed["truth_hash"] is None
    assert observed["native_model_equals_committed_truth"] is None
    assert observed["all_caps_validated"] is True
    assert observed["geometry_smoke_validated"] is True
    assert observed["geometry_smoke_native_solver_calls"] == 1
    assert observed["maximum_episodes"] == 8
    assert observed["maximum_total_requested_conflicts"] == 4096
    assert observed["maximum_total_billed_conflicts"] == 4104
    assert observed["vault_caps"] == {
        "maximum_serialized_bytes": 8_388_608,
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
    }
