from __future__ import annotations

import copy
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest

import o1_crypto_lab.joint_score_sieve_v15 as sieve_v15
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import build_compatibility_grouping
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)
from o1_crypto_lab.vault_phase_field_v1 import derive_vault_phase_field
from o1_crypto_lab.vault_ranked_decision_v1 import (
    VaultRankedDecision,
    derive_vault_ranked_decision,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_V12_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v12.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="74" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (8.0, 0.0)),
            CriticalityPotentialFactor((2,), (6.0, 0.0)),
            CriticalityPotentialFactor((3,), (0.0, 10.0)),
            CriticalityPotentialFactor((6,), (1.0, 0.0)),
        ),
    )


def _artifacts(
    tmp_path: Path,
) -> tuple[ThresholdNoGoodVault, VaultRankedDecision]:
    field = _field()
    cnf = tmp_path / "release-contrast.cnf"
    cnf.write_text(
        "p cnf 256 5\n"
        "6 0\n2 4 5 0\n2 4 -5 0\n2 -4 5 0\n2 -4 -5 0\n",
        encoding="ascii",
    )
    potential = tmp_path / "release-contrast.potential"
    grouping = tmp_path / "release-contrast.grouping"
    sieve_v15.write_joint_score_sieve_potential(potential, field)
    sieve_v15.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v15.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    input_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (
            ThresholdNoGoodClause((-1, 3)),
            ThresholdNoGoodClause((-2, 3)),
            ThresholdNoGoodClause((-1, 3, -6)),
        ),
    )
    vault = tmp_path / "release-contrast.vault"
    write_threshold_no_good_vault(vault, input_vault, caps=O1C66_VAULT_CAPS)
    phase = derive_vault_phase_field(
        vault.read_bytes(), key_variable_count=256, clause_start=0
    )
    decision = derive_vault_ranked_decision(
        phase,
        field,
        build_compatibility_grouping(field, width_cap=6),
    )
    assert decision.ranked_literals == (3, -1, -2, -6)
    return input_vault, decision


def _mask(indices: tuple[int, ...]) -> bytes:
    payload = bytearray(32)
    for index in indices:
        payload[index // 8] |= 1 << (index % 8)
    return bytes(payload)


def _sequence(literals: tuple[int, ...]) -> bytes:
    return b"".join(struct.pack("<i", literal) for literal in literals)


def _byte_fields(prefix: str, payload: bytes) -> dict[str, object]:
    return {
        f"{prefix}_hex": payload.hex(),
        f"{prefix}_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _put_sequence(
    reader: dict[str, object], prefix: str, literals: tuple[int, ...]
) -> None:
    payload = _sequence(literals)
    reader[f"{prefix}_count"] = len(literals)
    reader[f"{prefix}_bytes"] = len(payload)
    reader.update(_byte_fields(prefix, payload))


def _put_state(reader: dict[str, object], prefix: str, indices: tuple[int, ...]) -> None:
    reader.update(_byte_fields(prefix, _mask(indices)))


def _reader(
    decision: VaultRankedDecision, *, active: bool = True
) -> dict[str, object]:
    reader = sieve_v15._reader_expected(decision)
    for prefix in sieve_v15._STATE_PREFIXES:
        reader.update(
            {
                f"{prefix}_bits": 256,
                f"{prefix}_bytes": 32,
                f"{prefix}_encoding": sieve_v15.VAULT_RANKED_DECISION_STATE_ENCODING,
            }
        )
    for prefix in sieve_v15._SEQUENCE_PREFIXES:
        reader[f"{prefix}_encoding"] = (
            sieve_v15.VAULT_RANKED_DECISION_SEQUENCE_ENCODING
        )

    original = (3, -1, -2)
    release = (-2, 3, -1) if active else ()
    contrast = (1,) if active else ()
    contrast_release = (1,) if active else ()
    calls = 8 if active else 5
    actual = (3, -1, -2, 0, 0, 1, 0, 0) if active else (3, -1, -2, 0, 0)
    events: list[dict[str, object]] = [
        {
            "call": index,
            "kind": "original",
            "rank_index": index - 1,
            "literal": literal,
            "next_callback_observed": True,
            "assignment_burst_to_next_callback": 1,
        }
        for index, literal in enumerate(original, start=1)
    ]
    if active:
        events.append(
            {
                "call": 6,
                "kind": "contrast",
                "rank_index": 1,
                "literal": 1,
                "next_callback_observed": True,
                "assignment_burst_to_next_callback": 1,
            }
        )
    pairs: list[dict[str, object]] = []
    for index, literal in enumerate(original):
        returned_contrast = active and index == 1
        pairs.append(
            {
                "rank_index": index,
                "variable": abs(literal),
                "original_literal": literal,
                "contrast_literal": -literal,
                "original_return_call": index + 1,
                "original_release_after_call": 5 if active else None,
                "original_release_level": 1 if active else None,
                "contrast_return_call": 6 if returned_contrast else None,
                "contrast_release_after_call": 7 if returned_contrast else None,
                "contrast_release_level": 0 if returned_contrast else None,
            }
        )
    reader.update(
        {
            "decision_rule": sieve_v15.VAULT_RANKED_DECISION_DECISION_RULE,
            "callback_rule": sieve_v15.VAULT_RANKED_DECISION_CALLBACK_RULE,
            "cursor": 4,
            "rows_consumed": 4,
            "original_once_returns": 3,
            "skipped_preassigned": 1,
            "released_original": 3 if active else 0,
            "contrast_enqueued": 3 if active else 0,
            "contrast_returns": 1 if active else 0,
            "contrast_releases": 1 if active else 0,
            "contrast_deferred_assigned": 2 if active else 0,
            "paired_variables": 1 if active else 0,
            "variable_second_decisions": 1 if active else 0,
            "same_signed_redecisions": 0,
            "solver_phase_calls": 0,
            "cb_decide_calls": calls,
            "cb_decide_nonzero": 4 if active else 3,
            "cb_decide_zero": 4 if active else 2,
            "first_parent_fallback_call": 4,
            "first_final_fallback_call": 4,
            "queue_size": 2 if active else 0,
            "maximum_queue_size": 3 if active else 0,
            "assignment_literals_observed": 10 if active else 3,
            "returned_sequence_encoding": (
                sieve_v15.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
            ),
            "returned_sequence_count": calls,
            "returned_sequence_bytes": 4 * calls,
            "returned_sequence_sha256": hashlib.sha256(_sequence(actual)).hexdigest(),
            "nonzero_event_rule": sieve_v15.VAULT_RANKED_DECISION_NONZERO_EVENT_RULE,
            "nonzero_return_events": events,
            "pair_record_rule": sieve_v15.VAULT_RANKED_DECISION_PAIR_RECORD_RULE,
            "pair_records": pairs,
            "bounded_state_rule": sieve_v15.VAULT_RANKED_DECISION_BOUNDED_STATE_RULE,
            "bounded_guidance_state_bytes": 706,
            "live_guidance_state_bytes": 202 if active else 196,
            "bounded_telemetry_state_bytes": 33_490,
        }
    )
    _put_state(reader, "consumed_state", (0, 1, 2, 3))
    _put_state(reader, "original_returned_state", (0, 1, 2))
    _put_state(reader, "original_released_state", (0, 1, 2) if active else ())
    _put_state(reader, "contrast_enqueued_state", (0, 1, 2) if active else ())
    _put_state(reader, "contrast_returned_state", (1,) if active else ())
    _put_state(reader, "contrast_released_state", (1,) if active else ())
    _put_state(
        reader,
        "contrast_deferred_assigned_state",
        (0, 2) if active else (),
    )
    _put_sequence(reader, "original_return_sequence", original)
    _put_sequence(reader, "original_release_sequence", release)
    _put_sequence(reader, "contrast_return_sequence", contrast)
    _put_sequence(reader, "contrast_release_sequence", contrast_release)
    return reader


def test_policy_and_valid_active_fixture_are_exact(tmp_path: Path) -> None:
    _, decision = _artifacts(tmp_path)
    policy = sieve_v15.vault_release_contrast_policy_spec_bytes()
    assert len(policy) == 674
    assert hashlib.sha256(policy).hexdigest() == (
        "96e040917b6566671683598a09c6d03f6ebec3809c6c63354f09ffca93c246b5"
    )
    reader = _reader(decision)
    assert sieve_v15.validate_vault_ranked_decision_reader(
        reader, expected_decision=decision
    ) == {name: reader[name] for name in sorted(reader)}


def test_authoritative_native_active_fixture_matches_frozen_hashes(
    tmp_path: Path,
) -> None:
    if not (
        shutil.which("c++")
        and NATIVE_V12_SOURCE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    ):
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    executable = tmp_path / "native-v12-fixture"
    compile_result = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O3",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE",
            f"-I{CADICAL_INCLUDE}",
            str(NATIVE_V12_SOURCE),
            str(CADICAL_LIBRARY),
            "-o",
            str(executable),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    input_vault, decision = _artifacts(tmp_path)
    rank_table = tmp_path / "release-contrast.rank-table"
    rank_table.write_bytes(decision.rank_table_bytes)
    completed = subprocess.run(
        [
            str(executable),
            "--cnf",
            str(tmp_path / "release-contrast.cnf"),
            "--potential",
            str(tmp_path / "release-contrast.potential"),
            "--grouping",
            str(tmp_path / "release-contrast.grouping"),
            "--vault-in",
            str(tmp_path / "release-contrast.vault"),
            "--rank-table",
            str(rank_table),
            "--threshold",
            "12",
            "--conflict-limit",
            "64",
            "--seed",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    stable = json.dumps(
        {name: value for name, value in payload.items() if name != "resources"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert len(stable) == 16_356
    assert hashlib.sha256(stable).hexdigest() == (
        "e856105aab55758924f9cdd22c9e1607b9e0f79a67f438061f6ba9c9d7bde961"
    )
    assert decision.rank_table_sha256 == (
        "ad0656f1968a47f2cb4eb9229a8ee034bf5690b7f93224f2d19e4ef57678e6e6"
    )
    reader = payload["reader"]
    assert sieve_v15.validate_vault_ranked_decision_reader(
        reader, expected_decision=decision
    )
    assert sieve_v15.validate_native_lifecycle(payload)
    parsed = sieve_v15._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=_field(),
        grouping=build_compatibility_grouping(_field(), width_cap=6),
        grouping_sha256=input_vault.identity.grouping_sha256,
        cnf_sha256=input_vault.identity.cnf_sha256,
        potential_sha256=input_vault.identity.potential_sha256,
        threshold=12.0,
        requested_conflicts=64,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=decision,
    )
    assert isinstance(parsed, sieve_v15.JointScoreSieveV15Result)
    assert parsed.raw == payload
    assert reader["returned_sequence_sha256"] == (
        "142448052b524afe08a51ac6ccc0b6053ecd3ab64c593bdfbf22e41175731315"
    )
    assert (
        reader["cb_decide_calls"],
        reader["cb_decide_nonzero"],
        reader["cb_decide_zero"],
        reader["queue_size"],
        reader["maximum_queue_size"],
    ) == (507, 4, 503, 2, 3)
    assert reader["contrast_deferred_assigned"] == 2
    assert sieve_v15._state_indices(
        bytes.fromhex(reader["contrast_deferred_assigned_state_hex"])
    ) == (0, 2)


def test_passive_v12_is_explicitly_opt_in_and_legacy_is_rejected(
    tmp_path: Path,
) -> None:
    _, decision = _artifacts(tmp_path)
    passive = _reader(decision, active=False)
    with pytest.raises(O1RelationalSearchError, match="active contrast"):
        sieve_v15.validate_vault_ranked_decision_reader(
            passive, expected_decision=decision
        )
    assert sieve_v15.validate_vault_ranked_decision_reader(
        passive,
        expected_decision=decision,
        require_active_contrast=False,
    )
    legacy = sieve_v15._v14_reader(passive, decision)
    with pytest.raises(O1RelationalSearchError, match="reader fields"):
        sieve_v15.validate_vault_ranked_decision_reader(
            legacy,
            expected_decision=decision,
            require_active_contrast=False,
        )


Mutation = Callable[[dict[str, object]], None]


def _set(field: str, value: object) -> Mutation:
    return lambda reader: reader.__setitem__(field, value)


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (_set("schema", "legacy"), "rank, identity, or policy"),
        (_set("implementation_release_parent_schema", "legacy"), "rank, identity"),
        (_set("order_sha256", "00" * 32), "rank, identity"),
        (_set("contrast_policy_spec_sha256", "00" * 32), "rank, identity"),
        (_set("decision_rule", "passive"), "runtime contract"),
        (_set("cursor", 3), "state subset"),
        (_set("rows_consumed", 3), "state subset"),
        (_set("original_once_returns", 2), "sequence scalar"),
        (_set("released_original", 2), "sequence scalar"),
        (_set("contrast_enqueued", 2), "state subset"),
        (_set("contrast_returns", 2), "sequence scalar"),
        (_set("contrast_releases", 2), "sequence scalar"),
        (_set("contrast_deferred_assigned", 1), "state subset"),
        (_set("paired_variables", 2), "callback or queue"),
        (_set("same_signed_redecisions", 1), "callback or queue"),
        (_set("variable_second_decisions", 2), "callback or queue"),
        (_set("solver_phase_calls", 1), "callback or queue"),
        (_set("cb_decide_nonzero", 3), "callback or queue"),
        (_set("first_parent_fallback_call", 5), "parent fallback"),
        (_set("first_final_fallback_call", 5), "callback-return hash"),
        (_set("queue_size", 3), "bounded guidance|callback or queue"),
        (_set("maximum_queue_size", 2), "bounded guidance"),
        (_set("assignment_literals_observed", 3), "callback-return hash"),
        (_set("returned_sequence_sha256", "00" * 32), "callback-return hash"),
        (_set("bounded_guidance_state_bytes", 705), "bounded guidance"),
        (_set("live_guidance_state_bytes", 201), "bounded guidance"),
        (_set("bounded_telemetry_state_bytes", 33_489), "bounded guidance"),
    ),
)
def test_scalar_schema_identity_and_bound_mutations_fail_closed(
    tmp_path: Path, mutate: Mutation, message: str
) -> None:
    _, decision = _artifacts(tmp_path)
    reader = _reader(decision)
    mutate(reader)
    with pytest.raises(O1RelationalSearchError, match=message):
        sieve_v15.validate_vault_ranked_decision_reader(
            reader, expected_decision=decision
        )


def test_state_sequence_event_and_pair_scientific_mutations_fail_closed(
    tmp_path: Path,
) -> None:
    _, decision = _artifacts(tmp_path)

    state = _reader(decision)
    _put_state(state, "contrast_enqueued_state", (0, 1))
    with pytest.raises(O1RelationalSearchError, match="state subset"):
        sieve_v15.validate_vault_ranked_decision_reader(
            state, expected_decision=decision
        )

    order = _reader(decision)
    _put_sequence(order, "original_return_sequence", (3, -2, -1))
    with pytest.raises(O1RelationalSearchError, match="state subset"):
        sieve_v15.validate_vault_ranked_decision_reader(
            order, expected_decision=decision
        )

    opposite = _reader(decision)
    events = copy.deepcopy(opposite["nonzero_return_events"])
    assert isinstance(events, list)
    events[-1]["literal"] = -1
    opposite["nonzero_return_events"] = events
    with pytest.raises(O1RelationalSearchError, match="event projection"):
        sieve_v15.validate_vault_ranked_decision_reader(
            opposite, expected_decision=decision
        )

    event_position = _reader(decision)
    events = copy.deepcopy(event_position["nonzero_return_events"])
    assert isinstance(events, list)
    events[-1]["call"] = 5
    event_position["nonzero_return_events"] = events
    with pytest.raises(O1RelationalSearchError, match="pair causality|callback-return"):
        sieve_v15.validate_vault_ranked_decision_reader(
            event_position, expected_decision=decision
        )

    burst = _reader(decision)
    events = copy.deepcopy(burst["nonzero_return_events"])
    assert isinstance(events, list)
    events[-1]["next_callback_observed"] = False
    burst["nonzero_return_events"] = events
    with pytest.raises(O1RelationalSearchError, match="notification telemetry"):
        sieve_v15.validate_vault_ranked_decision_reader(
            burst, expected_decision=decision
        )

    pair = _reader(decision)
    pairs = copy.deepcopy(pair["pair_records"])
    assert isinstance(pairs, list)
    pairs[1]["contrast_literal"] = -1
    pair["pair_records"] = pairs
    with pytest.raises(O1RelationalSearchError, match="pair-record identity"):
        sieve_v15.validate_vault_ranked_decision_reader(
            pair, expected_decision=decision
        )

    causal = _reader(decision)
    pairs = copy.deepcopy(causal["pair_records"])
    assert isinstance(pairs, list)
    pairs[1]["contrast_return_call"] = 5
    causal["pair_records"] = pairs
    with pytest.raises(O1RelationalSearchError, match="contrast pair causality"):
        sieve_v15.validate_vault_ranked_decision_reader(
            causal, expected_decision=decision
        )


def test_v12_payload_projects_only_frozen_v14_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_vault, decision = _artifacts(tmp_path)
    reader = _reader(decision)
    payload: dict[str, object] = {name: None for name in sieve_v15._TOP_LEVEL_FIELDS}
    payload.update(
        {
            "schema": sieve_v15.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                sieve_v15.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "implementation_release_parent_schema": (
                sieve_v15.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
            ),
            "seed": 0,
            "reader": reader,
            "sieve": {"cb_decide_calls": 8, "cb_decide_nonzero": 0},
        }
    )
    seen: dict[str, object] = {}

    def fake_parent(parent_payload: object, **_: object) -> Any:
        assert isinstance(parent_payload, dict)
        seen.update(parent_payload)
        return sieve_v15._v14.JointScoreSieveV14Result(
            status=0,
            conflict_limit=64,
            threshold=50.0,
            key_model=None,
            stats={},
            sieve={},
            resources={},
            raw={},
            adapter_memory={},
            input_vault=input_vault,
            eligible_emitted_clauses=(),
            next_vault=input_vault,
            vault_telemetry={},
            reader={},
        )

    monkeypatch.setattr(sieve_v15._v14, "_parse_native_payload", fake_parent)
    result = sieve_v15._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=_field(),
        grouping=build_compatibility_grouping(_field(), width_cap=6),
        grouping_sha256=input_vault.identity.grouping_sha256,
        cnf_sha256=input_vault.identity.cnf_sha256,
        potential_sha256=input_vault.identity.potential_sha256,
        threshold=50.0,
        requested_conflicts=64,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=decision,
    )
    assert isinstance(result, sieve_v15.JointScoreSieveV15Result)
    assert result.reader == reader
    assert result.nonzero_events[-1].literal == 1
    assert result.contrast_pairs[1].contrast_return_call == 6
    assert "implementation_release_parent_schema" not in seen
    assert seen["schema"] == sieve_v15._v14.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected = seen["reader"]
    assert isinstance(projected, dict)
    assert projected["once_returns"] == 3
    assert projected["cb_decide_nonzero"] == 3
    assert projected["cb_decide_zero"] == 5
