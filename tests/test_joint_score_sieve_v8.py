from __future__ import annotations

import copy
import hashlib
import inspect
import json
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v8 as sieve_v8
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v7 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JointScoreSieveExecutionError,
    JointScoreSieveV7Result,
    build_compatibility_grouping,
    joint_score_complete,
    joint_score_upper_bound,
    write_joint_score_sieve_grouping,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.joint_score_sieve_v8 import (
    JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA,
    JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE,
    JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA,
    JointScoreSieveV8Result,
    run_joint_score_sieve,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING,
    THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE,
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE,
    THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    VaultCaps,
    append_new_deduplicated,
    partial_assignment_from_vault_clause,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (-3.0, 3.0)),
            CriticalityPotentialFactor((2,), (-2.0, 2.0)),
        ),
    )


def _vault(
    clauses: tuple[ThresholdNoGoodClause, ...] = (), *, threshold: float = 0.0
) -> ThresholdNoGoodVault:
    field = _field()
    identity = vault_identity_from_sources(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=threshold,
    )
    return ThresholdNoGoodVault(identity, field.observed_variables, clauses)


def _record(
    index: int,
    literals: tuple[int, ...],
    *,
    source: str,
    witness: float,
    classification: str,
) -> dict[str, object]:
    canonical = struct.pack("<I", len(literals)) + b"".join(
        struct.pack("<i", literal) for literal in literals
    )
    source_code = {"trail_upper_bound": 1, "complete_model_score": 2}[source]
    return {
        "index": index,
        "source": source,
        "witness_score": witness,
        "witness_score_f64le_hex": struct.pack("<d", witness).hex(),
        "literal_count": len(literals),
        "literals": list(literals),
        "clause_sha256": hashlib.sha256(canonical).hexdigest(),
        "witness_sha256": hashlib.sha256(
            bytes((source_code,)) + struct.pack("<d", witness) + canonical
        ).hexdigest(),
        "classification": classification,
    }


def _telemetry(
    input_vault: ThresholdNoGoodVault,
    records: list[dict[str, object]],
    *,
    caps: VaultCaps = O1C66_VAULT_CAPS,
    terminal_reason: str | None = None,
) -> dict[str, object]:
    canonical_records: list[bytes] = []
    new: list[ThresholdNoGoodClause] = []
    ledgers = {
        "new": [0, 0],
        "input_duplicate": [0, 0],
        "current_duplicate": [0, 0],
    }
    terminal_empty_count = 0
    total_literals = 0
    for record in records:
        literals = tuple(record["literals"])  # type: ignore[arg-type]
        canonical = struct.pack("<I", len(literals)) + b"".join(
            struct.pack("<i", literal) for literal in literals
        )
        canonical_records.append(canonical)
        total_literals += len(literals)
        classification = record["classification"]
        if classification == "terminal_empty":
            terminal_empty_count += 1
        else:
            key = str(classification)
            ledgers[key][0] += 1
            ledgers[key][1] += len(literals)
            if key == "new":
                new.append(ThresholdNoGoodClause(literals))
    if terminal_reason is None:
        next_vault = append_new_deduplicated(input_vault, tuple(new), caps=caps).vault
        next_fields: dict[str, object] = {
            "next_vault_available": True,
            "next_vault_terminal_reason": None,
            "next_vault_sha256": next_vault.sha256,
            "next_serialized_bytes": next_vault.serialized_bytes,
            "next_clause_count": next_vault.clause_count,
            "next_literal_count": next_vault.literal_count,
        }
    else:
        next_fields = {
            "next_vault_available": False,
            "next_vault_terminal_reason": terminal_reason,
            "next_vault_sha256": None,
            "next_serialized_bytes": None,
            "next_clause_count": None,
            "next_literal_count": None,
        }
    return {
        "schema": JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA,
        "binary_magic_hex": THRESHOLD_NO_GOOD_VAULT_MAGIC.hex(),
        "semantic_rule": THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE,
        "identity_rule": THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE,
        "clause_encoding": THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING,
        "witness_encoding": THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING,
        "maximum_payload_bytes": caps.maximum_serialized_bytes,
        "maximum_clause_count": caps.maximum_clauses,
        "maximum_literal_count": caps.maximum_literals,
        "input_sha256": input_vault.sha256,
        "input_serialized_bytes": input_vault.serialized_bytes,
        "input_clause_count": input_vault.clause_count,
        "input_literal_count": input_vault.literal_count,
        "input_clause_aggregate_sha256": input_vault.clause_aggregate_sha256,
        "input_certification_rule": JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE,
        "validated_input_clause_count": input_vault.clause_count,
        "validated_input_literal_count": input_vault.literal_count,
        "validated_input_clause_aggregate_sha256": (
            input_vault.clause_aggregate_sha256
        ),
        "input_cnf_sha256": input_vault.identity.cnf_sha256,
        "input_potential_sha256": input_vault.identity.potential_sha256,
        "input_grouping_sha256": input_vault.identity.grouping_sha256,
        "input_observed_variables_sha256": (
            input_vault.identity.observed_variables_sha256
        ),
        "input_bound_rule_sha256": input_vault.identity.bound_rule_sha256,
        "input_threshold_f64le_hex": input_vault.identity.threshold_f64le_hex,
        "preloaded_clause_count": input_vault.clause_count,
        "preloaded_literal_count": input_vault.literal_count,
        "fully_emitted_clause_count": len(records),
        "fully_emitted_literal_count": total_literals,
        "emitted_new_clause_count": ledgers["new"][0],
        "emitted_new_literal_count": ledgers["new"][1],
        "emitted_input_duplicate_clause_count": ledgers["input_duplicate"][0],
        "emitted_input_duplicate_literal_count": ledgers["input_duplicate"][1],
        "emitted_current_duplicate_clause_count": ledgers["current_duplicate"][0],
        "emitted_current_duplicate_literal_count": ledgers["current_duplicate"][1],
        "terminal_empty_clause_count": terminal_empty_count,
        "pending_clause_exported": False,
        "fully_emitted_aggregate_sha256": hashlib.sha256(
            b"".join(canonical_records)
        ).hexdigest(),
        "fully_emitted_clauses": records,
        **next_fields,
    }


def _valid_case() -> tuple[
    CriticalityPotentialField,
    Any,
    ThresholdNoGoodVault,
    dict[str, object],
]:
    field = _field()
    grouping = build_compatibility_grouping(field)
    input_clause = ThresholdNoGoodClause((1,))
    complete_clause = ThresholdNoGoodClause((1, 2))
    input_vault = _vault((input_clause,))
    input_witness = joint_score_upper_bound(
        field,
        partial_assignment_from_vault_clause(input_clause),
        grouping=grouping,
    )
    complete_witness = joint_score_complete(
        field, partial_assignment_from_vault_clause(complete_clause)
    )
    records = [
        _record(
            0,
            input_clause.literals,
            source="trail_upper_bound",
            witness=input_witness,
            classification="input_duplicate",
        ),
        _record(
            1,
            complete_clause.literals,
            source="complete_model_score",
            witness=complete_witness,
            classification="new",
        ),
        _record(
            2,
            complete_clause.literals,
            source="complete_model_score",
            witness=complete_witness,
            classification="current_duplicate",
        ),
    ]
    return field, grouping, input_vault, _telemetry(input_vault, records)


def test_valid_telemetry_is_independently_certified_and_reconstructed() -> None:
    field, grouping, input_vault, telemetry = _valid_case()
    eligible, next_vault, normalized = sieve_v8._parse_vault_telemetry(
        telemetry,
        input_vault=input_vault,
        field=field,
        grouping=grouping,
        threshold=0.0,
        caps=O1C66_VAULT_CAPS,
    )

    assert tuple(record.classification for record in eligible) == (
        "input_duplicate",
        "new",
        "current_duplicate",
    )
    assert eligible[0].excluded_assignment == ((1, -1),)
    assert eligible[1].certification == "original_factor_exact_score"
    assert next_vault is not None
    assert next_vault.clauses == (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
    )
    assert normalized == telemetry


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    (
        (
            lambda value: value.__setitem__("pending_clause_exported", True),
            "input vault",
        ),
        (
            lambda value: value.__setitem__("validated_input_clause_count", 0),
            "input vault",
        ),
        (
            lambda value: value["fully_emitted_clauses"][1].__setitem__(  # type: ignore[index,union-attr]
                "classification", "input_duplicate"
            ),
            "classification",
        ),
        (
            lambda value: value["fully_emitted_clauses"][1].__setitem__(  # type: ignore[index,union-attr]
                "witness_score_f64le_hex", "00" * 8
            ),
            "encoding",
        ),
        (
            lambda value: value["fully_emitted_clauses"][1].__setitem__(  # type: ignore[index,union-attr]
                "source", []
            ),
            "encoding",
        ),
        (lambda value: value.__setitem__("emitted_new_clause_count", 2), "ledger"),
        (
            lambda value: value.__setitem__(
                "fully_emitted_aggregate_sha256", "00" * 32
            ),
            "ledger",
        ),
        (lambda value: value.__setitem__("next_vault_sha256", "00" * 32), "cumulative"),
    ),
)
def test_forged_native_vault_claims_are_rejected(mutation: Any, pattern: str) -> None:
    field, grouping, input_vault, telemetry = _valid_case()
    forged = copy.deepcopy(telemetry)
    mutation(forged)
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve_v8._parse_vault_telemetry(
            forged,
            input_vault=input_vault,
            field=field,
            grouping=grouping,
            threshold=0.0,
            caps=O1C66_VAULT_CAPS,
        )


def test_witness_digest_cannot_hide_an_unsound_grouped_clause() -> None:
    field, grouping, input_vault, telemetry = _valid_case()
    forged = copy.deepcopy(telemetry)
    record = forged["fully_emitted_clauses"][0]  # type: ignore[index]
    unsafe = ThresholdNoGoodClause((-1,))
    unsafe_witness = joint_score_upper_bound(
        field,
        partial_assignment_from_vault_clause(unsafe),
        grouping=grouping,
    )
    forged_record = _record(
        0,
        unsafe.literals,
        source="trail_upper_bound",
        witness=unsafe_witness,
        classification="new",
    )
    assert isinstance(record, dict)
    record.clear()
    record.update(forged_record)
    with pytest.raises(O1RelationalSearchError, match="certification"):
        sieve_v8._parse_vault_telemetry(
            forged,
            input_vault=input_vault,
            field=field,
            grouping=grouping,
            threshold=0.0,
            caps=O1C66_VAULT_CAPS,
        )


def test_input_vault_is_certified_before_native_execution() -> None:
    field = _field()
    grouping = build_compatibility_grouping(field)
    unsafe = _vault((ThresholdNoGoodClause((-1,)),))
    with pytest.raises(O1RelationalSearchError, match="certification"):
        sieve_v8._certify_input_vault(
            unsafe, field=field, grouping=grouping, threshold=0.0
        )


def test_terminal_empty_clause_is_validated_but_never_archived() -> None:
    field = _field()
    grouping = build_compatibility_grouping(field)
    input_vault = _vault(threshold=6.0)
    root = joint_score_upper_bound(field, {}, grouping=grouping)
    telemetry = _telemetry(
        input_vault,
        [
            _record(
                0,
                (),
                source="trail_upper_bound",
                witness=root,
                classification="terminal_empty",
            )
        ],
        terminal_reason="terminal_empty_clause",
    )
    eligible, next_vault, _ = sieve_v8._parse_vault_telemetry(
        telemetry,
        input_vault=input_vault,
        field=field,
        grouping=grouping,
        threshold=6.0,
        caps=O1C66_VAULT_CAPS,
    )
    assert eligible == ()
    assert next_vault is None


def test_capacity_crossing_uses_native_typed_precedence_and_null_next_fields() -> None:
    field, grouping, input_vault, telemetry = _valid_case()
    records = telemetry["fully_emitted_clauses"]
    assert isinstance(records, list)
    caps = VaultCaps(1_000, 1, 10)
    capacity = _telemetry(
        input_vault,
        records,
        caps=caps,
        terminal_reason="capacity_clause_count",
    )
    _, next_vault, _ = sieve_v8._parse_vault_telemetry(
        capacity,
        input_vault=input_vault,
        field=field,
        grouping=grouping,
        threshold=0.0,
        caps=caps,
    )
    assert next_vault is None
    assert capacity["next_vault_sha256"] is None


def test_next_vault_integer_ledgers_reject_boolean_values() -> None:
    field = _field()
    grouping = build_compatibility_grouping(field)
    input_vault = _vault()
    telemetry = _telemetry(input_vault, [])
    telemetry["next_clause_count"] = False
    with pytest.raises(O1RelationalSearchError, match="next_clause_count"):
        sieve_v8._parse_vault_telemetry(
            telemetry,
            input_vault=input_vault,
            field=field,
            grouping=grouping,
            threshold=0.0,
            caps=O1C66_VAULT_CAPS,
        )


def _fake_parent(threshold: float = 0.0) -> JointScoreSieveV7Result:
    return JointScoreSieveV7Result(
        status=0,
        conflict_limit=1,
        threshold=threshold,
        key_model=None,
        stats={
            "conflicts": 0,
            "conflicts_before_solve": 0,
            "solve_conflicts": 0,
            "decisions": 0,
            "propagations": 0,
        },
        sieve={
            "external_clauses_emitted": 3,
            "external_clause_literals": 5,
            "state": {"pending_clause_length": 0},
        },
        resources={},
        raw={},
        adapter_memory={"memory_sample_count": 0},
    )


def test_top_level_v6_identity_is_checked_before_v7_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    field, grouping, input_vault, telemetry = _valid_case()
    payload: dict[str, object] = {name: None for name in sieve_v8._TOP_LEVEL_FIELDS}
    payload.update(
        {
            "schema": JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "implementation_parent_schema": JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
            "status": 0,
            "post_solve_state": 256,
            "post_solve_state_name": "INCONCLUSIVE",
            "teardown_rule": sieve_v8.JOINT_SCORE_SIEVE_TEARDOWN_RULE,
            "pending_backtrack_rule": (
                sieve_v8.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
            ),
            "vault": telemetry,
        }
    )
    seen: dict[str, object] = {}

    def fake_parent_parser(
        parent_payload: object, **_: object
    ) -> JointScoreSieveV7Result:
        assert isinstance(parent_payload, dict)
        seen.update(parent_payload)
        return _fake_parent()

    monkeypatch.setattr(sieve_v8._v7, "_parse_native_payload", fake_parent_parser)
    result = sieve_v8._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=field,
        grouping=grouping,
        grouping_sha256="45" * 32,
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        threshold=0.0,
        requested_conflicts=1,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
    )
    assert isinstance(result, JointScoreSieveV8Result)
    assert "vault" not in seen
    assert seen["schema"] == sieve_v8._v7.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert (
        seen["implementation_parent_schema"]
        == sieve_v8._v7.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    assert result.raw == payload

    def mismatched_parent_parser(_: object, **__: object) -> JointScoreSieveV7Result:
        parent = _fake_parent()
        assert isinstance(parent.sieve, dict)
        parent.sieve["external_clauses_emitted"] = 2
        return parent

    monkeypatch.setattr(sieve_v8._v7, "_parse_native_payload", mismatched_parent_parser)
    with pytest.raises(O1RelationalSearchError, match="emission ledgers"):
        sieve_v8._parse_native_payload(
            payload,
            input_vault=input_vault,
            vault_caps=O1C66_VAULT_CAPS,
            field=field,
            grouping=grouping,
            grouping_sha256="45" * 32,
            cnf_sha256="01" * 32,
            potential_sha256="23" * 32,
            threshold=0.0,
            requested_conflicts=1,
            seed=0,
            memory_limit_bytes=None,
            memory_samples=(),
        )

    forged = dict(payload)
    forged["implementation_parent_schema"] = "wrong"
    with pytest.raises(O1RelationalSearchError, match="result contract"):
        sieve_v8._parse_native_payload(
            forged,
            input_vault=input_vault,
            vault_caps=O1C66_VAULT_CAPS,
            field=field,
            grouping=grouping,
            grouping_sha256="45" * 32,
            cnf_sha256="01" * 32,
            potential_sha256="23" * 32,
            threshold=0.0,
            requested_conflicts=1,
            seed=0,
            memory_limit_bytes=None,
            memory_samples=(),
        )


def _inputs(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault]:
    field = _field()
    executable = tmp_path / "native-v6"
    executable.write_bytes(b"synthetic-native-v6")
    cnf = tmp_path / "case.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "case.potential"
    write_joint_score_sieve_potential(potential, field)
    grouping = tmp_path / "case.grouping"
    write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=0.0,
    )
    input_vault = ThresholdNoGoodVault(identity, field.observed_variables, ())
    vault_path = tmp_path / "input.vault"
    write_threshold_no_good_vault(vault_path, input_vault, caps=O1C66_VAULT_CAPS)
    return executable, cnf, potential, grouping, vault_path, input_vault


def test_public_runner_passes_required_vault_path_and_explicit_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, cnf, potential, grouping, vault_path, input_vault = _inputs(tmp_path)
    captured: dict[str, object] = {}

    def fake_execute(
        command: list[str], *, timeout_seconds: float, memory_limit_bytes: int | None
    ) -> Any:
        captured["command"] = command
        captured["timeout_seconds"] = timeout_seconds
        captured["memory_limit_bytes"] = memory_limit_bytes
        return sieve_v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, json.dumps({}), ""), ()
        )

    def fake_parser(_: object, **kwargs: object) -> JointScoreSieveV8Result:
        captured["parse_kwargs"] = kwargs
        return JointScoreSieveV8Result(
            **_fake_parent().__dict__,
            input_vault=input_vault,
            eligible_emitted_clauses=(),
            next_vault=input_vault,
            vault_telemetry={},
        )

    monkeypatch.setattr(sieve_v8._v7, "_execute_native", fake_execute)
    monkeypatch.setattr(sieve_v8, "_parse_native_payload", fake_parser)
    result = run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault_path,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=0.0,
        conflict_limit=1,
        seed=9,
    )
    command = captured["command"]
    assert isinstance(command, list)
    assert command[command.index("--vault-in") + 1] == str(vault_path.resolve())
    assert captured["parse_kwargs"]["vault_caps"] == O1C66_VAULT_CAPS  # type: ignore[index]
    assert result.input_vault == input_vault
    assert result.next_vault == input_vault


def test_wrong_vault_identity_fails_before_native_launch_with_rich_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, cnf, potential, grouping, vault_path, input_vault = _inputs(tmp_path)
    changed = ThresholdNoGoodVault(
        vault_identity_from_sources(
            cnf_sha256="ff" * 32,
            potential_sha256=input_vault.identity.potential_sha256,
            grouping_sha256=input_vault.identity.grouping_sha256,
            observed_variables=input_vault.observed_variables,
            bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
            threshold=0.0,
        ),
        input_vault.observed_variables,
        (),
    )
    write_threshold_no_good_vault(vault_path, changed, caps=O1C66_VAULT_CAPS)

    def forbidden_execute(*_: object, **__: object) -> None:
        raise AssertionError("native execution should not start")

    monkeypatch.setattr(sieve_v8._v7, "_execute_native", forbidden_execute)
    with pytest.raises(JointScoreSieveExecutionError) as raised:
        run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            vault_path=vault_path,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=0.0,
            conflict_limit=1,
        )
    assert isinstance(raised.value.__cause__, O1RelationalSearchError)
    chain = raised.value.failure_telemetry["exception_chain"]
    assert isinstance(chain, list)
    assert any(str(row["type"]).endswith("ThresholdNoGoodVaultError") for row in chain)


def test_public_signature_requires_vault_caps_and_result_is_frozen() -> None:
    signature = inspect.signature(run_joint_score_sieve)
    assert signature.parameters["vault_path"].default is inspect.Parameter.empty
    assert signature.parameters["vault_caps"].default is inspect.Parameter.empty
    assert tuple(JointScoreSieveV8Result.__dataclass_fields__)[-4:] == (
        "input_vault",
        "eligible_emitted_clauses",
        "next_vault",
        "vault_telemetry",
    )
