from __future__ import annotations

import copy
import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v22 as sieve
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v7 import (
    build_compatibility_grouping,
    write_joint_score_sieve_grouping,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.o1c82_parent_centered_seed import (
    BANK_BYTES,
    EXPECTED_BANK_SHA256,
    compile_parent_centered_seed,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
THRESHOLD = -10.0


@dataclass(frozen=True)
class PublicCase:
    result: sieve.JointScoreSieveV22Result
    field: CriticalityPotentialField
    grouping: object
    input_vault: ThresholdNoGoodVault
    grouping_sha256: str
    cnf_sha256: str
    potential_sha256: str


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (-3.0, 3.0)),
            CriticalityPotentialFactor((2,), (-2.0, 2.0)),
        ),
    )


def _available() -> bool:
    return bool(
        shutil.which("c++")
        and NATIVE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


@pytest.fixture(scope="module")
def public_case(tmp_path_factory: pytest.TempPathFactory) -> PublicCase:
    if not _available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    directory = tmp_path_factory.mktemp("joint-score-sieve-v22")
    cnf = directory / "case.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    field = _field()
    potential = directory / "case.potential"
    potential_sha = write_joint_score_sieve_potential(potential, field)
    grouping_path = directory / "case.grouping"
    grouping_sha = write_joint_score_sieve_grouping(grouping_path, field)
    grouping = build_compatibility_grouping(field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=potential_sha,
        grouping_sha256=grouping_sha,
        observed_variables=field.observed_variables,
        bound_rule=sieve._v9.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=THRESHOLD,
    )
    input_vault = ThresholdNoGoodVault(identity, field.observed_variables, ())
    vault = directory / "input.vault"
    write_threshold_no_good_vault(vault, input_vault, caps=O1C66_VAULT_CAPS)
    seed_path = directory / "priority.seed"
    seed_payload = compile_parent_centered_seed(ROOT, verify_fresh=False)
    assert len(seed_payload) == BANK_BYTES
    assert hashlib.sha256(seed_payload).hexdigest() == EXPECTED_BANK_SHA256
    seed_path.write_bytes(seed_payload)
    executable = directory / "native-v19"
    result = sieve.run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping_path,
        vault_path=vault,
        priority_seed_path=seed_path,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=THRESHOLD,
        conflict_limit=8,
        seed=0,
        timeout_seconds=120.0,
        source_path=NATIVE,
        public_fixture=True,
    )
    assert executable.is_file()
    return PublicCase(
        result=result,
        field=field,
        grouping=grouping,
        input_vault=input_vault,
        grouping_sha256=grouping_sha,
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=potential_sha,
    )


def _revalidate(case: PublicCase, payload: object) -> sieve.JointScoreSieveV22Result:
    return sieve._parse_native_payload(
        payload,
        input_vault=case.input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=case.field,
        grouping=case.grouping,
        grouping_sha256=case.grouping_sha256,
        cnf_sha256=case.cnf_sha256,
        potential_sha256=case.potential_sha256,
        threshold=THRESHOLD,
        requested_conflicts=8,
        seed=0,
        priority_seed_sha256=EXPECTED_BANK_SHA256,
        production_seal=False,
    )


def test_real_native_v19_build_run_and_exact_command(
    public_case: PublicCase,
) -> None:
    result = public_case.result
    assert result.native_stdout is not None
    assert (
        result.native_stdout_sha256
        == hashlib.sha256(result.native_stdout.encode()).hexdigest()
    )
    assert result.raw["schema"] == sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert result.normalized_summary["candidate_population"] == 2
    assert result.normalized_summary["belief_orientation_authorized"] is False
    assert result.normalized_summary["key_bits_emitted"] == 0
    assert len(result.next_priority_seed) == BANK_BYTES
    assert (
        result.priority_state["current_bank_sha256"]
        == hashlib.sha256(result.next_priority_seed).hexdigest()
    )
    command = list(result.command)
    assert command[1::2] == [
        "--cnf",
        "--potential",
        "--grouping",
        "--vault-in",
        "--priority-seed",
        "--threshold",
        "--conflict-limit",
        "--seed",
    ]
    assert command[-1] == "0"


def test_one_shot_lower_ub_and_nonclaim_semantics(public_case: PublicCase) -> None:
    result = public_case.result
    actions = result.priority_actions
    assert actions["action_count"] == actions["failure_first_count"]
    assert actions["certified_crossing_count"] == 0
    assert actions["prune_claim_for_failure_first"] is False
    rows = actions["actions"]
    assert isinstance(rows, list)
    variables: set[int] = set()
    for row in rows:
        assert isinstance(row, dict)
        variable = row["variable"]
        assert variable not in variables
        variables.add(variable)
        assert row["semantic"] == sieve.PROOF_MINING_SEMANTIC
        assert row["current_lower_upper_bound"] >= THRESHOLD
        assert row["literal"] == (
            -variable if row["upper_zero"] <= row["upper_one"] else variable
        )
    assert result.priority_state["consumed_coordinate_count"] == len(rows)


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    (
        (lambda root: root.__setitem__("unexpected", 1), "result fields"),
        (
            lambda root: root["priority_state"].__setitem__(  # type: ignore[union-attr]
                "candidate_order_sha256", "00" * 32
            ),
            "priority state identity",
        ),
        (
            lambda root: root["priority_state"]["probe_trace"].__setitem__(  # type: ignore[index,union-attr]
                "bytes", 1
            ),
            "probe trace envelope",
        ),
        (
            lambda root: root["priority_actions"].__setitem__(  # type: ignore[union-attr]
                "prune_claim_for_failure_first", True
            ),
            "priority action contract",
        ),
        (
            lambda root: root["priority_actions"]["actions"][0].__setitem__(  # type: ignore[index,union-attr]
                "literal", 256
            ),
            "priority action semantics",
        ),
        (
            lambda root: root["decision_ownership"].__setitem__(  # type: ignore[union-attr]
                "proposals", 0
            ),
            "decision ownership replay",
        ),
    ),
)
def test_tampered_native_contracts_fail_closed(
    public_case: PublicCase, mutation: Any, pattern: str
) -> None:
    forged = copy.deepcopy(public_case.result.raw)
    mutation(forged)
    with pytest.raises(O1RelationalSearchError, match=pattern):
        _revalidate(public_case, forged)


def test_final_bank_sha_and_variable_241_zero_are_enforced(
    public_case: PublicCase,
) -> None:
    forged = copy.deepcopy(public_case.result.raw)
    state = forged["priority_state"]
    assert isinstance(state, dict)
    bank = bytearray.fromhex(str(state["bank_hex"]))
    bank[240 * 96] ^= 1
    state["bank_hex"] = bank.hex()
    state["current_bank_sha256"] = hashlib.sha256(bank).hexdigest()
    with pytest.raises(O1RelationalSearchError, match="priority bank seal"):
        _revalidate(public_case, forged)


def test_selection_coordinate_and_action_trace_are_recomputed(
    public_case: PublicCase,
) -> None:
    forged = copy.deepcopy(public_case.result.raw)
    operator = forged["priority_state"]["operator"]  # type: ignore[index]
    assert isinstance(operator, dict)
    selection = operator["selection"]
    assert isinstance(selection, dict)
    if selection["available"]:
        coordinate = selection["coordinate"]
        assert isinstance(coordinate, dict)
        coordinate["priority"] += 1.0
        with pytest.raises(O1RelationalSearchError, match="operator selection"):
            _revalidate(public_case, forged)

    forged = copy.deepcopy(public_case.result.raw)
    actions = forged["priority_actions"]
    assert isinstance(actions, dict)
    actions["action_trace_sha256"] = "00" * 32
    with pytest.raises(O1RelationalSearchError, match="action aggregate ledger"):
        _revalidate(public_case, forged)


def test_duplicate_or_nonfinite_native_json_is_rejected() -> None:
    with pytest.raises(O1RelationalSearchError):
        sieve._v21.load_native_json('{"schema":"a","schema":"b"}')
    with pytest.raises(O1RelationalSearchError):
        sieve._v21.load_native_json('{"value":NaN}')


def test_production_population_requires_255_coordinates_and_missing_241(
    public_case: PublicCase,
) -> None:
    with pytest.raises(O1RelationalSearchError, match="production candidate"):
        sieve._parse_native_payload(
            public_case.result.raw,
            input_vault=public_case.input_vault,
            vault_caps=O1C66_VAULT_CAPS,
            field=public_case.field,
            grouping=public_case.grouping,
            grouping_sha256=public_case.grouping_sha256,
            cnf_sha256=public_case.cnf_sha256,
            potential_sha256=public_case.potential_sha256,
            threshold=THRESHOLD,
            requested_conflicts=8,
            seed=0,
            priority_seed_sha256=EXPECTED_BANK_SHA256,
            production_seal=True,
        )


def test_source_contract_contains_no_target_or_belief_path() -> None:
    source = NATIVE.read_text(encoding="utf-8")
    assert "o1-256-cadical-joint-score-sieve-result-v19" in source
    assert "FAILURE_FIRST_PROOF_MINING" in source
    assert "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE" in source
    assert 'belief_orientation_authorized\\":false' in source
    assert 'growing_parent_history_bytes\\":0' in source
    assert "truth_key" not in source
    assert "reveal" not in source.lower()
