from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable

import pytest

import o1_crypto_lab.joint_score_sieve_v16 as sieve_v16
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import (
    JointScoreCompatibilityGrouping,
    build_compatibility_grouping,
)
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
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v13.cpp"
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


@dataclass(frozen=True)
class SplitArtifacts:
    cnf: Path
    potential: Path
    grouping_path: Path
    rank_vault_path: Path
    active_vault_path: Path
    rank_table_path: Path
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    rank_vault: ThresholdNoGoodVault
    active_vault: ThresholdNoGoodVault
    decision: VaultRankedDecision


def _artifacts(tmp_path: Path) -> SplitArtifacts:
    field = _field()
    cnf = tmp_path / "release-contrast.cnf"
    cnf.write_text(
        "p cnf 256 5\n"
        "6 0\n2 4 5 0\n2 4 -5 0\n2 -4 5 0\n2 -4 -5 0\n",
        encoding="ascii",
    )
    potential = tmp_path / "release-contrast.potential"
    grouping_path = tmp_path / "release-contrast.grouping"
    sieve_v16.write_joint_score_sieve_potential(potential, field)
    sieve_v16.write_joint_score_sieve_grouping(grouping_path, field)
    grouping = build_compatibility_grouping(field, width_cap=6)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping_path.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v16.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    clauses = (
        ThresholdNoGoodClause((-1, 3)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-1, 3, -6)),
    )
    rank_vault = ThresholdNoGoodVault(identity, field.observed_variables, clauses)
    active_vault = ThresholdNoGoodVault(
        identity, field.observed_variables, clauses[:1]
    )
    rank_vault_path = tmp_path / "rank-source.vault"
    active_vault_path = tmp_path / "active.vault"
    write_threshold_no_good_vault(
        rank_vault_path, rank_vault, caps=O1C66_VAULT_CAPS
    )
    write_threshold_no_good_vault(
        active_vault_path, active_vault, caps=O1C66_VAULT_CAPS
    )
    phase = derive_vault_phase_field(
        rank_vault.serialized, key_variable_count=256, clause_start=0
    )
    decision = derive_vault_ranked_decision(phase, field, grouping)
    assert decision.ranked_literals == (3, -1, -2, -6)
    rank_table_path = tmp_path / "release-contrast.rank-table"
    rank_table_path.write_bytes(decision.rank_table_bytes)
    return SplitArtifacts(
        cnf,
        potential,
        grouping_path,
        rank_vault_path,
        active_vault_path,
        rank_table_path,
        field,
        grouping,
        rank_vault,
        active_vault,
        decision,
    )


@pytest.fixture(scope="module")
def native_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not (
        shutil.which("c++")
        and NATIVE_SOURCE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    ):
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    executable = tmp_path_factory.mktemp("o1c74-v16-native") / "native-v13-fixture"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O3",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C74_PUBLIC_FIXTURE",
            f"-I{CADICAL_INCLUDE}",
            str(NATIVE_SOURCE),
            str(CADICAL_LIBRARY),
            "-o",
            str(executable),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return executable


def _native_payload(executable: Path, artifacts: SplitArtifacts) -> dict[str, Any]:
    completed = subprocess.run(
        [
            str(executable),
            "--cnf",
            str(artifacts.cnf),
            "--potential",
            str(artifacts.potential),
            "--grouping",
            str(artifacts.grouping_path),
            "--rank-vault",
            str(artifacts.rank_vault_path),
            "--vault-in",
            str(artifacts.active_vault_path),
            "--rank-table",
            str(artifacts.rank_table_path),
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
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _parse(
    payload: object, artifacts: SplitArtifacts
) -> sieve_v16.JointScoreSieveV16Result:
    return sieve_v16._parse_native_payload(
        payload,
        input_vault=artifacts.active_vault,
        rank_source_vault=artifacts.rank_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=artifacts.field,
        grouping=artifacts.grouping,
        grouping_sha256=artifacts.rank_vault.identity.grouping_sha256,
        cnf_sha256=artifacts.rank_vault.identity.cnf_sha256,
        potential_sha256=artifacts.rank_vault.identity.potential_sha256,
        threshold=12.0,
        requested_conflicts=64,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=artifacts.decision,
    )


def test_real_v13_payload_binds_rank_source_and_active_vault_separately(
    native_fixture: Path, tmp_path: Path
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    parsed = _parse(payload, artifacts)

    assert payload["schema"] == sieve_v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert payload["implementation_release_parent_schema"] == (
        sieve_v16.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    )
    assert payload["rank_source_vault_sha256"] == artifacts.rank_vault.sha256
    assert payload["reader"]["source_vault_sha256"] == artifacts.rank_vault.sha256
    assert payload["vault"]["input_sha256"] == artifacts.active_vault.sha256
    assert artifacts.rank_vault.sha256 != artifacts.active_vault.sha256
    assert parsed.raw == payload
    assert parsed.rank_source_vault == artifacts.rank_vault
    assert parsed.rank_source_vault_sha256 == artifacts.rank_vault.sha256
    assert parsed.input_vault == artifacts.active_vault
    assert parsed.reader["order_sha256"] == artifacts.decision.order_sha256
    assert sieve_v16.validate_native_lifecycle(payload)


Mutation = Callable[[dict[str, Any]], None]


def _set_top(field: str, value: object) -> Mutation:
    return lambda payload: payload.__setitem__(field, value)


def _set_nested(section: str, field: str, value: object) -> Mutation:
    def mutate(payload: dict[str, Any]) -> None:
        payload[section][field] = value

    return mutate


@pytest.mark.parametrize(
    "mutation",
    (
        _set_top("schema", "legacy"),
        _set_top("implementation_release_parent_schema", "legacy"),
        _set_top("rank_source_vault_sha256", "00" * 32),
        _set_nested("reader", "source_vault_sha256", "00" * 32),
        _set_nested("vault", "input_sha256", "00" * 32),
    ),
)
def test_split_identity_mutations_fail_closed(
    native_fixture: Path,
    tmp_path: Path,
    mutation: Mutation,
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = copy.deepcopy(_native_payload(native_fixture, artifacts))
    mutation(payload)
    with pytest.raises(O1RelationalSearchError, match="joint-score-sieve-v16"):
        _parse(payload, artifacts)


def test_process_adapter_reads_both_inputs_and_returns_raw_v13(
    native_fixture: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(tmp_path)
    derived_from: list[bytes] = []

    def derive_from_rank_source(
        vault_payload: bytes, *_args: bytes
    ) -> VaultRankedDecision:
        derived_from.append(vault_payload)
        return artifacts.decision

    monkeypatch.setattr(
        sieve_v16,
        "derive_production_vault_ranked_decision",
        derive_from_rank_source,
    )
    result = sieve_v16.run_joint_score_sieve(
        executable=native_fixture,
        cnf_path=artifacts.cnf,
        potential_path=artifacts.potential,
        grouping_path=artifacts.grouping_path,
        rank_vault_path=artifacts.rank_vault_path,
        vault_path=artifacts.active_vault_path,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=12.0,
        conflict_limit=64,
        seed=0,
        timeout_seconds=10.0,
        require_active_contrast=False,
    )
    assert isinstance(result, sieve_v16.JointScoreSieveV16Result)
    assert result.raw["schema"] == sieve_v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert result.rank_source_vault.sha256 == artifacts.rank_vault.sha256
    assert result.input_vault.sha256 == artifacts.active_vault.sha256
    assert result.reader["source_vault_sha256"] == artifacts.rank_vault.sha256
    assert result.vault_telemetry["input_sha256"] == artifacts.active_vault.sha256
    assert derived_from == [artifacts.rank_vault.serialized]
    assert derived_from[0] != artifacts.active_vault.serialized


@pytest.mark.parametrize("drift_role", ("rank", "active"))
def test_process_adapter_stability_checks_each_vault(
    native_fixture: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift_role: str,
) -> None:
    artifacts = _artifacts(tmp_path)
    monkeypatch.setattr(
        sieve_v16,
        "derive_production_vault_ranked_decision",
        lambda *_args: artifacts.decision,
    )
    executor = sieve_v16._v15._v14._v13._v12._v11._v9._v8._v7
    original_execute = executor._execute_native
    drift_path = (
        artifacts.rank_vault_path
        if drift_role == "rank"
        else artifacts.active_vault_path
    )

    def execute_then_drift(
        command: list[str],
        *,
        timeout_seconds: float,
        memory_limit_bytes: int | None,
    ) -> object:
        result = original_execute(
            command,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        drift_path.write_bytes(drift_path.read_bytes() + b"x")
        return result

    monkeypatch.setattr(executor, "_execute_native", execute_then_drift)
    with pytest.raises(
        sieve_v16.JointScoreSieveExecutionError,
        match="joint-score-sieve-v16",
    ):
        sieve_v16.run_joint_score_sieve(
            executable=native_fixture,
            cnf_path=artifacts.cnf,
            potential_path=artifacts.potential,
            grouping_path=artifacts.grouping_path,
            rank_vault_path=artifacts.rank_vault_path,
            vault_path=artifacts.active_vault_path,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=12.0,
            conflict_limit=64,
            seed=0,
            timeout_seconds=10.0,
            require_active_contrast=False,
        )
