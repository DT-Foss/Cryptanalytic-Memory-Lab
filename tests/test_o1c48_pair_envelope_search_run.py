from __future__ import annotations

import copy
import hashlib
import inspect
import json
import shlex
from pathlib import Path

import pytest

import o1_crypto_lab.o1c48_pair_envelope_search_run as run_module
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.o1c48_pair_envelope_search_run import (
    O1C48RunError,
    _PostFreezeSourceGate,
    _compile_pair_plans,
    _evaluate_gate,
    _model_honors_fixed_spins,
    _reproduction_command,
    _snapshot_nonprotected_sources,
    _snapshot_consumed_config,
    _validate_config_contract,
    _verify_nonprotected_sources_unchanged,
    _verify_consumed_config_unchanged,
    load_config,
)
from o1_crypto_lab.proof_parent_criticality import (
    ParentCriticalityFactor,
    ParentCriticalityField,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c48_pair_envelope_search_v1.json"


def test_frozen_config_has_exact_work_ledger_and_defers_protected_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    _validate_config_contract(config)
    assert len(config["search"]["arms"]) * (
        1 + len(config["search"]["residual_widths"])
    ) == config["budgets"]["maximum_native_solver_calls"] == 12
    assert (
        config["budgets"]["maximum_native_solver_calls"]
        * config["search"]["conflict_limit"]
        == config["budgets"]["maximum_requested_conflicts"]
        == 6144
    )

    invalid = copy.deepcopy(config)
    invalid["budgets"]["maximum_native_solver_calls"] = 11
    with pytest.raises(O1C48RunError, match="config ledger differs"):
        _validate_config_contract(invalid)
    invalid = copy.deepcopy(config)
    invalid["search"]["scored_call_timeout_seconds"] = 121
    with pytest.raises(O1C48RunError, match="config ledger differs"):
        _validate_config_contract(invalid)
    invalid = copy.deepcopy(config)
    invalid["unexpected"] = True
    with pytest.raises(O1C48RunError, match="top-level config fields differ"):
        _validate_config_contract(invalid)

    hashed: list[Path] = []
    original_sha256_file = run_module.sha256_file

    def recording_sha256(path: str | Path) -> str:
        hashed.append(Path(path).resolve())
        return original_sha256_file(path)

    monkeypatch.setattr(run_module, "sha256_file", recording_sha256)
    loaded = load_config(CONFIG)
    assert loaded["attempt_id"] == "O1C-0048"
    protected = {
        (ROOT / loaded["source"][name]).resolve()
        for name in run_module.PROTECTED_SOURCES
    }
    assert protected.isdisjoint(hashed)


def _field() -> ParentCriticalityField:
    return ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=4,
        source_sha256="11" * 32,
        factors=(
            ParentCriticalityFactor(1, 1, 1, 300, 4, (1, 2, 300)),
            ParentCriticalityFactor(2, 1, 2, 301, 3, (2, 3, 301)),
            ParentCriticalityFactor(3, 1, 3, 302, 2, (3, 4, 302)),
            ParentCriticalityFactor(4, 1, 4, 303, 1, (1, 4, 303)),
        ),
        metrics={"factor_count": 4},
    )


def _pair_factor(
    left: int, right: int, internal: int, strength: float
) -> CriticalityPotentialFactor:
    return CriticalityPotentialFactor(
        (left, right, internal),
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, strength),
    )


def test_primary_plan_is_compiled_once_then_transformed_and_validated() -> None:
    potentials = {
        "primary": CriticalityPotentialField(
            offset=0.0,
            source_sha256="21" * 32,
            factors=(
                _pair_factor(1, 2, 300, 4.0),
                _pair_factor(3, 4, 302, 1.0),
            ),
        ),
        "key_rotated": CriticalityPotentialField(
            offset=0.0,
            source_sha256="22" * 32,
            factors=(
                _pair_factor(2, 3, 300, 4.0),
                _pair_factor(4, 5, 302, 1.0),
            ),
        ),
        "clause_rotated": CriticalityPotentialField(
            offset=0.0,
            source_sha256="23" * 32,
            factors=(
                _pair_factor(1, 2, 400, 4.0),
                _pair_factor(3, 4, 401, 1.0),
            ),
        ),
    }
    fields, plans, validation = _compile_pair_plans(_field(), potentials)
    assert plans["primary"].groups == ((1, 2), (3, 4))
    assert plans["key_rotated"].groups == ((2, 3), (4, 5))
    assert plans["clause_rotated"].groups == plans["primary"].groups
    for name in run_module.PAIR_ARMS:
        assert set(plans[name].ordered_variables) == {
            factor.key_variable for factor in fields[name].factors
        }
        assert set(plans[name].ordered_variables).issubset(
            potentials[name].observed_variables
        )
        assert validation[name]["partitions_transformed_field_keys_exactly"] is True
        assert validation[name]["all_pair_variables_observed_by_potential"] is True


def _search_row(
    name: str,
    *,
    recovered: bool,
    residual_bits: int | None = None,
    conflicts: int = 20,
) -> dict[str, object]:
    row: dict[str, object] = {
        "name": name,
        "model_publicly_verified": recovered,
        "stats": {"conflicts": conflicts},
    }
    if residual_bits is not None:
        row["residual_bits"] = residual_bits
        row["model_truth_hamming"] = 0 if recovered else None
        row["model_truth_exact"] = recovered
        row["model_matches_truth_fixed_prefix"] = recovered
    return row


def test_gate_is_lexicographic_and_requires_strict_primary_margin() -> None:
    full = [_search_row(name, recovered=False) for name in run_module.ARMS]
    residual = [
        _search_row(name, recovered=True, residual_bits=8, conflicts=20)
        for name in run_module.ARMS
    ]
    residual.append(
        _search_row("primary", recovered=True, residual_bits=9, conflicts=30)
    )
    gate = _evaluate_gate(full, residual, (8, 9))
    assert gate["passed"] is True
    assert gate["selected_tier"] == "strict-primary-residual-width"

    full[0] = _search_row("internal", recovered=True)
    gate = _evaluate_gate(full, residual, (8, 9))
    assert gate["passed"] is False
    assert gate["selected_tier"] == "control-full256-blocks-lower-tiers"

    full = [_search_row(name, recovered=name == "primary") for name in run_module.ARMS]
    full[2] = _search_row("key_rotated", recovered=True)
    gate = _evaluate_gate(full, residual, (8, 9))
    assert gate["passed"] is False
    assert gate["selected_tier"] == "strict-primary-full256"

    full = [_search_row(name, recovered=False) for name in run_module.ARMS]
    residual = [
        _search_row(
            name,
            recovered=True,
            residual_bits=8,
            conflicts=1 if name == "primary" else 20,
        )
        for name in run_module.ARMS
    ]
    gate = _evaluate_gate(full, residual, (8, 9))
    assert gate[
        "residual_frontier_tied_at_largest_all_arm_recovered_width"
    ] is True
    assert gate["primary_strict_residual_conflict_gain"] is True
    assert gate["passed"] is True

    residual.append(
        _search_row("key_rotated", recovered=True, residual_bits=9, conflicts=30)
    )
    gate = _evaluate_gate(full, residual, (8, 9))
    assert gate["maximum_recovered_residual_bits_by_arm"] == {
        "internal": 8,
        "primary": 8,
        "key_rotated": 9,
        "clause_rotated": 8,
    }
    assert gate[
        "residual_frontier_tied_at_largest_all_arm_recovered_width"
    ] is False
    assert gate["primary_strict_residual_conflict_gain"] is False
    assert gate["passed"] is False
    assert gate["selected_tier"] == "untied-residual-frontier-blocks-conflict-tier"

    residual = [
        _search_row(name, recovered=True, residual_bits=8)
        for name in run_module.ARMS
    ]
    primary = next(row for row in residual if row["name"] == "primary")
    primary["model_truth_hamming"] = 1
    primary["model_truth_exact"] = False
    gate = _evaluate_gate(full, residual, (8, 9))
    assert gate["maximum_recovered_residual_bits_by_arm"]["primary"] == 0
    assert gate["passed"] is False


def test_residual_prefix_membership_checks_every_fixed_bit() -> None:
    model = bytes([0b00000001]) + bytes(31)
    assert _model_honors_fixed_spins(model, {1: 1, 2: -1, 256: -1}) is True
    assert _model_honors_fixed_spins(model, {1: -1, 2: -1, 256: -1}) is False


def test_consumed_config_bytes_and_reproduction_command_are_stable(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config with spaces.json"
    config = {"schema": "test", "value": 1}
    original = (json.dumps(config, sort_keys=True) + "\n").encode("ascii")
    config_path.write_bytes(original)
    frozen = _snapshot_consumed_config(config_path, config)
    assert frozen == original
    _verify_consumed_config_unchanged(config_path, frozen)

    command = _reproduction_command(config_path)
    assert shlex.split(command)[-2:] == ["--config", str(config_path)]

    config_path.write_bytes(b'{"schema":"test","value":2}\n')
    with pytest.raises(O1C48RunError, match="changed before publication"):
        _verify_consumed_config_unchanged(config_path, frozen)


def test_nonprotected_source_snapshots_reject_late_mutation(tmp_path: Path) -> None:
    paths: dict[str, Path] = {}
    expected: dict[str, str] = {}
    for name in run_module.NON_PROTECTED_SOURCES:
        path = tmp_path / name
        payload = f"{name}\n".encode("ascii")
        path.write_bytes(payload)
        paths[name] = path
        expected[name] = hashlib.sha256(payload).hexdigest()
    snapshots, hashes = _snapshot_nonprotected_sources(paths, expected)
    assert hashes == expected
    _verify_nonprotected_sources_unchanged(paths, snapshots)

    paths["primary_potential"].write_bytes(b"mutated\n")
    with pytest.raises(O1C48RunError, match="changed during run for primary_potential"):
        _verify_nonprotected_sources_unchanged(paths, snapshots)


def test_protected_sources_cannot_be_opened_until_attacker_freeze(
    tmp_path: Path,
) -> None:
    paths: dict[str, Path] = {}
    expected: dict[str, str] = {}
    for name in run_module.PROTECTED_SOURCES:
        path = tmp_path / f"{name}.json"
        payload = (json.dumps({"name": name}, sort_keys=True) + "\n").encode("ascii")
        path.write_bytes(payload)
        paths[name] = path
        expected[name] = hashlib.sha256(payload).hexdigest()
    gate = _PostFreezeSourceGate(paths, expected)
    assert gate.pre_freeze_read_counts() == {
        name: 0 for name in run_module.PROTECTED_SOURCES
    }
    with pytest.raises(O1C48RunError, match="before attacker freeze"):
        gate.read_verified_json("reveal")
    gate.seal("ab" * 32)
    for name in run_module.PROTECTED_SOURCES:
        assert gate.read_verified_json(name) == {"name": name}
    assert gate.post_freeze_read_counts() == {
        name: 1 for name in run_module.PROTECTED_SOURCES
    }

    source = inspect.getsource(run_module.run)
    freeze_position = source.index("attacker_freeze_bytes =")
    assert freeze_position < source.index(
        'late_sources.read_verified_json("reveal")'
    )
    assert freeze_position < source.index(
        'late_sources.read_verified_json("o1c46_result")'
    )
    assert freeze_position < source.index(
        'late_sources.read_verified_json("o1c47_result")'
    )
