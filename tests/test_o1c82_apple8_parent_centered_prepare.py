from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c82_apple8_parent_centered_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1c82_parent_centered_seed import (
    BANK_BYTES,
    EXPECTED_BANK_SHA256,
)


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()
SEED_MANIFEST = (ROOT / prepare.DEFAULT_SEED_MANIFEST_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedParentCenteredArtifacts:
    return prepare.prepare_o1c82_parent_centered(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
        seed_manifest_path=SEED_MANIFEST,
    )


def test_page8_advance_and_zero_call_contract_are_exact(
    prepared: prepare.PreparedParentCenteredArtifacts,
) -> None:
    state = prepared.state
    assert state.current_projection.lineage_ordinal == 21
    assert state.active_projection.sha256 == prepare.PAGE8_SHA256
    assert state.active_projection.serialized_bytes == prepare.PAGE8_SERIALIZED_BYTES
    assert state.current_projection.describe()["selection_order_sha256"] == (
        prepare.PAGE8_SELECTION_ORDER_SHA256
    )
    assert state.active_projection.sha256 not in state.used_active_sha256[:-1]
    assert state.used_active_sha256[-2] == prepare.PAGE7_SHA256
    assert state.used_active_sha256[-1] == state.active_projection.sha256
    assert len(state.activation_ledger) == 9
    assert len(state.attic.chunks) == 12
    assert state.attic.chunks[-1].clause_count == 0
    assert state.attic.chunks[-1].sha256 == prepare.EMPTY_ROLLOVER_SHA256
    assert state.attic.chunks[-1].serialized_bytes == prepare.EMPTY_ROLLOVER_BYTES
    assert len(canonical_json_bytes(state.describe())) == prepare.PAGE8_RESIDENCY_BYTES
    assert len(canonical_json_bytes(state.activation_ledger_document())) == (
        prepare.PAGE8_ACTIVATION_LEDGER_BYTES
    )
    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    assert prepared.manifest["authorization"] == {
        "science_call_authorized": False,
        "intent_created": False,
        "page8_burned": False,
        "lineage21_burned": False,
        "page7_replay_authorized": False,
    }
    page8 = prepared.manifest["page8"]
    assert isinstance(page8, dict)
    assert page8["fresh_identity"] is True
    assert page8["advance_api"] == "advance_causal_residency"
    assert page8["rollover_clause_count"] == 0
    assert page8["rollover_occurrence_count"] == 0


def test_artifact_mapping_binds_state_ledger_and_seed_exactly(
    prepared: prepare.PreparedParentCenteredArtifacts,
) -> None:
    artifacts = prepared.artifacts
    assert set(artifacts) == {
        prepare.ACTIVE_PROJECTION_NAME,
        prepare.ACTIVATION_LEDGER_NAME,
        prepare.EMPTY_ROLLOVER_NAME,
        prepare.PREPARATION_MANIFEST_NAME,
        prepare.RESIDENCY_NAME,
        prepare.SEED_BANK_NAME,
        prepare.SEED_MANIFEST_NAME,
    }
    assert artifacts[prepare.ACTIVE_PROJECTION_NAME] == (
        prepared.state.active_projection.serialized
    )
    assert artifacts[prepare.RESIDENCY_NAME] == canonical_json_bytes(
        prepared.state.describe()
    )
    assert artifacts[prepare.ACTIVATION_LEDGER_NAME] == canonical_json_bytes(
        prepared.state.activation_ledger_document()
    )
    assert len(artifacts[prepare.SEED_BANK_NAME]) == BANK_BYTES
    assert _sha256(artifacts[prepare.SEED_BANK_NAME]) == EXPECTED_BANK_SHA256
    assert len(artifacts[prepare.SEED_MANIFEST_NAME]) == prepare.SEED_MANIFEST_BYTES
    assert _sha256(artifacts[prepare.SEED_MANIFEST_NAME]) == (
        prepare.SEED_MANIFEST_SHA256
    )
    assert artifacts[prepare.PREPARATION_MANIFEST_NAME] == canonical_json_bytes(
        prepared.manifest
    )
    manifest = json.loads(artifacts[prepare.PREPARATION_MANIFEST_NAME])
    assert isinstance(manifest, dict)
    rows: dict[str, Any] = manifest["artifacts"]
    for name, row in rows.items():
        assert row == {
            "serialized_bytes": len(artifacts[name]),
            "sha256": _sha256(artifacts[name]),
        }


def test_artifacts_can_only_be_staged_by_the_caller_in_a_temp_directory(
    prepared: prepare.PreparedParentCenteredArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page8-staging"
    output.mkdir()
    for name, payload in prepared.artifacts.items():
        (output / name).write_bytes(payload)
    assert {path.name: _sha256(path.read_bytes()) for path in output.iterdir()} == {
        name: _sha256(payload) for name, payload in prepared.artifacts.items()
    }


def test_replay_of_already_advanced_page_is_rejected(
    prepared: prepare.PreparedParentCenteredArtifacts,
) -> None:
    with pytest.raises(prepare.O1C82PreparationError, match="replay or mutation"):
        prepare._advance_page8(prepared.state)


def test_noncanonical_parent_and_seed_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(prepare.O1C82PreparationError, match="not canonical"):
        prepare.prepare_o1c82_parent_centered(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
            seed_manifest_path=SEED_MANIFEST,
        )

    alias = tmp_path / "capsule-alias"
    alias.symlink_to(CAPSULE, target_is_directory=True)
    with pytest.raises(prepare.O1C82PreparationError, match="not canonical"):
        prepare.prepare_o1c82_parent_centered(
            capsule_dir=alias,
            parent_result_path=PARENT_RESULT,
            seed_manifest_path=SEED_MANIFEST,
        )


def test_result_seed_and_capsule_mutations_are_rejected(tmp_path: Path) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}")
    with pytest.raises(prepare.O1C82PreparationError, match="result binding"):
        prepare.prepare_o1c82_parent_centered(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
            seed_manifest_path=SEED_MANIFEST,
        )

    bad_seed = (tmp_path / "seed.json").resolve()
    bad_seed.write_bytes(b"{}")
    with pytest.raises(prepare.O1C82PreparationError, match="seed manifest seal"):
        prepare._load_seed(bad_seed)

    capsule = tmp_path / "capsule"
    try:
        shutil.copytree(CAPSULE, capsule, copy_function=os.link)
    except OSError:
        shutil.copytree(CAPSULE, capsule)
    capsule.chmod(capsule.stat().st_mode | 0o700)
    (capsule / "unexpected").write_bytes(b"x")
    with pytest.raises(prepare.O1C82PreparationError, match="inventory"):
        prepare.prepare_o1c82_parent_centered(
            capsule_dir=capsule.resolve(),
            parent_result_path=PARENT_RESULT,
            seed_manifest_path=SEED_MANIFEST,
        )
