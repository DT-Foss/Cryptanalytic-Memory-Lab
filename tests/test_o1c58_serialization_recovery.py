from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import numpy as np
import pytest

import o1_crypto_lab.o1c58_serialization_recovery as recovery_module

from o1_crypto_lab.full256_broker import (
    ENTROPY_BYTES,
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
)
from o1_crypto_lab.o1c58_multiblock_bit_vault_gradient_run import (
    ALL_ARMS_LIVE_STATE_BYTES,
    ARMS,
    BLOCK_COUNT,
    KEY_BITS,
    PREFIXES,
    _confidence_order,
    _public_verify_key,
    _synthesize_key,
)
from o1_crypto_lab.o1c58_serialization_recovery import (
    MANIFEST_NAME,
    O1C58RecoveryError,
    RESULT_NAME,
    _atomic_write,
    _converge_result_manifest,
    _install_recovery_outputs,
    _manifest_bytes,
    _normalize_json,
    _parse_run_markdown,
    _reconstruct_truth,
    _validate_capsule_inventory,
)


def _run_bytes(
    *,
    classification: str = "MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER",
    base: int = 127,
    primary: int = 127,
    longest: int = 0,
    exact: bool = False,
    elapsed: float = 99.07695375000185,
    peak: int = 211124224,
) -> bytes:
    return (
        "# O1C Run O1C-0058\n\n"
        f"- Classification: `{classification}`\n"
        f"- Base / primary prefix-8 correct bits: `{base}` / `{primary}`\n"
        f"- Primary prefix-8 longest correct confidence prefix: `{longest}`\n"
        f"- Exact recovery: `{exact}`\n"
        f"- Elapsed seconds: `{elapsed}`\n"
        f"- Peak RSS bytes: `{peak}`\n"
        f"- Live efficacy/control vault bytes: `{ALL_ARMS_LIVE_STATE_BYTES}`\n\n"
        "The attended base, all finite differences, 256-cell vault snapshots, "
        "confidence orders, synthesized keys, and public output checks were frozen "
        "before the one-shot reveal. Prefixes 1/2/4 are post-selection evidence "
        "ablations; prefix 8 is the primary all-public-block attack.\n"
    ).encode("ascii")


def test_numpy_normalization_is_recursive_and_strict_json_serializable() -> None:
    value = {
        "integer": np.int64(7),
        "boolean": np.bool_(True),
        "float": np.float64(0.25),
        "nested": (np.uint16(9), {"array": np.asarray([1, 2], dtype=np.int32)}),
        "scalar_array": np.asarray(5, dtype=np.int16),
    }
    normalized = _normalize_json(value)
    assert normalized == {
        "integer": 7,
        "boolean": True,
        "float": 0.25,
        "nested": [9, {"array": [1, 2]}],
        "scalar_array": 5,
    }
    json.dumps(normalized, sort_keys=True, allow_nan=False)
    with pytest.raises(O1C58RecoveryError, match="non-finite"):
        _normalize_json(np.float64(np.inf))


def test_run_parser_accepts_only_the_original_structural_shape() -> None:
    parsed = _parse_run_markdown(_run_bytes())
    assert parsed == {
        "classification": "MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER",
        "base_correct_bits": 127,
        "primary_prefix8_correct_bits": 127,
        "primary_prefix8_longest_correct_confidence_prefix": 0,
        "exact_recovery": False,
        "elapsed_seconds": 99.07695375000185,
        "peak_rss_bytes": 211124224,
        "all_arms_live_state_bytes": 6144,
    }
    with pytest.raises(O1C58RecoveryError, match="RUN.md"):
        _parse_run_markdown(_run_bytes() + b"extra")


class _Entropy:
    def __call__(self, count: int) -> bytes:
        assert count == ENTROPY_BYTES
        return bytes((29 * index + 11) & 0xFF for index in range(count))


def test_truth_rows_and_classification_reconstruct_from_reveal_and_frozen_bytes() -> (
    None
):
    broker = Full256TargetBroker(
        block_count=BLOCK_COUNT,
        entropy_source=_Entropy(),
        entropy_source_id="test.o1c58.recovery",
        target_id="test-o1c58-recovery",
    )
    publication = broker.publish()
    public = public_view_from_publication(publication)
    receipt = make_freeze_receipt(
        publication, frozen_artifact_sha256=hashlib.sha256(b"freeze").hexdigest()
    )
    reveal = broker.reveal(receipt)
    base = bytes(range(32))
    vault_lookup: dict[tuple[str, int], np.ndarray] = {}
    confidence_lookup: dict[tuple[str, int], tuple[int, ...]] = {}
    candidate_lookup: dict[tuple[str, int], bytes] = {}
    verification_lookup: dict[tuple[str, int], dict[str, object]] = {}
    for arm_index, arm in enumerate(ARMS):
        for prefix in PREFIXES:
            evidence = np.asarray(
                [
                    float(((index + prefix + arm_index) % 5) - 2)
                    for index in range(KEY_BITS)
                ],
                dtype=np.float64,
            )
            candidate = _synthesize_key(base, evidence)
            key = (arm, prefix)
            vault_lookup[key] = evidence
            confidence_lookup[key] = _confidence_order(evidence)
            candidate_lookup[key] = candidate
            verification_lookup[key] = _public_verify_key(candidate, public)
    frozen: dict[str, object] = {
        "base_key": base,
        "base_verification": _public_verify_key(base, public),
        "vault_lookup": vault_lookup,
        "confidence_lookup": confidence_lookup,
        "candidate_lookup": candidate_lookup,
        "verification_lookup": verification_lookup,
    }
    config = {
        "success": {
            "confidence_guidance_depth": 8,
            "secondary_minimum_primary_prefix8_correct_bits": 144,
            "secondary_minimum_improvement_over_base_correct_bits": 8,
        }
    }
    reconstructed = _reconstruct_truth(config=config, reveal=reveal, frozen=frozen)
    rows = cast(list[dict[str, object]], reconstructed["truth_rows"])
    assert len(rows) == len(ARMS) * len(PREFIXES)
    assert [(row["arm"], row["prefix"]) for row in rows] == [
        (arm, prefix) for arm in ARMS for prefix in PREFIXES
    ]
    normalized = _normalize_json(
        {
            "truth_rows": reconstructed["truth_rows"],
            "base_metrics": reconstructed["base_metrics"],
            "gates": reconstructed["gates"],
        }
    )
    json.dumps(normalized, sort_keys=True, allow_nan=False)
    assert reconstructed["classification"] in {
        "MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER",
        "MULTIBLOCK_BIT_VAULT_PARTIAL_DIRECTIONAL_RECOVERY",
        "MULTIBLOCK_BIT_VAULT_EXACT_FULL256_RECOVERY",
    }


def _synthetic_partial_capsule(root: Path, payload: bytes) -> dict[str, object]:
    metadata = {
        "RUN.md": b"run",
        "command.txt": b"command",
        "config.json": b"{}\n",
        "freeze_receipt.json": b"{}\n",
        "publication.json": b"{}\n",
        "reveal.json": b"{}\n",
        "score_freeze.json": b"{}\n",
    }
    for name, content in metadata.items():
        (root / name).write_bytes(content)
    artifact = root / "payload.bin"
    artifact.write_bytes(payload)
    return {"payload.bin": hashlib.sha256(payload).hexdigest()}


def test_capsule_hash_tamper_and_second_write_are_refused(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    hashes = _synthetic_partial_capsule(capsule, b"frozen")
    members = _validate_capsule_inventory(capsule, hashes)
    assert members["payload.bin"] == b"frozen"
    (capsule / "payload.bin").write_bytes(b"tampered")
    with pytest.raises(O1C58RecoveryError, match="hash differs"):
        _validate_capsule_inventory(capsule, hashes)

    destination = tmp_path / "one-shot.json"
    _atomic_write(destination, b"first")
    with pytest.raises(O1C58RecoveryError, match="refusing to replace"):
        _atomic_write(destination, b"second")
    assert destination.read_bytes() == b"first"


def test_manifest_and_persistent_byte_ledger_converge_exactly() -> None:
    result: dict[str, object] = {
        "schema": "test",
        "resources": {"persistent_artifact_bytes": 0},
        "numpy": np.int64(13),
    }
    members = {"a.bin": b"a", "nested/b.bin": b"bb"}
    normalized, result_bytes, manifest = _converge_result_manifest(result, members)
    final = {**members, RESULT_NAME: result_bytes}
    assert manifest == _manifest_bytes(final)
    assert MANIFEST_NAME.encode() not in manifest
    assert cast(dict[str, object], normalized["resources"])[
        "persistent_artifact_bytes"
    ] == sum(len(payload) for payload in final.values()) + len(manifest)
    assert _converge_result_manifest(normalized, members)[1:] == (
        result_bytes,
        manifest,
    )


def test_staged_install_resumes_after_seal_before_authoritative_mirror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    hashes = _synthetic_partial_capsule(capsule, b"frozen")
    original = _validate_capsule_inventory(capsule, hashes)
    authoritative = tmp_path / "authoritative.json"
    command = b"recover\n"
    note = b"note\n"
    result = b'{"recovered":true}\n'
    manifest = _manifest_bytes(
        {
            **original,
            "RECOVERY.md": note,
            "recovery_command.txt": command,
            RESULT_NAME: result,
        }
    )
    real_install = recovery_module._install_exact

    def fail_authoritative(path: Path, payload: bytes) -> None:
        if path == authoritative:
            raise O1C58RecoveryError("simulated mirror interruption")
        real_install(path, payload)

    monkeypatch.setattr(recovery_module, "_install_exact", fail_authoritative)
    with pytest.raises(O1C58RecoveryError, match="simulated mirror"):
        _install_recovery_outputs(
            capsule=capsule,
            authoritative=authoritative,
            original_members=original,
            command=command,
            note=note,
            result_bytes=result,
            manifest=manifest,
        )
    assert not authoritative.exists()
    assert (capsule.stat().st_mode & 0o777) == 0o555
    assert (
        _validate_capsule_inventory(capsule, hashes, allow_recovery_prefix=True)
        == original
    )

    monkeypatch.setattr(recovery_module, "_install_exact", real_install)
    _install_recovery_outputs(
        capsule=capsule,
        authoritative=authoritative,
        original_members=original,
        command=command,
        note=note,
        result_bytes=result,
        manifest=manifest,
    )
    assert authoritative.read_bytes() == result
    assert (capsule / RESULT_NAME).read_bytes() == result
    assert (capsule / MANIFEST_NAME).read_bytes() == manifest

    # Leave pytest's temporary tree removable on every platform.
    capsule.chmod(0o755)
    for path in capsule.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)
