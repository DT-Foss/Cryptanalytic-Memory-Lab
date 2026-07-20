from __future__ import annotations

import copy
import hashlib
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c94_page14_nine_axis_quotient as quotient
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[1]
PERSISTED_RESULT = ROOT / quotient.RESULT_RELATIVE
PERSISTED_INTERPRETATION = ROOT / quotient.INTERPRETATION_RELATIVE


def _mapping(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def source() -> quotient.SealedSource:
    return quotient.load_sealed_source(ROOT)


@pytest.fixture(scope="module")
def factored(source: quotient.SealedSource) -> quotient.NineAxisQuotient:
    return quotient.build_quotient(source.occurrences)


@pytest.fixture(scope="module")
def result() -> dict[str, object]:
    return quotient.generate_result(ROOT)


def test_sealed_source_population_and_semantic_identity(
    source: quotient.SealedSource,
) -> None:
    assert len(source.occurrences) == 261
    assert sum(row.clause.literal_count for row in source.occurrences) == 756_414
    assert len({row.clause_sha256 for row in source.occurrences}) == 261
    assert len({row.witness_sha256 for row in source.occurrences}) == 261
    assert len({row.witness_score_f64le_hex for row in source.occurrences}) == 261
    assert all(row.classification == "new" for row in source.occurrences)
    assert all(row.source == "trail_upper_bound" for row in source.occurrences)
    aggregate = hashlib.sha256(
        b"".join(row.clause.serialized for row in source.occurrences)
    ).hexdigest()
    assert aggregate == quotient.SOURCE_AGGREGATE_SHA256


def test_quotient_has_exact_shared_prefix_and_tail_shape(
    factored: quotient.NineAxisQuotient,
) -> None:
    assert len(factored.shared_signed_core) == 2_709
    assert [len(row.residual) for row in factored.prefix_rows] == [
        174,
        206,
        224,
        207,
        170,
    ]
    assert sum(len(row.residual) for row in factored.prefix_rows) == 981
    assert len(factored.tail_fixed_residual) == 71
    assert len(factored.copy_complement_map) == 118
    assert len(factored.tail_codewords) == 256
    assert len(set(factored.tail_codewords)) == 256
    assert len(factored.tail_witness_score_f64le_hex) == 256

    weights = Counter(
        quotient.AXES[row.axis_position] for row in factored.copy_complement_map
    )
    assert weights == Counter(
        {15: 8, 18: 6, 23: 9, 28: 20, 100: 9, 118: 16, 181: 12, 216: 19, 238: 19}
    )
    map_payload = canonical_json_bytes(
        [row.row() for row in factored.copy_complement_map]
    )
    assert len(map_payload) == 1_574
    assert (
        hashlib.sha256(map_payload).hexdigest() == quotient.COPY_COMPLEMENT_MAP_SHA256
    )


def test_canonical_quotient_round_trip_preserves_every_identity(
    source: quotient.SealedSource,
    factored: quotient.NineAxisQuotient,
) -> None:
    document = quotient.quotient_document(factored)
    assert canonical_json_bytes(document) == canonical_json_bytes(
        quotient.quotient_document(factored)
    )
    decoded = quotient.quotient_from_document(document)
    reconstructed = quotient.reconstruct_occurrences(decoded)
    receipt = quotient.verify_reconstruction_seals(
        reconstructed, source=source.occurrences
    )
    assert receipt["clause_count"] == 261
    assert receipt["literal_count"] == 756_414
    assert receipt["fully_emitted_aggregate_sha256"] == (
        "dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0"
    )
    assert receipt["per_row_clause_identities_match_sealed_source"] is True
    assert receipt["per_row_witness_identities_match_sealed_source"] is True


def test_negative_codeword_and_witness_mutations_are_rejected(
    source: quotient.SealedSource,
    factored: quotient.NineAxisQuotient,
) -> None:
    codeword_mutation = copy.deepcopy(quotient.quotient_document(factored))
    tail = _mapping(codeword_mutation["tail"])
    codewords = tail["codewords"]
    assert isinstance(codewords, list)
    first = codewords[0]
    assert isinstance(first, str)
    codewords[0] = ("1" if first[0] == "0" else "0") + first[1:]
    decoded = quotient.quotient_from_document(codeword_mutation)
    reconstructed = quotient.reconstruct_occurrences(decoded)
    with pytest.raises(quotient.O1C94QuotientError, match="reconstructed"):
        quotient.verify_reconstruction_seals(reconstructed, source=source.occurrences)

    witness_mutation = copy.deepcopy(quotient.quotient_document(factored))
    mutated_tail = _mapping(witness_mutation["tail"])
    witnesses = mutated_tail["witness_score_f64le_hex"]
    assert isinstance(witnesses, list)
    witnesses[0] = "000000000000f03f"
    decoded_witness = quotient.quotient_from_document(witness_mutation)
    reconstructed_witness = quotient.reconstruct_occurrences(decoded_witness)
    with pytest.raises(quotient.O1C94QuotientError, match="row 5 differs"):
        quotient.verify_reconstruction_seals(
            reconstructed_witness, source=source.occurrences
        )


def test_negative_core_and_copy_map_mutations_are_rejected(
    factored: quotient.NineAxisQuotient,
) -> None:
    core_mutation = copy.deepcopy(quotient.quotient_document(factored))
    core = _mapping(core_mutation["shared_signed_core"])
    encoded = core["i32le_base64"]
    assert isinstance(encoded, str)
    core["i32le_base64"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    with pytest.raises(quotient.O1C94QuotientError):
        quotient.quotient_from_document(core_mutation)

    map_mutation = copy.deepcopy(quotient.quotient_document(factored))
    tail = _mapping(map_mutation["tail"])
    rows = tail["copy_complement_map"]
    assert isinstance(rows, list)
    first = rows[0]
    assert isinstance(first, list)
    first[1] = 1 - first[1]
    with pytest.raises(
        quotient.O1C94QuotientError, match="copy/complement map seal differs"
    ):
        quotient.quotient_from_document(map_mutation)


def test_sealed_vault_rejects_byte_tamper_and_symlink(tmp_path: Path) -> None:
    capsule = tmp_path / quotient.SOURCE_CAPSULE_RELATIVE
    (capsule / "episodes/00").mkdir(parents=True)
    shutil.copy2(ROOT / quotient.SOURCE_MANIFEST_RELATIVE, capsule / "artifacts.sha256")
    shutil.copy2(ROOT / quotient.SOURCE_RESULT_RELATIVE, capsule / "result.json")
    source_vault = ROOT / quotient.SOURCE_VAULT_RELATIVE
    tampered = bytearray(source_vault.read_bytes())
    tampered[len(tampered) // 2] ^= 1
    (capsule / "episodes/00/vault.json").write_bytes(tampered)
    with pytest.raises(quotient.O1C94QuotientError, match="digest differs"):
        quotient.load_sealed_source(tmp_path)

    (capsule / "episodes/00/vault.json").unlink()
    try:
        (capsule / "episodes/00/vault.json").symlink_to(source_vault)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(quotient.O1C94QuotientError, match="sealed regular file"):
        quotient.load_sealed_source(tmp_path)


def test_cube_multiplicity_subsumption_and_storage_are_exact(
    result: dict[str, object],
) -> None:
    geometry = _mapping(result["geometry"])
    cube = _mapping(geometry["base_8_cube_multiplicities"])
    assert cube["unique_cell_count"] == 256
    assert cube["multiplicity_histogram"] == {"1": 253, "2": 2, "4": 1}
    assert cube["duplicate_patterns"] == {
        "00000000": 2,
        "00000110": 4,
        "10000000": 2,
    }
    subsumption = _mapping(result["subsumption"])
    relation = _mapping(subsumption["relation"])
    assert subsumption["proper_relation_count"] == 1
    assert relation["subsumer_index"] == 3
    assert relation["subsumed_index"] == 2
    assert relation["additional_literal_count"] == 17
    assert subsumption["lossless_quotient_retains_subsumed_row"] is True

    storage = _mapping(result["storage"])
    conservative = _mapping(storage["conservative_before_bit_packing"])
    assert conservative["raw_literal_entries"] == 756_414
    assert conservative["five_prefix_rows"] == 14_526
    assert conservative["one_tail_signed_core"] == 2_780
    assert conservative["tail_residuals"] == 30_208
    assert conservative["factored_literal_entries"] == 47_514
    assert conservative["saved_literal_entries"] == 708_900
    assert conservative["reduction_percent"] == pytest.approx(93.7185192236)
    assert conservative["times_smaller"] == pytest.approx(15.9198131077)


def test_live_state_is_bounded_and_claim_is_compression_only(
    result: dict[str, object],
) -> None:
    state = _mapping(result["state_accounting"])
    assert state["literal_pool"] == {
        "entries": 3_879,
        "packed_i32le_bytes": 15_516,
    }
    assert state["packed_codeword_bytes"] == 288
    assert state["packed_witness_score_bytes"] == 2_088
    assert state["maximum_row_scratch_literal_entries"] == 2_933
    assert state["packed_retained_quotient_bytes"] == 18_034
    assert state["maximum_row_scratch_bytes"] == 11_732
    assert state["maximum_live_decoder_bytes"] == 29_766
    assert state["raw_flat_clause_materialization_required"] is False

    boundary = _mapping(result["claim_boundary"])
    assert boundary["compression_only"] is True
    assert boundary["cnf_copy_complement_equivalences_proved"] is False
    assert boundary["logical_substitution_authorized"] is False
    assert boundary["key_bit_claims"] == 0
    assert boundary["entropy_gain_bits"] == 0.0


def test_config_source_seals_and_zero_call_scope_are_frozen(
    result: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_: object, **__: object) -> int:
        raise AssertionError("O1C94 attempted a prohibited external call")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    config = quotient.load_config(quotient.CONFIG_RELATIVE, root=ROOT)
    assert config.document["scope"] == {
        "fresh_targets": 0,
        "gpu_calls": 0,
        "mps_calls": 0,
        "native_solver_calls": 0,
        "preflight_calls": 0,
        "public_verification_calls": 0,
        "refits": 0,
        "reveal_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
    }
    assert _mapping(result["config_seal"])["sha256"] == config.sha256
    assert result["scope"] == config.document["scope"]


def test_persisted_outputs_are_fresh_canonical_and_deterministic(
    result: dict[str, object],
) -> None:
    json_payload = quotient.serialize_result(result)
    markdown_payload = quotient.render_interpretation(result)
    assert json_payload == quotient.serialize_result(result)
    assert PERSISTED_RESULT.read_bytes() == json_payload
    assert PERSISTED_INTERPRETATION.read_bytes() == markdown_payload
    assert b"PENDING" not in json_payload
    markdown = markdown_payload.decode("utf-8")
    assert "756414` \u2192 `47514" in markdown
    assert "This is compression only" in markdown
    assert "No solver, preflight, target, truth" in markdown
