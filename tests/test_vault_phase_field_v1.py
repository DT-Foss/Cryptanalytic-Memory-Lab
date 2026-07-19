from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from o1_crypto_lab.threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultIdentity,
    observed_variables_sha256,
)
from o1_crypto_lab.vault_phase_field_v1 import (
    PRODUCTION_BASE_VAULT_SHA256,
    PRODUCTION_EFFECTIVE_BITPACK_HEX,
    PRODUCTION_EFFECTIVE_BITPACK_SHA256,
    PRODUCTION_FIELD_SHA256,
    PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256,
    PRODUCTION_VAULT_PHASE_READER,
    PRODUCTION_VAULT_SHA256,
    VAULT_PHASE_READER_SPEC_SHA256,
    VaultPhaseFieldError,
    derive_vault_phase_field,
    validate_production_vault_phase_field,
    vault_phase_field_reader_spec_bytes,
)


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_VAULT = (
    ROOT
    / "runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1"
    / "vault-imported.bin"
)


def _generic_vault() -> ThresholdNoGoodVault:
    observed_variables = (1, 2, 3, 300)
    identity = ThresholdNoGoodVaultIdentity(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables_sha256=observed_variables_sha256(observed_variables),
        bound_rule_sha256="89" * 32,
        threshold=15.0,
    )
    clauses = (
        ThresholdNoGoodClause((1, -2)),
        ThresholdNoGoodClause((-1, 2, 300)),
        ThresholdNoGoodClause((-1, -2, 3)),
        ThresholdNoGoodClause((1, 2, -3)),
    )
    return ThresholdNoGoodVault(identity, observed_variables, clauses)


def test_generic_vault_slice_derives_signed_delta_field_and_fallback() -> None:
    vault = _generic_vault()
    field = derive_vault_phase_field(
        vault.serialized,
        key_variable_count=4,
        clause_start=1,
        clause_stop=4,
        fallback_phase=1,
    )

    assert field.source_vault_sha256 == vault.sha256
    assert field.source_clause_count == 4
    assert field.base_prefix_clause_count == 1
    assert field.suffix_clause_count == 3
    assert field.suffix_literal_count == 9
    assert field.positive_occurrences == (1, 2, 1, 0)
    assert field.negative_occurrences == (2, 1, 1, 0)
    assert field.delta == (-1, 1, 0, 0)
    assert field.phase_literals == (-1, 2, 0, 0)
    assert field.field_bytes == struct.pack("<4i", -1, 2, 0, 0)
    assert field.positive_count == 1
    assert field.negative_count == 1
    assert field.unphased_variables == (3, 4)
    assert field.applied_phase_calls == 2
    assert field.effective_bitpack == b"\x0e"

    expected_base = ThresholdNoGoodVault(
        vault.identity,
        vault.observed_variables,
        vault.clauses[:1],
    )
    assert field.base_prefix_vault_sha256 == expected_base.sha256
    assert (
        field.suffix_canonical_records_sha256
        == hashlib.sha256(
            b"".join(clause.serialized for clause in vault.clauses[1:])
        ).hexdigest()
    )


def test_generic_derivation_validates_types_slice_and_canonical_encoding() -> None:
    payload = _generic_vault().serialized
    with pytest.raises(VaultPhaseFieldError, match="payload type"):
        derive_vault_phase_field(bytearray(payload))  # type: ignore[arg-type]
    with pytest.raises(VaultPhaseFieldError, match="arguments"):
        derive_vault_phase_field(payload, key_variable_count=True)  # type: ignore[arg-type]
    with pytest.raises(VaultPhaseFieldError, match="slice"):
        derive_vault_phase_field(payload, clause_start=3, clause_stop=2)
    with pytest.raises(VaultPhaseFieldError, match="trailing"):
        derive_vault_phase_field(payload + b"\0")


def test_generic_derivation_matches_native_maximum_variable_bound() -> None:
    observed_variables = (1_000_001,)
    identity = ThresholdNoGoodVaultIdentity(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables_sha256=observed_variables_sha256(observed_variables),
        bound_rule_sha256="89" * 32,
        threshold=15.0,
    )
    vault = ThresholdNoGoodVault(
        identity,
        observed_variables,
        (ThresholdNoGoodClause(observed_variables),),
    )

    with pytest.raises(VaultPhaseFieldError, match="literal order differs"):
        derive_vault_phase_field(vault.serialized)


def test_production_reader_spec_and_immutable_mapping_are_exact() -> None:
    preimage = vault_phase_field_reader_spec_bytes()
    assert len(preimage) == 847
    assert preimage.endswith(b"32-bytes\n")
    assert hashlib.sha256(preimage).hexdigest() == VAULT_PHASE_READER_SPEC_SHA256
    assert PRODUCTION_VAULT_PHASE_READER["reader_spec_sha256"] == (
        VAULT_PHASE_READER_SPEC_SHA256
    )
    with pytest.raises(TypeError):
        PRODUCTION_VAULT_PHASE_READER["field_bytes"] = 0  # type: ignore[index]


def test_exact_production_vault_reproduces_every_sealed_projection() -> None:
    assert PRODUCTION_VAULT.is_file()
    payload = PRODUCTION_VAULT.read_bytes()
    field = validate_production_vault_phase_field(payload)

    assert field.source_vault_sha256 == PRODUCTION_VAULT_SHA256
    assert field.source_clause_count == 202
    assert field.base_prefix_clause_count == 12
    assert field.base_prefix_vault_sha256 == PRODUCTION_BASE_VAULT_SHA256
    assert field.suffix_start_clause_index == 12
    assert field.suffix_stop_clause_index_exclusive == 202
    assert field.suffix_clause_count == 190
    assert field.suffix_literal_count == 564_667
    assert field.suffix_canonical_records_sha256 == (
        PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256
    )
    assert len(field.field_bytes) == 1_024
    assert field.field_sha256 == PRODUCTION_FIELD_SHA256
    assert (field.positive_count, field.negative_count, field.unphased_count) == (
        139,
        116,
        1,
    )
    assert field.unphased_variables == (241,)
    assert field.applied_phase_calls == 255
    assert field.effective_bitpack.hex() == PRODUCTION_EFFECTIVE_BITPACK_HEX
    assert field.effective_bitpack_sha256 == PRODUCTION_EFFECTIVE_BITPACK_SHA256


def test_production_validator_rejects_a_single_byte_change() -> None:
    payload = bytearray(PRODUCTION_VAULT.read_bytes())
    payload[-1] ^= 1
    with pytest.raises(VaultPhaseFieldError):
        validate_production_vault_phase_field(bytes(payload))
