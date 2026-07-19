from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES,
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    ThresholdNoGoodVaultIdentity,
    ThresholdNoGoodVaultOverflow,
    VaultCaps,
    append_new_deduplicated,
    empty_threshold_no_good_vault,
    observed_variables_bytes,
    observed_variables_sha256,
    parse_threshold_no_good_vault,
    partial_assignment_from_vault_clause,
    read_threshold_no_good_vault,
    serialize_threshold_no_good_vault,
    validate_threshold_no_good_vault_identity,
    vault_clause_from_partial_assignment,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


def _identity(
    observed: tuple[int, ...] = (1, 2, 9), *, threshold: float = -1.25
) -> ThresholdNoGoodVaultIdentity:
    return vault_identity_from_sources(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables=observed,
        bound_rule="exact-safe-grouped-bound-v1",
        threshold=threshold,
    )


def _vault(
    clauses: tuple[ThresholdNoGoodClause, ...] = (),
    *,
    observed: tuple[int, ...] = (1, 2, 9),
    threshold: float = -1.25,
) -> ThresholdNoGoodVault:
    return ThresholdNoGoodVault(
        _identity(observed, threshold=threshold), observed, clauses
    )


def test_magic_header_round_trip_and_hash_are_exact() -> None:
    clauses = (
        ThresholdNoGoodClause((-1, 2)),
        ThresholdNoGoodClause((1, -9)),
    )
    vault = _vault(clauses)
    payload = serialize_threshold_no_good_vault(vault, caps=O1C66_VAULT_CAPS)

    assert THRESHOLD_NO_GOOD_VAULT_MAGIC == b"O1-NOGOOD-VAULT-V1\0"
    assert len(THRESHOLD_NO_GOOD_VAULT_MAGIC) == 19
    assert THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES == 191
    assert payload[:19] == THRESHOLD_NO_GOOD_VAULT_MAGIC
    assert len(payload) == 191 + (4 + 2 * 4) * 2
    assert payload[-24:] == clauses[0].serialized + clauses[1].serialized
    assert vault.sha256 == hashlib.sha256(payload).hexdigest()
    assert vault.clause_aggregate_sha256 == hashlib.sha256(payload[191:]).hexdigest()
    assert (
        parse_threshold_no_good_vault(
            payload, observed_variables=(1, 2, 9), caps=O1C66_VAULT_CAPS
        )
        == vault
    )


def test_empty_vault_has_canonical_empty_aggregate() -> None:
    vault = empty_threshold_no_good_vault(
        identity=_identity(), observed_variables=(1, 2, 9), caps=O1C66_VAULT_CAPS
    )
    assert vault.serialized_bytes == THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES
    assert vault.clause_count == vault.literal_count == 0
    assert vault.clause_aggregate_sha256 == hashlib.sha256(b"").hexdigest()
    assert vault.describe()["threshold_f64le_hex"] == struct.pack("<d", -1.25).hex()


@pytest.mark.parametrize(
    "literals",
    (
        (),
        (0,),
        (-(1 << 31),),
        ((1 << 31),),
        (2, 1),
        (-2, 2),
        (1, -1),
        (1, -1, 2),
    ),
)
def test_clause_constructor_rejects_noncanonical_literals(
    literals: tuple[int, ...],
) -> None:
    with pytest.raises(ThresholdNoGoodVaultError, match="clause"):
        ThresholdNoGoodClause(literals)


def test_clause_scope_duplicates_and_observed_identity_are_rejected() -> None:
    clause = ThresholdNoGoodClause((-1, 9))
    with pytest.raises(ThresholdNoGoodVaultError, match="not observed"):
        _vault((ThresholdNoGoodClause((1, 3)),))
    with pytest.raises(ThresholdNoGoodVaultError, match="duplicate"):
        _vault((clause, clause))
    with pytest.raises(ThresholdNoGoodVaultError, match="observed identity"):
        ThresholdNoGoodVault(_identity((1, 2)), (1, 2, 9), ())


def test_observed_variable_encoding_is_strict_and_deterministic() -> None:
    payload = struct.pack("<III", 1, 2, 9)
    assert observed_variables_bytes((1, 2, 9)) == payload
    assert observed_variables_sha256((1, 2, 9)) == hashlib.sha256(payload).hexdigest()
    for invalid in ((2, 1), (1, 1), (0, 1), (True, 2)):
        with pytest.raises(ThresholdNoGoodVaultError, match="observed"):
            observed_variables_bytes(invalid)  # type: ignore[arg-type]


def test_clause_assignment_polarity_round_trips() -> None:
    clause = vault_clause_from_partial_assignment({9: 1, 1: -1, 2: 1})
    assert clause.literals == (1, -2, -9)
    assert partial_assignment_from_vault_clause(clause) == {1: -1, 2: 1, 9: 1}
    with pytest.raises(ThresholdNoGoodVaultError, match="partial assignment"):
        vault_clause_from_partial_assignment({})


def test_parser_rejects_magic_truncation_trailing_and_duplicate_clause_bytes() -> None:
    clause = ThresholdNoGoodClause((-1, 2))
    vault = _vault((clause,))
    payload = vault.serialized
    corrupt_magic = b"X" + payload[1:]
    duplicate = bytearray(payload[:187])
    duplicate.extend(struct.pack("<I", 2))
    duplicate.extend(clause.serialized)
    duplicate.extend(clause.serialized)
    for malformed, pattern in (
        (corrupt_magic, "magic"),
        (payload[:180], "truncated"),
        (payload[:-1], "truncated"),
        (payload + b"x", "trailing"),
        (bytes(duplicate), "duplicate"),
    ):
        with pytest.raises(ThresholdNoGoodVaultError, match=pattern):
            parse_threshold_no_good_vault(
                malformed, observed_variables=(1, 2, 9), caps=O1C66_VAULT_CAPS
            )


def test_digest_tamper_parses_as_a_different_identity_and_is_rejected() -> None:
    vault = _vault()
    tampered = bytearray(vault.serialized)
    tampered[19] ^= 1
    parsed = parse_threshold_no_good_vault(
        bytes(tampered), observed_variables=(1, 2, 9), caps=O1C66_VAULT_CAPS
    )
    assert parsed.identity != vault.identity
    with pytest.raises(ThresholdNoGoodVaultError, match="identity contract"):
        validate_threshold_no_good_vault_identity(parsed, expected=vault.identity)


def test_threshold_identity_compares_exact_bits_including_signed_zero() -> None:
    positive = _identity(threshold=0.0)
    negative = _identity(threshold=-0.0)
    lower = _identity(threshold=math_next_down(-1.25))
    baseline = _identity(threshold=-1.25)

    assert positive != negative
    assert positive.threshold_f64le_hex == "0000000000000000"
    assert negative.threshold_f64le_hex == "0000000000000080"
    assert lower != baseline
    with pytest.raises(ThresholdNoGoodVaultError, match="identity contract"):
        validate_threshold_no_good_vault_identity(
            _vault(threshold=-1.25), expected=lower
        )


def math_next_down(value: float) -> float:
    bits = struct.unpack("<Q", struct.pack("<d", value))[0]
    return struct.unpack("<d", struct.pack("<Q", bits + 1))[0]


def test_append_is_exact_dedup_only_and_preserves_first_emission_order() -> None:
    existing = ThresholdNoGoodClause((-1,))
    larger = ThresholdNoGoodClause((-1, 2))
    other = ThresholdNoGoodClause((1, -9))
    vault = _vault((existing,))
    result = append_new_deduplicated(
        vault,
        (existing, larger, larger, other, existing),
        caps=O1C66_VAULT_CAPS,
    )

    assert result.vault.clauses == (existing, larger, other)
    assert result.appended_clauses == (larger, other)
    assert result.duplicate_clause_count == 3
    assert result.duplicate_literal_count == 4
    assert vault.clauses == (existing,)
    assert existing in result.vault.clauses and larger in result.vault.clauses


@pytest.mark.parametrize(
    ("caps", "expected_dimension"),
    (
        (VaultCaps(202, 10, 10), "serialized_bytes"),
        (VaultCaps(1_000, 1, 10), "clauses"),
        (VaultCaps(1_000, 10, 2), "literals"),
    ),
)
def test_append_overflow_is_typed_exact_and_atomic(
    caps: VaultCaps, expected_dimension: str
) -> None:
    existing = ThresholdNoGoodClause((-1,))
    vault = _vault((existing,))
    before = vault.serialized
    with pytest.raises(ThresholdNoGoodVaultOverflow) as raised:
        append_new_deduplicated(vault, (ThresholdNoGoodClause((1, 2)),), caps=caps)
    error = raised.value
    assert error.dimension == expected_dimension
    assert error.current_serialized_bytes == 199
    assert error.proposed_serialized_bytes == 211
    assert error.current_clauses == 1 and error.proposed_clauses == 2
    assert error.current_literals == 1 and error.proposed_literals == 3
    assert error.describe()["dimension"] == expected_dimension
    assert vault.serialized == before and vault.clauses == (existing,)


def test_append_overflow_stops_before_consuming_or_constructing_later_clauses() -> None:
    vault = _vault()

    def clauses():
        yield ThresholdNoGoodClause((-1, 2))
        raise AssertionError("iterator advanced beyond the atomic overflow")

    with pytest.raises(ThresholdNoGoodVaultOverflow):
        append_new_deduplicated(
            vault,
            clauses(),
            caps=VaultCaps(THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES + 11, 10, 10),
        )


def test_parse_enforces_all_caps_with_typed_overflow() -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 2)),))
    for caps, dimension in (
        (VaultCaps(len(vault.serialized) - 1, 10, 10), "serialized_bytes"),
        (VaultCaps(1_000, 0, 10), "clauses"),
        (VaultCaps(1_000, 10, 1), "literals"),
    ):
        with pytest.raises(ThresholdNoGoodVaultOverflow) as raised:
            parse_threshold_no_good_vault(
                vault.serialized, observed_variables=(1, 2, 9), caps=caps
            )
        assert raised.value.dimension == dimension


def test_atomic_file_writer_and_reader_preserve_exact_bytes(tmp_path: Path) -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 2)),))
    path = tmp_path / "archive.vault"
    assert (
        write_threshold_no_good_vault(path, vault, caps=O1C66_VAULT_CAPS)
        == vault.sha256
    )
    assert path.read_bytes() == vault.serialized
    assert not tuple(tmp_path.glob(".archive.vault.*.tmp"))
    assert (
        read_threshold_no_good_vault(
            path, observed_variables=(1, 2, 9), caps=O1C66_VAULT_CAPS
        )
        == vault
    )


def test_file_reader_rejects_payload_bytes_at_the_explicit_cap(tmp_path: Path) -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 2)),))
    path = tmp_path / "oversized.vault"
    path.write_bytes(vault.serialized)
    with pytest.raises(ThresholdNoGoodVaultOverflow) as raised:
        read_threshold_no_good_vault(
            path,
            observed_variables=(1, 2, 9),
            caps=VaultCaps(len(vault.serialized) - 1, 10, 10),
        )
    assert raised.value.dimension == "serialized_bytes"


def test_public_apis_require_explicit_caps() -> None:
    signatures = (
        serialize_threshold_no_good_vault,
        parse_threshold_no_good_vault,
        append_new_deduplicated,
        read_threshold_no_good_vault,
        write_threshold_no_good_vault,
    )
    for function in signatures:
        assert "caps" in function.__annotations__
