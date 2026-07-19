from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import math
from pathlib import Path
import struct

import pytest

from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import (
    build_compatibility_grouping,
    compatibility_grouped_upper_bound,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultIdentity,
    observed_variables_sha256,
)
from o1_crypto_lab.vault_phase_field_v1 import derive_vault_phase_field
from o1_crypto_lab.vault_ranked_decision_v1 import (
    PRODUCTION_CANDIDATE_COUNT,
    PRODUCTION_ORDER_BYTES,
    PRODUCTION_ORDER_SHA256,
    PRODUCTION_RANK_TABLE_BYTES,
    PRODUCTION_RANK_TABLE_SHA256,
    VAULT_RANKED_DECISION_READER_SCHEMA,
    VAULT_RANKED_DECISION_SPEC_SHA256,
    VaultRankedDecisionError,
    VaultRankedDecisionRow,
    canonical_gap,
    derive_production_vault_ranked_decision,
    derive_vault_ranked_decision,
    validate_production_vault_ranked_decision,
    validate_vault_ranked_decision,
    vault_ranked_decision_spec_bytes,
)


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_VAULT = (
    ROOT
    / "runs/20260719_170824_O1C-0069_apple8-alternating-reader-v1"
    / "vault-imported.bin"
)
PRODUCTION_POTENTIAL = (
    ROOT / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_"
    "crossblock-consequence-sieve-v1"
    / "artifacts/potential/primary-eight-block.potential"
)
PRODUCTION_GROUPING = (
    ROOT
    / "runs/20260719_123602_O1C-0065_apple8-width6-grouped-sieve-v1"
    / "apple9-width6.grouping"
)


def _phase_field(clauses: tuple[tuple[int, ...], ...], *, key_variable_count: int):
    observed = tuple(sorted({abs(literal) for clause in clauses for literal in clause}))
    identity = ThresholdNoGoodVaultIdentity(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables_sha256=observed_variables_sha256(observed),
        bound_rule_sha256="67" * 32,
        threshold=1.0,
    )
    vault = ThresholdNoGoodVault(
        identity,
        observed,
        tuple(ThresholdNoGoodClause(clause) for clause in clauses),
    )
    return derive_vault_phase_field(
        vault.serialized, key_variable_count=key_variable_count
    )


def _unary_field(energies: dict[int, tuple[float, float]]):
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="ab" * 32,
        factors=tuple(
            CriticalityPotentialFactor((variable,), values)
            for variable, values in sorted(energies.items())
        ),
    )
    return field, build_compatibility_grouping(field, width_cap=6)


@pytest.fixture(scope="module")
def production_payloads() -> tuple[bytes, bytes, bytes]:
    return (
        PRODUCTION_VAULT.read_bytes(),
        PRODUCTION_POTENTIAL.read_bytes(),
        PRODUCTION_GROUPING.read_bytes(),
    )


@pytest.fixture(scope="module")
def production_decision(production_payloads):
    vault, potential, grouping = production_payloads
    return derive_production_vault_ranked_decision(vault, potential, grouping)


def test_synthetic_rank_is_nonascending_plus3_minus1_minus2() -> None:
    phase = _phase_field(((-1, 4), (-2, 5), (3, 6)), key_variable_count=3)
    field, grouping = _unary_field({1: (0.0, 2.0), 2: (0.0, 1.0), 3: (0.0, 3.0)})

    decision = derive_vault_ranked_decision(phase, field, grouping)

    assert phase.delta == (-1, -1, 1)
    assert decision.ranked_literals == (3, -1, -2)
    assert [row.gap for row in decision.rows] == [3.0, 2.0, 1.0]
    assert decision.order_bytes == struct.pack("<3i", 3, -1, -2)
    for row in decision.rows:
        assert row.u_plus == compatibility_grouped_upper_bound(
            field, grouping, {row.variable: 1}
        )
        assert row.u_minus == compatibility_grouped_upper_bound(
            field, grouping, {row.variable: -1}
        )


def test_exact_ties_fall_back_to_variable_ascending() -> None:
    phase = _phase_field(((-1, 3), (2, 4)), key_variable_count=2)
    field, grouping = _unary_field({1: (0.0, 1.0), 2: (0.0, 1.0)})

    decision = derive_vault_ranked_decision(phase, field, grouping)

    assert tuple((row.variable, row.delta, row.gap) for row in decision.rows) == (
        (1, -1, 1.0),
        (2, 1, 1.0),
    )
    assert decision.ranked_literals == (-1, 2)


def test_zero_vote_and_potential_unobserved_variables_are_omitted() -> None:
    phase = _phase_field(((-2, 5), (3, 6)), key_variable_count=4)
    field, grouping = _unary_field({3: (0.0, 4.0)})

    decision = derive_vault_ranked_decision(phase, field, grouping)

    assert phase.delta == (0, -1, 1, 0)
    assert decision.ranked_literals == (3,)
    assert decision.zero_delta_variables == (1, 4)
    assert decision.unobserved_nonzero_variables == (2,)
    assert decision.describe()["zero_delta_count"] == 2
    assert decision.describe()["unobserved_nonzero_count"] == 1


def test_gap_is_exact_lattice_round_once_upward_and_positive_zero() -> None:
    small = 3.0 * 2.0**-55
    assert 1.0 - small == math.nextafter(1.0, 0.0)
    assert canonical_gap(1.0, small) == 1.0
    assert struct.pack("<d", canonical_gap(-0.0, 0.0)) == b"\0" * 8

    for invalid in (math.inf, -math.inf, math.nan, 1, True):
        with pytest.raises(VaultRankedDecisionError, match="bound differs"):
            canonical_gap(invalid, 0.0)  # type: ignore[arg-type]


def test_spec_reader_and_immutable_row_are_canonical(production_decision) -> None:
    spec = vault_ranked_decision_spec_bytes()
    binding = production_decision.reader_binding()
    assert len(spec) == 674
    assert hashlib.sha256(spec).hexdigest() == VAULT_RANKED_DECISION_SPEC_SHA256
    assert binding["schema"] == VAULT_RANKED_DECISION_READER_SCHEMA
    assert binding["ranked_literals"] == list(production_decision.ranked_literals)
    assert binding["rank_table_rows"] == PRODUCTION_CANDIDATE_COUNT
    assert set(binding) == {
        "schema",
        "operator",
        "source_vault_sha256",
        "suffix_canonical_records_sha256",
        "vote_field_sha256",
        "potential_sha256",
        "potential_source_sha256",
        "grouping_sha256",
        "grouping_width_cap",
        "key_variable_count",
        "observed_variable_count",
        "candidate_count",
        "zero_delta_count",
        "unobserved_nonzero_count",
        "vote_rule",
        "bound_rule",
        "gap_rule",
        "sort_rule",
        "literal_rule",
        "reader_spec_bytes",
        "reader_spec_sha256",
        "order_encoding",
        "ranked_literals",
        "order_bytes",
        "order_sha256",
        "rank_table_encoding",
        "rank_table_rows",
        "rank_table_bytes",
        "rank_table_sha256",
    }

    row = production_decision.rows[0]
    with pytest.raises(FrozenInstanceError):
        row.delta = 0  # type: ignore[misc]
    with pytest.raises(VaultRankedDecisionError, match="row differs"):
        VaultRankedDecisionRow(row.variable, row.delta, row.u_plus, row.u_minus, 0.0)


def test_production_artifacts_reproduce_all_deterministic_identities(
    production_decision,
) -> None:
    decision = validate_production_vault_ranked_decision(production_decision)
    assert validate_vault_ranked_decision(decision) is decision
    assert decision.candidate_count == PRODUCTION_CANDIDATE_COUNT == 255
    assert decision.zero_delta_variables == (241,)
    assert decision.unobserved_nonzero_variables == ()
    assert decision.ranked_literals[:6] == (158, -188, 169, -190, -247, -189)
    assert len(decision.order_bytes) == PRODUCTION_ORDER_BYTES == 1_020
    assert (
        decision.order_sha256
        == PRODUCTION_ORDER_SHA256
        == ("26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5")
    )
    assert len(decision.rank_table_bytes) == PRODUCTION_RANK_TABLE_BYTES == 9_180
    assert (
        decision.rank_table_sha256
        == PRODUCTION_RANK_TABLE_SHA256
        == ("d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae")
    )
    first = struct.unpack_from("<Iqddd", decision.rank_table_bytes)
    assert first == (
        decision.rows[0].variable,
        decision.rows[0].delta,
        decision.rows[0].u_plus,
        decision.rows[0].u_minus,
        decision.rows[0].gap,
    )


@pytest.mark.parametrize("artifact", ("vault", "potential", "grouping"))
def test_production_derivation_rejects_single_byte_tamper(
    production_payloads, artifact: str
) -> None:
    values = [bytearray(value) for value in production_payloads]
    index = {"vault": 0, "potential": 1, "grouping": 2}[artifact]
    values[index][-1] ^= 1
    with pytest.raises(VaultRankedDecisionError):
        derive_production_vault_ranked_decision(*(bytes(value) for value in values))


def test_projection_tamper_and_wrong_types_fail_closed(production_decision) -> None:
    with pytest.raises(VaultRankedDecisionError, match="projection differs"):
        replace(production_decision, order_bytes=production_decision.order_bytes + b"x")
    with pytest.raises(VaultRankedDecisionError, match="type differs"):
        validate_vault_ranked_decision(object())  # type: ignore[arg-type]


def test_module_has_no_private_answer_artifact_dependency() -> None:
    source = (ROOT / "src/o1_crypto_lab/vault_ranked_decision_v1.py").read_text(
        encoding="utf-8"
    )
    forbidden = ("tr" + "uth", "rev" + "eal")
    assert all(token not in source.lower() for token in forbidden)
