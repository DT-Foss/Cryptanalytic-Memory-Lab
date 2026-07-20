from __future__ import annotations

import ast
import hashlib
import inspect
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import o1_crypto_lab.joint_score_sieve_v29 as sieve
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.o1c82_parent_centered_seed import RECORD_BYTES, RECORD_STRUCT


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
RECEIPT = ROOT / sieve.O1C92_PRIORITY_RECEIPT_RELATIVE
LIVE_BANK = ROOT / sieve.O1C93_LIVE_BANK_RELATIVE
MANIFEST = ROOT / sieve.O1C93_MANIFEST_RELATIVE
PAGE15 = ROOT / sieve.O1C93_PAGE15_RELATIVE
PAGE14 = ROOT / "research/o1c91_page14_causal_rollover_seed_20260720/page-14-active.bin"
PAGE13 = ROOT / "research/o1c89_page13_causal_rollover_seed_20260720/page-13-active.bin"
PAGE12 = ROOT / "research/o1c87_page12_causal_rollover_seed_20260720/page-12-active.bin"
PAGE11 = ROOT / "research/o1c86_page11_causal_rollover_seed_20260720/page-11-active.bin"
PAGE10 = (
    ROOT / "research/o1c85_page10_transport_recovery_seed_20260720/page-10-active.bin"
)
PAGE9 = ROOT / "research/o1c83_causal_rollover_seed_20260720/page-09-active.bin"
OLD_LIVE_BANK = (
    ROOT / "research/o1c91_page14_causal_rollover_seed_20260720/"
    "final-parent-centered-priority-bank.bin"
)
V28 = ROOT / "src/o1_crypto_lab/joint_score_sieve_v28.py"
FROZEN_V28_SHA256 = "68b5c5cb0f07da89f6dd6efffcce8e35c1e332f96db861412e145c9987702d39"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _replace_packed_value(
    payload: bytes, *, variable: int, index: int, value: int | float
) -> bytes:
    result = bytearray(payload)
    offset = (variable - 1) * RECORD_BYTES
    values = list(RECORD_STRUCT.unpack_from(result, offset))
    values[index] = value
    RECORD_STRUCT.pack_into(result, offset, *values)
    return bytes(result)


def test_o1c93_known_production_bindings_are_exact() -> None:
    assert sieve.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v29-adapter-v1")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v26")
    assert "o1c95" in sieve.PRIORITY_STATE_SCHEMA
    assert "o1c95" in sieve.PRIORITY_ACTION_SCHEMA
    assert sieve.NATIVE_SOURCE_BYTES == 49_762
    assert sieve.NATIVE_SOURCE_SHA256 == (
        "500909839e1e6698b92b56be2208320232ea080f01da23803db74137593c2ffc"
    )
    assert sieve.PRODUCTION_PAGE15_LINEAGE_ORDINAL == 28
    assert sieve.PRODUCTION_PAGE15_BYTES == 2_843_047
    assert (
        sieve.PRODUCTION_PAGE15_SHA256
        == "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2"
    )
    assert (
        sieve.LIVE_BANK_SHA256
        == "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca"
    )


def test_sealed_live_bank_exact_aggregate_and_old_bank_rejected() -> None:
    live = LIVE_BANK.read_bytes()
    records = sieve._decode_live_bank(
        live, expected_sha256=sieve.LIVE_BANK_SHA256, sealed_input=True
    )
    assert len(live) == 24_576
    assert len(records) == 256
    assert sum(record.count for record in records) == 283_069
    assert max(record.count for record in records) == 2_675
    assert min(record.count for record in records if record.count) == 227
    assert sum(record.count >= 37 for record in records) == 255
    assert tuple(record.variable for record in records if record.count == 0) == (241,)

    with pytest.raises(O1RelationalSearchError, match="prior live bank"):
        sieve._decode_live_bank(
            OLD_LIVE_BANK.read_bytes(),
            expected_sha256=sieve.LIVE_BANK_SHA256,
            sealed_input=True,
        )


@pytest.mark.parametrize(
    ("variable", "index", "value", "pattern"),
    (
        (1, 1, float("nan"), "finite record"),
        (1, 2, -1.0, "nonnegative M2"),
        (1, 3, 2**63, "sign partition"),
        (1, 9, 2.0, "absolute-z order"),
        (241, 1, 1.0, "zero coordinate"),
    ),
)
def test_live_bank_record_invariants_are_independent_of_digest(
    variable: int, index: int, value: int | float, pattern: str
) -> None:
    forged = _replace_packed_value(
        LIVE_BANK.read_bytes(), variable=variable, index=index, value=value
    )
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._decode_live_bank(forged, expected_sha256=None, sealed_input=False)


def test_output_counts_may_exceed_2675_but_must_replay_probe_delta() -> None:
    before_payload = LIVE_BANK.read_bytes()
    before = sieve._decode_live_bank(
        before_payload,
        expected_sha256=sieve.LIVE_BANK_SHA256,
        sealed_input=True,
    )
    maximum = max(before, key=lambda record: record.count)
    assert maximum.count == 2_675
    after_payload = _replace_packed_value(
        before_payload,
        variable=maximum.variable,
        index=0,
        value=maximum.count + 1,
    )
    after = sieve._decode_live_bank(
        after_payload, expected_sha256=None, sealed_input=False
    )
    assert max(record.count for record in after) == 2_676
    sieve._validate_continuation_transition(before, after, probe_count=1)

    with pytest.raises(O1RelationalSearchError, match="total count delta"):
        sieve._validate_continuation_transition(before, after, probe_count=2)
    decreasing = list(after)
    decreasing[0] = replace(decreasing[0], count=before[0].count - 1)
    with pytest.raises(O1RelationalSearchError, match="count monotonicity"):
        sieve._validate_continuation_transition(before, decreasing, probe_count=0)


def test_o1c92_receipt_replays_and_links_exact_final_bank() -> None:
    receipt = RECEIPT.read_bytes()
    bank = LIVE_BANK.read_bytes()
    assert len(receipt) == sieve.O1C92_PRIORITY_RECEIPT_BYTES == 52_014
    assert sieve.O1C92_PRIORITY_RECEIPT_SCHEMA.endswith(
        "o1c92-live-parent-centered-continuation-priority-state-v1"
    )
    assert _sha(receipt) == sieve.O1C92_PRIORITY_RECEIPT_SHA256
    assert len(bank) == 24_576
    assert _sha(bank) == sieve.LIVE_BANK_SHA256
    sieve._validate_receipt(receipt, bank)

    forged = bytearray(bank)
    forged[0] ^= 1
    with pytest.raises(O1RelationalSearchError, match="receipt bank linkage"):
        sieve._validate_receipt(receipt, bytes(forged))


def test_published_o1c93_manifest_contract_is_exact() -> None:
    assert (
        sieve.O1C93_MANIFEST_SCHEMA
        == "o1-256-o1c93-page15-causal-rollover-preparation-v1"
    )
    assert sieve.O1C93_MANIFEST_BYTES == 24_136
    assert sieve.O1C93_MANIFEST_SHA256 == (
        "187f09309b2d866549441d713f29bfed696c140f5c5a99536001c889f5836a24"
    )
    assert sieve.O1C93_MANIFEST_ARTIFACTS == frozenset(
        {
            "lineage-28-new-chunk.vault",
            "page-15-active.bin",
            "residency.json",
            "activation-ledger.json",
            "occurrence-ledger.json",
            "subsumption-relations.json",
            "common-signed-intersection-audit.json",
            "final-parent-centered-priority-bank.bin",
            "o1c92-priority-state-receipt.json",
        }
    )
    assert len(sieve.O1C93_PUBLISHED_ARTIFACTS) == 10
    assert sieve.O1C93_PAGE15_RELATIVE == Path(
        "research/o1c93_page15_causal_rollover_seed_20260720/page-15-active.bin"
    )
    assert sieve.O1C93_LINEAGE28_CHUNK_BYTES == 3_026_891
    assert sieve.O1C93_LINEAGE28_CHUNK_CLAUSE_COUNT == 261
    assert sieve.O1C93_LINEAGE28_CHUNK_LITERAL_COUNT == 756_414
    assert sieve.PRODUCTION_PAGE15_ACTIVE_LIMIT == 251
    assert sieve.PRODUCTION_PAGE15_CLAUSE_COUNT == 251
    assert sieve.PRODUCTION_PAGE15_LITERAL_COUNT == 710_463
    assert sieve.PRODUCTION_PAGE15_CATEGORY_COUNTS == {
        "structural_root": 9,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 199,
        "hot_event": 0,
        "recycled": 0,
    }
    assert sieve.PRODUCTION_PAGE15_HEADROOM == {
        "clauses": 261,
        "literals": 889_537,
        "serialized_bytes": 5_545_561,
    }

    payload = MANIFEST.read_bytes()
    assert len(payload) == sieve.O1C93_MANIFEST_BYTES
    assert _sha(payload) == sieve.O1C93_MANIFEST_SHA256
    assert sieve._manifest_contract() == (
        sieve.O1C93_MANIFEST_SCHEMA,
        sieve.O1C93_MANIFEST_BYTES,
        sieve.O1C93_MANIFEST_SHA256,
        sieve.O1C93_MANIFEST_ARTIFACTS,
    )
    sieve._validate_manifest(payload)

    manifest = json.loads(payload)
    assert manifest["attic"]["union_clause_count"] == 1_812
    assert manifest["attic"]["undominated_clause_count"] == 1_801
    relations = manifest["attic"]["new_strict_subsumption_relations"]
    assert [(row["subsumer_index"], row["subsumed_index"]) for row in relations] == [
        (1_554, 1_553)
    ]

    page15 = manifest["page15"]
    residency = page15["new_clause_residency"]
    assert residency["attic_retained_clause_count"] == 261
    assert residency["resident_clause_count"] == 160
    assert residency["missing_clause_count"] == 101
    assert residency["dominated_missing_union_indices"] == [1_553]
    assert residency["undominated_missing_clause_count"] == 100
    assert page15["never_resident_undominated"]["clause_count"] == 167

    capacity = page15["native_capacity_proof"]
    assert capacity["clause_headroom_guarantee"] == {
        "maximum_additional_clauses_before_capacity_terminal": 261,
        "native_vault_maximum_clauses": 512,
        "page15_input_clauses": 251,
        "parent_centered_action_capacity": 256,
        "proved_sufficient": True,
        "spare_clause_slots_beyond_action_capacity": 5,
    }
    assert capacity["recorded_residual_headroom"] == {
        "literals": 889_537,
        "serialized_bytes": 5_545_561,
    }
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False


@pytest.mark.parametrize(
    ("mutate", "pattern"),
    (
        (
            lambda root: root["page15"]["new_clause_residency"].__setitem__(
                "missing_clause_count", 100
            ),
            "new-clause residency",
        ),
        (
            lambda root: root["page15"]["new_clause_residency"].__setitem__(
                "dominated_missing_clause_count", 2
            ),
            "new-clause residency",
        ),
        (
            lambda root: root["page15"][
                "historical_never_resident_undominated"
            ].__setitem__(
                "newly_resident_union_indices", []
            ),
            "historical residency",
        ),
        (
            lambda root: root["page15"]["never_resident_undominated"].__setitem__(
                "clause_count", 166
            ),
            "never-resident-undominated",
        ),
        (
            lambda root: root["attic"]["new_strict_subsumption_relations"][0].__setitem__(
                "literal_delta", 3
            ),
            "manifest contract",
        ),
    ),
)
def test_manifest_residency_partitions_and_relations_are_fail_closed(
    mutate: object, pattern: str
) -> None:
    manifest = json.loads(MANIFEST.read_bytes())
    assert callable(mutate)
    mutate(manifest)
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._validate_manifest(canonical_json_bytes(manifest))


@pytest.mark.parametrize(
    "field",
    (
        "literal_future_emission_safety_claimed",
        "serialized_byte_future_emission_safety_claimed",
    ),
)
def test_non_clause_future_safety_claims_remain_false(field: str) -> None:
    manifest = json.loads(MANIFEST.read_bytes())
    manifest["page15"]["native_capacity_proof"][field] = True
    with pytest.raises(O1RelationalSearchError, match="manifest contract"):
        sieve._validate_manifest(canonical_json_bytes(manifest))


def test_page15_reader_accepts_only_the_bound_identity(tmp_path: Path) -> None:
    payload = PAGE15.read_bytes()
    assert len(payload) == sieve.PRODUCTION_PAGE15_BYTES
    assert _sha(payload) == sieve.PRODUCTION_PAGE15_SHA256
    resolved, accepted = sieve._read_page15(PAGE15)
    assert resolved == PAGE15.resolve()
    assert accepted == payload

    forged = bytearray(payload)
    forged[len(forged) // 2] ^= 1
    path = tmp_path / "forged-page-15-active.bin"
    path.write_bytes(forged)
    with pytest.raises(O1RelationalSearchError, match="Page15 active projection"):
        sieve._read_page15(path)


def test_burned_page14_through_page9_are_rejected() -> None:
    assert PAGE14.stat().st_size == sieve.BURNED_PAGE14_BYTES
    assert _sha(PAGE14.read_bytes()) == sieve.BURNED_PAGE14_SHA256
    assert PAGE13.stat().st_size == sieve.BURNED_PAGE13_BYTES
    assert _sha(PAGE13.read_bytes()) == sieve.BURNED_PAGE13_SHA256
    assert PAGE12.stat().st_size == sieve.BURNED_PAGE12_BYTES
    assert _sha(PAGE12.read_bytes()) == sieve.BURNED_PAGE12_SHA256
    assert PAGE11.stat().st_size == sieve.BURNED_PAGE11_BYTES
    assert _sha(PAGE11.read_bytes()) == sieve.BURNED_PAGE11_SHA256
    assert PAGE10.stat().st_size == sieve.BURNED_PAGE10_BYTES
    assert _sha(PAGE10.read_bytes()) == sieve.BURNED_PAGE10_SHA256
    assert PAGE9.stat().st_size == sieve.BURNED_PAGE9_BYTES
    assert _sha(PAGE9.read_bytes()) == sieve.BURNED_PAGE9_SHA256
    with pytest.raises(O1RelationalSearchError, match="burned Page14"):
        sieve._read_page15(PAGE14)
    with pytest.raises(O1RelationalSearchError, match="burned Page13"):
        sieve._read_page15(PAGE13)
    with pytest.raises(O1RelationalSearchError, match="burned Page12"):
        sieve._read_page15(PAGE12)
    with pytest.raises(O1RelationalSearchError, match="burned Page11"):
        sieve._read_page15(PAGE11)
    with pytest.raises(O1RelationalSearchError, match="burned Page10"):
        sieve._read_page15(PAGE10)
    with pytest.raises(O1RelationalSearchError, match="burned Page9"):
        sieve._read_page15(PAGE9)


def test_prelaunch_rechecks_every_sealed_input(tmp_path: Path) -> None:
    paths = {
        "source": tmp_path / SOURCE.name,
        "manifest": tmp_path / MANIFEST.name,
        "receipt": tmp_path / RECEIPT.name,
        "bank": tmp_path / LIVE_BANK.name,
        "page15": tmp_path / PAGE15.name,
    }
    for name, original in (
        ("source", SOURCE),
        ("manifest", MANIFEST),
        ("receipt", RECEIPT),
        ("bank", LIVE_BANK),
        ("page15", PAGE15),
    ):
        shutil.copyfile(original, paths[name])
    executable = tmp_path / "sealed-unit-executable"
    executable.write_bytes(b"sealed-unit-executable")
    executable.chmod(0o700)
    source_sha256 = _sha(paths["source"].read_bytes())
    executable_sha256 = _sha(executable.read_bytes())

    def validate() -> None:
        sieve._validate_prelaunch(
            source_path=paths["source"],
            executable_path=executable,
            manifest_path=paths["manifest"],
            receipt_path=paths["receipt"],
            bank_path=paths["bank"],
            page15_path=paths["page15"],
            expected_source_sha256=source_sha256,
            expected_executable_sha256=executable_sha256,
            expected_executable_bytes=len(b"sealed-unit-executable"),
        )

    validate()
    for candidate in (*paths.values(), executable):
        original = candidate.read_bytes()
        forged = bytearray(original)
        forged[len(forged) // 2] ^= 1
        candidate.write_bytes(forged)
        with pytest.raises(O1RelationalSearchError, match="differs"):
            validate()
        candidate.write_bytes(original)


def test_priority_seed_report_requires_live_provenance() -> None:
    report: dict[str, object] = {
        "magic": sieve.PRIORITY_SEED_MAGIC,
        "schema": sieve.PRIORITY_SEED_SCHEMA,
        "payload_bytes": 24_576,
        "payload_sha256": sieve.LIVE_BANK_SHA256,
        "production_seal_enforced": True,
        "expected_production_sha256": sieve.LIVE_BANK_SHA256,
        "import_roundtrip_exact": True,
        "initial_eligible_coordinate_count": 255,
        "seed_source": sieve.PRIORITY_SEED_SOURCE,
        "live_continuation_bank_identity": True,
        "fresh_seed_parser_used": False,
    }
    assert (
        sieve._validate_seed_report(
            report,
            seed_sha256=sieve.LIVE_BANK_SHA256,
            production_seal=True,
        )
        == report
    )
    for field in (
        "seed_source",
        "live_continuation_bank_identity",
        "fresh_seed_parser_used",
    ):
        forged = dict(report)
        forged[field] = None
        with pytest.raises(O1RelationalSearchError, match="priority seed contract"):
            sieve._validate_seed_report(
                forged,
                seed_sha256=sieve.LIVE_BANK_SHA256,
                production_seal=True,
            )


def test_adapter_has_no_seed_parser_or_native_build_dependency() -> None:
    tree = ast.parse(Path(sieve.__file__).read_text(encoding="utf-8"))
    forbidden = {
        "parse_seed_bank",
        "EXPECTED_BANK_SHA256",
        "_build_native",
        "build_native_joint_score_sieve",
        "shutil",
    }
    referenced = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    imported = {
        alias.name.rsplit(".", 1)[-1]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not forbidden & (referenced | imported)


def test_dynamic_executable_identity_is_required_immediately_before_one_launch() -> (
    None
):
    signature = inspect.signature(sieve.run_joint_score_sieve)
    for name in ("expected_executable_sha256", "expected_executable_bytes"):
        parameter = signature.parameters[name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    source = Path(sieve.__file__).read_text(encoding="utf-8")
    immediate = source.index('label="native executable immediately before launch"')
    launch = source.index("execution = _v9._v8._v7._execute_native(", immediate)
    assert immediate < launch
    assert source.count("_execute_native(") == 1
    assert "timeout_seconds=float(timeout_seconds)" in source[launch:]
    assert "EXPECTED_EXECUTABLE_SHA256" not in source


def test_result_and_continuation_replay_hooks_are_preserved() -> None:
    source = Path(sieve.__file__).read_text(encoding="utf-8")
    assert "_v22._validate_priority_state(" in source
    assert "_v22._validate_actions(" in source
    assert "_v22._validate_ownership_linkage(" in source
    assert "_validate_continuation_transition(" in source
    assert "derive_vault_soft_conflict_ledger(" in source
    assert "_v9._parse_native_payload(" in source


def test_historical_v28_adapter_is_untouched() -> None:
    assert _sha(V28.read_bytes()) == FROZEN_V28_SHA256


def test_native_v26_source_contract() -> None:
    source_bytes = SOURCE.read_bytes()
    assert len(source_bytes) == sieve.NATIVE_SOURCE_BYTES
    assert _sha(source_bytes) == sieve.NATIVE_SOURCE_SHA256
    source = source_bytes.decode("utf-8")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA in source
    assert sieve.PRIORITY_STATE_SCHEMA in source
    assert sieve.PRIORITY_ACTION_SCHEMA in source
    assert sieve.LIVE_BANK_SHA256 in source
    assert sieve.PRODUCTION_PAGE15_SHA256 in source
    assert sieve.BURNED_PAGE14_SHA256 in source
    assert sieve.BURNED_PAGE12_SHA256 in source
    assert sieve.BURNED_PAGE11_SHA256 in source
    assert sieve.BURNED_PAGE10_SHA256 in source
    assert sieve.BURNED_PAGE9_SHA256 in source
    assert r"fresh_seed_parser_used\":false" in source
    assert "truth_key" not in source
