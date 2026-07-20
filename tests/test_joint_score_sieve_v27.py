from __future__ import annotations

import ast
import hashlib
import inspect
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import o1_crypto_lab.joint_score_sieve_v27 as sieve
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.o1c82_parent_centered_seed import RECORD_BYTES, RECORD_STRUCT


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
RECEIPT = ROOT / sieve.O1C88_PRIORITY_RECEIPT_RELATIVE
LIVE_BANK = ROOT / sieve.O1C89_LIVE_BANK_RELATIVE
MANIFEST = ROOT / sieve.O1C89_MANIFEST_RELATIVE
PAGE13 = ROOT / sieve.O1C89_PAGE13_RELATIVE
PAGE12 = ROOT / "research/o1c87_page12_causal_rollover_seed_20260720/page-12-active.bin"
PAGE11 = ROOT / "research/o1c86_page11_causal_rollover_seed_20260720/page-11-active.bin"
PAGE10 = (
    ROOT / "research/o1c85_page10_transport_recovery_seed_20260720/page-10-active.bin"
)
PAGE9 = ROOT / "research/o1c83_causal_rollover_seed_20260720/page-09-active.bin"
OLD_LIVE_BANK = (
    ROOT / "research/o1c87_page12_causal_rollover_seed_20260720/"
    "final-parent-centered-priority-bank.bin"
)
V26 = ROOT / "src/o1_crypto_lab/joint_score_sieve_v26.py"
FROZEN_V26_SHA256 = "6ebb77adf3ed20ce6447bcdb6bf542b9aa2e9fe12276f1161543a465c18d27f2"


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


def test_o1c89_known_production_bindings_are_exact() -> None:
    assert sieve.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v27-adapter-v1")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v24")
    assert "o1c90" in sieve.PRIORITY_STATE_SCHEMA
    assert "o1c90" in sieve.PRIORITY_ACTION_SCHEMA
    assert sieve.PRODUCTION_PAGE13_LINEAGE_ORDINAL == 26
    assert sieve.PRODUCTION_PAGE13_BYTES == 2_846_623
    assert (
        sieve.PRODUCTION_PAGE13_SHA256
        == "4c1b7d5a6d40fad9439d95433bcc7a60ff3e7ddc0e4542b0cf003cdf4581e546"
    )
    assert (
        sieve.LIVE_BANK_SHA256
        == "0203de9f1732b095bf30062cb8a07b018ded829ee99f18ffbca715c653c0cc6a"
    )


def test_sealed_live_bank_exact_aggregate_and_old_bank_rejected() -> None:
    live = LIVE_BANK.read_bytes()
    records = sieve._decode_live_bank(
        live, expected_sha256=sieve.LIVE_BANK_SHA256, sealed_input=True
    )
    assert len(live) == 24_576
    assert len(records) == 256
    assert sum(record.count for record in records) == 215_781
    assert max(record.count for record in records) == 1_752
    assert sum(record.count >= 37 for record in records) == 255
    assert tuple(record.variable for record in records if record.count == 0) == (241,)

    with pytest.raises(O1RelationalSearchError, match="live bank digest"):
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


def test_output_counts_may_exceed_1752_but_must_replay_probe_delta() -> None:
    before_payload = LIVE_BANK.read_bytes()
    before = sieve._decode_live_bank(
        before_payload,
        expected_sha256=sieve.LIVE_BANK_SHA256,
        sealed_input=True,
    )
    maximum = max(before, key=lambda record: record.count)
    assert maximum.count == 1_752
    after_payload = _replace_packed_value(
        before_payload,
        variable=maximum.variable,
        index=0,
        value=maximum.count + 1,
    )
    after = sieve._decode_live_bank(
        after_payload, expected_sha256=None, sealed_input=False
    )
    assert max(record.count for record in after) == 1_753
    sieve._validate_continuation_transition(before, after, probe_count=1)

    with pytest.raises(O1RelationalSearchError, match="total count delta"):
        sieve._validate_continuation_transition(before, after, probe_count=2)
    decreasing = list(after)
    decreasing[0] = replace(decreasing[0], count=before[0].count - 1)
    with pytest.raises(O1RelationalSearchError, match="count monotonicity"):
        sieve._validate_continuation_transition(before, decreasing, probe_count=0)


def test_o1c88_receipt_replays_and_links_exact_final_bank() -> None:
    receipt = RECEIPT.read_bytes()
    bank = LIVE_BANK.read_bytes()
    assert len(receipt) == sieve.O1C88_PRIORITY_RECEIPT_BYTES == 52_009
    assert _sha(receipt) == sieve.O1C88_PRIORITY_RECEIPT_SHA256
    assert len(bank) == 24_576
    assert _sha(bank) == sieve.LIVE_BANK_SHA256
    sieve._validate_receipt(receipt, bank)

    forged = bytearray(bank)
    forged[0] ^= 1
    with pytest.raises(O1RelationalSearchError, match="receipt bank linkage"):
        sieve._validate_receipt(receipt, bytes(forged))


def test_published_o1c89_manifest_contract_is_exact() -> None:
    assert (
        sieve.O1C89_MANIFEST_SCHEMA
        == "o1-256-o1c89-page13-causal-rollover-preparation-v1"
    )
    assert sieve.O1C89_MANIFEST_BYTES == 15_590
    assert (
        sieve.O1C89_MANIFEST_SHA256
        == "467e519df281db4fc10de9223195dfedba9fd51edc93b40883f59fd3821e29ec"
    )
    assert sieve.O1C89_MANIFEST_ARTIFACTS == frozenset(
        {
            "lineage-26-new-chunk.vault",
            "page-13-active.bin",
            "residency.json",
            "activation-ledger.json",
            "occurrence-ledger.json",
            "subsumption-relations.json",
            "common-signed-intersection-audit.json",
            "final-parent-centered-priority-bank.bin",
            "o1c88-priority-state-receipt.json",
        }
    )
    assert sieve.O1C89_PUBLISHED_ARTIFACTS == sieve.O1C89_MANIFEST_ARTIFACTS | {
        "causal-rollover-preparation-manifest.json"
    }
    assert len(sieve.O1C89_PUBLISHED_ARTIFACTS) == 10
    assert sieve.O1C89_MANIFEST_RELATIVE == Path(
        "research/o1c89_page13_causal_rollover_seed_20260720/"
        "causal-rollover-preparation-manifest.json"
    )
    assert sieve.O1C89_PAGE13_RELATIVE == Path(
        "research/o1c89_page13_causal_rollover_seed_20260720/page-13-active.bin"
    )
    assert sieve.PRODUCTION_PAGE13_ACTIVE_LIMIT == 253
    assert sieve.PRODUCTION_PAGE13_CLAUSE_COUNT == 253
    assert sieve.PRODUCTION_PAGE13_LITERAL_COUNT == 711_355
    assert sieve.PRODUCTION_PAGE13_CATEGORY_COUNTS == {
        "structural_root": 5,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 205,
        "hot_event": 0,
        "recycled": 0,
    }
    assert sieve.PRODUCTION_PAGE13_HEADROOM == {
        "clauses": 259,
        "literals": 888_645,
        "serialized_bytes": 5_541_985,
    }
    payload = MANIFEST.read_bytes()
    assert len(payload) == sieve.O1C89_MANIFEST_BYTES
    assert _sha(payload) == sieve.O1C89_MANIFEST_SHA256
    assert sieve._manifest_contract() == (
        sieve.O1C89_MANIFEST_SCHEMA,
        sieve.O1C89_MANIFEST_BYTES,
        sieve.O1C89_MANIFEST_SHA256,
        sieve.O1C89_MANIFEST_ARTIFACTS,
    )
    sieve._validate_manifest(payload)

    manifest = json.loads(payload)
    assert manifest["attic"]["union_clause_count"] == 1_291
    residency = manifest["page13"]["new_clause_residency"]
    assert residency["attic_retained_clause_count"] == 259
    assert residency["resident_clause_count"] == 205
    assert residency["missing_clause_count"] == 54
    assert residency["missing_union_indices"] == list(
        sieve.PRODUCTION_PAGE13_MISSING_NEW_UNION_INDICES
    )
    for field in (
        "literal_future_emission_safety_claimed",
        "serialized_byte_future_emission_safety_claimed",
    ):
        forged = json.loads(payload)
        forged["page13"]["native_capacity_proof"][field] = True
        with pytest.raises(O1RelationalSearchError, match="manifest contract"):
            sieve._validate_manifest(canonical_json_bytes(forged))


def test_page13_reader_accepts_only_the_bound_identity(tmp_path: Path) -> None:
    payload = PAGE13.read_bytes()
    assert len(payload) == sieve.PRODUCTION_PAGE13_BYTES
    assert _sha(payload) == sieve.PRODUCTION_PAGE13_SHA256
    resolved, accepted = sieve._read_page13(PAGE13)
    assert resolved == PAGE13.resolve()
    assert accepted == payload

    forged = bytearray(payload)
    forged[len(forged) // 2] ^= 1
    path = tmp_path / "forged-page-13-active.bin"
    path.write_bytes(forged)
    with pytest.raises(O1RelationalSearchError, match="Page13 active projection"):
        sieve._read_page13(path)


def test_burned_page12_page11_page10_and_page9_are_rejected() -> None:
    assert PAGE12.stat().st_size == sieve.BURNED_PAGE12_BYTES
    assert _sha(PAGE12.read_bytes()) == sieve.BURNED_PAGE12_SHA256
    assert PAGE11.stat().st_size == sieve.BURNED_PAGE11_BYTES
    assert _sha(PAGE11.read_bytes()) == sieve.BURNED_PAGE11_SHA256
    assert PAGE10.stat().st_size == sieve.BURNED_PAGE10_BYTES
    assert _sha(PAGE10.read_bytes()) == sieve.BURNED_PAGE10_SHA256
    assert PAGE9.stat().st_size == sieve.BURNED_PAGE9_BYTES
    assert _sha(PAGE9.read_bytes()) == sieve.BURNED_PAGE9_SHA256
    with pytest.raises(O1RelationalSearchError, match="burned Page12"):
        sieve._read_page13(PAGE12)
    with pytest.raises(O1RelationalSearchError, match="burned Page11"):
        sieve._read_page13(PAGE11)
    with pytest.raises(O1RelationalSearchError, match="burned Page10"):
        sieve._read_page13(PAGE10)
    with pytest.raises(O1RelationalSearchError, match="burned Page9"):
        sieve._read_page13(PAGE9)


def test_prelaunch_rechecks_every_sealed_input(tmp_path: Path) -> None:
    paths = {
        "source": tmp_path / SOURCE.name,
        "manifest": tmp_path / MANIFEST.name,
        "receipt": tmp_path / RECEIPT.name,
        "bank": tmp_path / LIVE_BANK.name,
        "page13": tmp_path / PAGE13.name,
    }
    for name, original in (
        ("source", SOURCE),
        ("manifest", MANIFEST),
        ("receipt", RECEIPT),
        ("bank", LIVE_BANK),
        ("page13", PAGE13),
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
            page13_path=paths["page13"],
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
        with pytest.raises(O1RelationalSearchError, match="seal"):
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


def test_historical_v26_adapter_is_untouched() -> None:
    assert _sha(V26.read_bytes()) == FROZEN_V26_SHA256


def test_native_v24_source_contract() -> None:
    source_bytes = SOURCE.read_bytes()
    source = source_bytes.decode("utf-8")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA in source
    assert sieve.PRIORITY_STATE_SCHEMA in source
    assert sieve.PRIORITY_ACTION_SCHEMA in source
    assert sieve.LIVE_BANK_SHA256 in source
    assert sieve.PRODUCTION_PAGE13_SHA256 in source
    assert sieve.BURNED_PAGE12_SHA256 in source
    assert sieve.BURNED_PAGE11_SHA256 in source
    assert sieve.BURNED_PAGE10_SHA256 in source
    assert sieve.BURNED_PAGE9_SHA256 in source
    assert r"fresh_seed_parser_used\":false" in source
    assert "truth_key" not in source
