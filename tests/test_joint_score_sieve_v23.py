from __future__ import annotations

import ast
import hashlib
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import o1_crypto_lab.joint_score_sieve_v23 as sieve
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.o1c82_parent_centered_seed import RECORD_BYTES, RECORD_STRUCT


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
MANIFEST = ROOT / sieve.O1C83_MANIFEST_RELATIVE
RECEIPT = ROOT / sieve.O1C82_PRIORITY_RECEIPT_RELATIVE
LIVE_BANK = ROOT / sieve.O1C83_LIVE_BANK_RELATIVE
PAGE9 = ROOT / sieve.O1C83_PAGE9_RELATIVE
FRESH_BANK = (
    ROOT
    / "runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1"
    / "initial/parent-centered-priority-seed.bin"
)


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


def test_sealed_live_bank_exact_aggregate_and_fresh_bank_rejected() -> None:
    live = LIVE_BANK.read_bytes()
    records = sieve._decode_live_bank(
        live, expected_sha256=sieve.LIVE_BANK_SHA256, sealed_input=True
    )
    assert len(live) == 24_576
    assert len(records) == 256
    assert sum(record.count for record in records) == 49_490
    assert max(record.count for record in records) == 575
    assert sum(record.count >= 37 for record in records) == 255
    assert records[240].count == 0

    with pytest.raises(O1RelationalSearchError, match="live bank digest"):
        sieve._decode_live_bank(
            FRESH_BANK.read_bytes(),
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


def test_output_counts_may_exceed_575_but_must_replay_probe_delta() -> None:
    before_payload = LIVE_BANK.read_bytes()
    before = sieve._decode_live_bank(
        before_payload,
        expected_sha256=sieve.LIVE_BANK_SHA256,
        sealed_input=True,
    )
    maximum = max(before, key=lambda record: record.count)
    assert maximum.count == 575
    after_payload = _replace_packed_value(
        before_payload,
        variable=maximum.variable,
        index=0,
        value=maximum.count + 1,
    )
    after = sieve._decode_live_bank(
        after_payload, expected_sha256=None, sealed_input=False
    )
    assert max(record.count for record in after) == 576
    sieve._validate_continuation_transition(before, after, probe_count=1)

    with pytest.raises(O1RelationalSearchError, match="total count delta"):
        sieve._validate_continuation_transition(before, after, probe_count=2)
    decreasing = list(after)
    decreasing[0] = replace(decreasing[0], count=before[0].count - 1)
    with pytest.raises(O1RelationalSearchError, match="count monotonicity"):
        sieve._validate_continuation_transition(before, decreasing, probe_count=0)


def test_manifest_receipt_bank_and_page9_contracts_link() -> None:
    manifest = MANIFEST.read_bytes()
    receipt = RECEIPT.read_bytes()
    bank = LIVE_BANK.read_bytes()
    page9 = PAGE9.read_bytes()
    assert len(manifest) == sieve.O1C83_MANIFEST_BYTES
    assert _sha(manifest) == sieve.O1C83_MANIFEST_SHA256
    assert len(receipt) == sieve.O1C82_PRIORITY_RECEIPT_BYTES
    assert _sha(receipt) == sieve.O1C82_PRIORITY_RECEIPT_SHA256
    assert len(page9) == sieve.PRODUCTION_PAGE9_BYTES
    assert _sha(page9) == sieve.PRODUCTION_PAGE9_SHA256
    sieve._validate_manifest(manifest)
    sieve._validate_receipt(receipt, bank)


@pytest.mark.parametrize(
    "tampered_name",
    ("source", "executable", "manifest", "receipt", "bank", "page9"),
)
def test_every_prelaunch_seal_fails_before_execution(
    tmp_path: Path, tampered_name: str
) -> None:
    paths = {
        "source": tmp_path / "native.cpp",
        "executable": tmp_path / "native-bin",
        "manifest": tmp_path / "manifest.json",
        "receipt": tmp_path / "receipt.json",
        "bank": tmp_path / "bank.bin",
        "page9": tmp_path / "page9.bin",
    }
    shutil.copyfile(SOURCE, paths["source"])
    paths["executable"].write_bytes(b"sealed-unit-executable")
    shutil.copyfile(MANIFEST, paths["manifest"])
    shutil.copyfile(RECEIPT, paths["receipt"])
    shutil.copyfile(LIVE_BANK, paths["bank"])
    shutil.copyfile(PAGE9, paths["page9"])
    source_sha = _sha(paths["source"].read_bytes())
    executable_sha = _sha(paths["executable"].read_bytes())

    clean = sieve._validate_prelaunch(
        source_path=paths["source"],
        executable_path=paths["executable"],
        manifest_path=paths["manifest"],
        receipt_path=paths["receipt"],
        bank_path=paths["bank"],
        page9_path=paths["page9"],
        expected_source_sha256=source_sha,
        expected_executable_sha256=executable_sha,
    )
    assert clean.bank_bytes == LIVE_BANK.read_bytes()

    target = paths[tampered_name]
    damaged = bytearray(target.read_bytes())
    damaged[len(damaged) // 2] ^= 1
    target.write_bytes(damaged)
    with pytest.raises(O1RelationalSearchError):
        sieve._validate_prelaunch(
            source_path=paths["source"],
            executable_path=paths["executable"],
            manifest_path=paths["manifest"],
            receipt_path=paths["receipt"],
            bank_path=paths["bank"],
            page9_path=paths["page9"],
            expected_source_sha256=source_sha,
            expected_executable_sha256=executable_sha,
        )


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
    assert sieve._validate_seed_report(
        report,
        seed_sha256=sieve.LIVE_BANK_SHA256,
        production_seal=True,
    ) == report
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


def test_adapter_has_no_original_seed_parser_dependency() -> None:
    tree = ast.parse(Path(sieve.__file__).read_text(encoding="utf-8"))
    forbidden = {"parse_seed_bank", "EXPECTED_BANK_SHA256"}
    referenced = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    imported = {
        alias.name.rsplit(".", 1)[-1]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not forbidden & (referenced | imported)


def test_native_v20_source_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA in source
    assert sieve.PRIORITY_STATE_SCHEMA in source
    assert sieve.PRIORITY_ACTION_SCHEMA in source
    assert sieve.LIVE_BANK_SHA256 in source
    assert sieve.PRODUCTION_PAGE9_SHA256 in source
    assert r'fresh_seed_parser_used\":false' in source
    assert "truth_key" not in source
