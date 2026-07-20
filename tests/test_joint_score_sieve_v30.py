from __future__ import annotations

import ast
import hashlib
import inspect
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import o1_crypto_lab.joint_score_sieve_v30 as sieve
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.o1c82_parent_centered_seed import RECORD_BYTES, RECORD_STRUCT


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
BUNDLE = ROOT / "research/o1c96_page16_transport_recovery_seed_20260720"
RECEIPT = ROOT / sieve.O1C92_PRIORITY_RECEIPT_RELATIVE
LIVE_BANK = ROOT / sieve.O1C96_LIVE_BANK_RELATIVE
MANIFEST = ROOT / sieve.O1C96_MANIFEST_RELATIVE
PAGE16 = ROOT / sieve.O1C96_PAGE16_RELATIVE
PAGE15 = ROOT / "research/o1c93_page15_causal_rollover_seed_20260720/page-15-active.bin"
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
V29 = ROOT / "src/o1_crypto_lab/joint_score_sieve_v29.py"
FROZEN_V29_SHA256 = "ea133e06209988727434e122cbe6ab531feae0f1b32636be72a77ef2bb394a0c"
CNF = (
    ROOT
    / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
    / "artifacts/cnf/full256-eight-block-apple-view-0008.cnf"
)
POTENTIAL = (
    ROOT
    / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
    / "artifacts/potential/primary-eight-block.potential"
)
GROUPING = (
    ROOT
    / "runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1"
    / "apple8-width6.grouping"
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


def test_o1c96_known_production_bindings_are_exact() -> None:
    assert sieve.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v30-adapter-v1")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v27")
    assert "o1c97" in sieve.PRIORITY_STATE_SCHEMA
    assert "o1c97" in sieve.PRIORITY_ACTION_SCHEMA
    assert sieve.NATIVE_SOURCE_BYTES == 50_154
    assert sieve.NATIVE_SOURCE_SHA256 == (
        "fa6ab51bbf8db39b57f9414dc675d5391969c2bafab30b8e1355337576ff090a"
    )
    assert sieve.PRODUCTION_PAGE16_LINEAGE_ORDINAL == 29
    assert sieve.PRODUCTION_PAGE16_BYTES == 2_831_459
    assert sieve.PRODUCTION_PAGE16_SHA256 == (
        "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5"
    )
    assert sieve.O1C96_MANIFEST_BYTES == 6_414
    assert sieve.O1C96_MANIFEST_SHA256 == (
        "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7"
    )
    assert sieve.LIVE_BANK_SHA256 == (
        "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca"
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


def test_output_counts_may_grow_but_must_replay_exact_probe_delta() -> None:
    before_payload = LIVE_BANK.read_bytes()
    before = sieve._decode_live_bank(
        before_payload,
        expected_sha256=sieve.LIVE_BANK_SHA256,
        sealed_input=True,
    )
    maximum = max(before, key=lambda record: record.count)
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


def test_o1c92_receipt_replays_and_links_exact_carried_bank() -> None:
    receipt = RECEIPT.read_bytes()
    bank = LIVE_BANK.read_bytes()
    assert len(receipt) == sieve.O1C92_PRIORITY_RECEIPT_BYTES == 52_014
    assert _sha(receipt) == sieve.O1C92_PRIORITY_RECEIPT_SHA256
    assert len(bank) == 24_576
    assert _sha(bank) == sieve.LIVE_BANK_SHA256
    sieve._validate_receipt(receipt, bank)

    forged = bytearray(bank)
    forged[0] ^= 1
    with pytest.raises(O1RelationalSearchError, match="receipt bank linkage"):
        sieve._validate_receipt(receipt, bytes(forged))


def test_published_o1c96_manifest_contract_is_exact() -> None:
    assert sieve.O1C96_MANIFEST_ARTIFACTS == frozenset(
        {
            "page-16-active.bin",
            "residency.json",
            "activation-ledger.json",
            "occurrence-ledger.json",
            "subsumption-relations.json",
            "common-signed-intersection-audit.json",
            "final-parent-centered-priority-bank.bin",
            "o1c92-priority-state-receipt.json",
            "o1c95-terminal-failure-receipt.json",
        }
    )
    assert len(sieve.O1C96_PUBLISHED_ARTIFACTS) == 10
    payload = MANIFEST.read_bytes()
    assert len(payload) == sieve.O1C96_MANIFEST_BYTES
    assert _sha(payload) == sieve.O1C96_MANIFEST_SHA256
    assert sieve._manifest_contract() == (
        sieve.O1C96_MANIFEST_SCHEMA,
        sieve.O1C96_MANIFEST_BYTES,
        sieve.O1C96_MANIFEST_SHA256,
        sieve.O1C96_MANIFEST_ARTIFACTS,
    )
    sieve._validate_manifest(payload)

    manifest = json.loads(payload)
    assert manifest["science_boundary"]["imported_clause_count"] == 0
    assert manifest["transport_recovery"]["new_chunk_count"] == 0
    assert manifest["parent"]["native_process_returncode_zero_before_adapter_validation"]
    assert manifest["page16"]["debt_completion"] == {
        "prior_never_resident_undominated_clause_count": 167,
        "admitted_as_new_debt_clause_count": 167,
        "remaining_never_resident_undominated_clause_count": 0,
        "recycled_clause_count": 32,
        "all_prior_debt_admitted": True,
    }


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("science_boundary", "imported_clause_count", 1),
        ("transport_recovery", "new_chunk_count", 1),
        ("page16", "literal_count", 707_565),
        ("parent", "native_json_discarded_before_runner_result", False),
    ),
)
def test_manifest_mutations_are_fail_closed_by_exact_seal(
    section: str, field: str, value: object
) -> None:
    manifest = json.loads(MANIFEST.read_bytes())
    manifest[section][field] = value
    with pytest.raises(O1RelationalSearchError, match="manifest seal"):
        sieve._validate_manifest(canonical_json_bytes(manifest))


def test_page16_reader_accepts_only_fresh_identity(tmp_path: Path) -> None:
    payload = PAGE16.read_bytes()
    assert len(payload) == sieve.PRODUCTION_PAGE16_BYTES
    assert _sha(payload) == sieve.PRODUCTION_PAGE16_SHA256
    resolved, accepted = sieve._read_page16(PAGE16)
    assert resolved == PAGE16.resolve()
    assert accepted == payload

    forged = bytearray(payload)
    forged[len(forged) // 2] ^= 1
    path = tmp_path / "forged-page-16-active.bin"
    path.write_bytes(forged)
    with pytest.raises(O1RelationalSearchError, match="Page16 active projection"):
        sieve._read_page16(path)


@pytest.mark.parametrize(
    ("path", "pattern"),
    (
        (PAGE15, "burned Page15"),
        (PAGE14, "burned Page14"),
        (PAGE13, "burned Page13"),
        (PAGE12, "burned Page12"),
        (PAGE11, "burned Page11"),
        (PAGE10, "burned Page10"),
        (PAGE9, "burned Page9"),
    ),
)
def test_burned_page15_through_page9_are_rejected(
    path: Path, pattern: str
) -> None:
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._read_page16(path)


def test_prelaunch_rechecks_every_sealed_input(tmp_path: Path) -> None:
    paths = {
        "source": tmp_path / SOURCE.name,
        "manifest": tmp_path / MANIFEST.name,
        "receipt": tmp_path / RECEIPT.name,
        "bank": tmp_path / LIVE_BANK.name,
        "page16": tmp_path / PAGE16.name,
    }
    for name, original in (
        ("source", SOURCE),
        ("manifest", MANIFEST),
        ("receipt", RECEIPT),
        ("bank", LIVE_BANK),
        ("page16", PAGE16),
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
            page16_path=paths["page16"],
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


def _seed_report() -> dict[str, object]:
    return {
        "magic": sieve.PRIORITY_SEED_MAGIC,
        "schema": sieve.PRIORITY_SEED_SCHEMA,
        "payload_bytes": 24_576,
        "payload_sha256": sieve.LIVE_BANK_SHA256,
        "production_seal_enforced": True,
        "expected_production_sha256": sieve.LIVE_BANK_SHA256,
        "source_priority_state_receipt_sha256": (
            sieve.O1C92_PRIORITY_RECEIPT_SHA256
        ),
        "source_priority_state_receipt_bytes": sieve.O1C92_PRIORITY_RECEIPT_BYTES,
        "import_roundtrip_exact": True,
        "initial_eligible_coordinate_count": 255,
        "seed_source": sieve.PRIORITY_SEED_SOURCE,
        "live_continuation_bank_identity": True,
        "fresh_seed_parser_used": False,
    }


def test_priority_seed_report_requires_exact_13_field_live_provenance() -> None:
    report = _seed_report()
    assert (
        sieve._validate_seed_report(
            report,
            seed_sha256=sieve.LIVE_BANK_SHA256,
            production_seal=True,
        )
        == report
    )
    assert set(report) == sieve._SEED_FIELDS
    assert len(report) == 13
    for field in (
        "source_priority_state_receipt_sha256",
        "source_priority_state_receipt_bytes",
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


def test_return_zero_schema_failure_exposes_exact_stdout_on_outward_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "return-zero-schema-fixture"
    executable.write_bytes(b"return-zero-schema-fixture")
    executable.chmod(0o700)
    stdout = '{"schema":"return-zero-schema-failure-sentinel"}\n'
    stderr = "completed-return-zero-stderr-sentinel"
    samples: tuple[dict[str, int | float], ...] = (
        {"elapsed_seconds": 0.125, "rss_bytes": 12_345_678},
    )
    observed_command: list[str] = []

    def execute(
        command: list[str],
        *,
        timeout_seconds: float,
        memory_limit_bytes: int | None,
    ) -> object:
        assert timeout_seconds == 45.0
        assert memory_limit_bytes == 536_870_912
        observed_command[:] = command
        completed = subprocess.CompletedProcess(command, 0, stdout, stderr)
        return sieve._v9._v8._v7._NativeExecution(completed, samples)

    monkeypatch.setattr(sieve._v9._v8._v7, "_execute_native", execute)
    executable_payload = executable.read_bytes()
    with pytest.raises(sieve._v9.JointScoreSieveExecutionError) as raised:
        sieve.run_joint_score_sieve(
            executable=executable,
            cnf_path=CNF,
            potential_path=POTENTIAL,
            grouping_path=GROUPING,
            vault_path=PAGE16,
            priority_seed_path=LIVE_BANK,
            vault_caps=sieve.O1C66_VAULT_CAPS,
            threshold=14.606178797892962,
            conflict_limit=128,
            expected_source_sha256=sieve.NATIVE_SOURCE_SHA256,
            expected_executable_sha256=_sha(executable_payload),
            expected_executable_bytes=len(executable_payload),
            seed=0,
            timeout_seconds=45.0,
            memory_limit_bytes=536_870_912,
            source_path=SOURCE,
            rollover_manifest_path=MANIFEST,
            priority_state_receipt_path=RECEIPT,
            sealed_page16_path=PAGE16,
        )

    error = raised.value
    assert getattr(error, "returncode") == 0
    assert getattr(error, "stdout") == stdout
    assert getattr(error, "stderr") == stderr
    assert getattr(error, "memory_samples") == samples
    assert getattr(error, "cmd") == observed_command
    assert error.failure_telemetry["returncode"] == 0
    assert error.failure_telemetry["stdout"] == stdout
    assert error.failure_telemetry["memory_samples"] == list(samples)
    assert "result fields" in str(error)


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


def test_dynamic_executable_identity_is_checked_immediately_before_one_launch() -> (
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


def test_historical_v29_adapter_is_untouched() -> None:
    assert _sha(V29.read_bytes()) == FROZEN_V29_SHA256


def test_native_v27_source_contract() -> None:
    source_bytes = SOURCE.read_bytes()
    assert len(source_bytes) == sieve.NATIVE_SOURCE_BYTES
    assert _sha(source_bytes) == sieve.NATIVE_SOURCE_SHA256
    source = source_bytes.decode("utf-8")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA in source
    assert sieve.PRIORITY_STATE_SCHEMA in source
    assert sieve.PRIORITY_ACTION_SCHEMA in source
    assert sieve.LIVE_BANK_SHA256 in source
    assert sieve.O1C96_MANIFEST_SHA256 in source
    assert sieve.PRODUCTION_PAGE16_SHA256 in source
    assert sieve.BURNED_PAGE15_SHA256 in source
    assert sieve.BURNED_PAGE14_SHA256 in source
    assert sieve.BURNED_PAGE9_SHA256 in source
    assert r"fresh_seed_parser_used\":false" in source
    assert "source_priority_state_receipt_sha256" in source
    assert "source_priority_state_receipt_bytes" in source
    assert "truth_key" not in source
