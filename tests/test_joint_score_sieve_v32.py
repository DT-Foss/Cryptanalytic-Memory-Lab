from __future__ import annotations

import copy
import hashlib
import inspect
from pathlib import Path
from typing import Mapping, cast

import pytest

import o1_crypto_lab.joint_score_sieve_v32 as sieve
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
BUNDLE = ROOT / "research/o1c100_page18_telemetry_recovery_seed_20260721"
MANIFEST = ROOT / sieve.O1C100_MANIFEST_RELATIVE
PAGE18 = ROOT / sieve.O1C100_PAGE18_RELATIVE
RECEIPT = ROOT / sieve.O1C97_PRIORITY_RECEIPT_RELATIVE
FAILURE_RECEIPT = ROOT / sieve.O1C99_FAILURE_RECEIPT_RELATIVE
LIVE_BANK = ROOT / sieve.O1C100_LIVE_BANK_RELATIVE


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _action(
    *,
    confirmed: bool = True,
    released: bool = True,
    unobserved_release: bool = False,
) -> dict[str, object]:
    return {
        "token": 1,
        "call": 7,
        "coordinate_index": 12,
        "literal": -13,
        "bound_level": 1,
        "confirmed": confirmed,
        "released": released,
        "unobserved_release": unobserved_release,
    }


def _ownership_fixture() -> tuple[
    dict[str, object], tuple[Mapping[str, object], ...], dict[str, int]
]:
    events = [
        {
            "sequence": 1,
            "kind": "PROPOSED",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 0,
            "observed_literal": 0,
        },
        {
            "sequence": 3,
            "kind": "LEVEL_BOUND",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 1,
            "observed_literal": 0,
        },
        {
            "sequence": 5,
            "kind": "CONFIRMED",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 1,
            "observed_literal": -13,
        },
        {
            "sequence": 6,
            "kind": "RELEASED",
            "token": 1,
            "callback": 7,
            "origin": "BOUND_LOSING_CHILD",
            "row": 12,
            "literal": -13,
            "level": 0,
            "observed_literal": 0,
        },
    ]
    zero_origin = {
        "proposals": 0,
        "level_bound": 0,
        "confirmed": 0,
        "releases": 0,
    }
    origin_counts = {origin: dict(zero_origin) for origin in sieve.OWNERSHIP_ORIGINS}
    origin_counts["BOUND_LOSING_CHILD"] = {
        "proposals": 1,
        "level_bound": 1,
        "confirmed": 1,
        "releases": 1,
    }
    ownership: dict[str, object] = {
        "schema": sieve.OWNERSHIP_SCHEMA,
        "lifecycle": sieve.OWNERSHIP_LIFECYCLE,
        "event_retention": sieve.OWNERSHIP_EVENT_RETENTION,
        "eligibility_rule": sieve.OWNERSHIP_ELIGIBILITY_RULE,
        "assignment_notification_rule": sieve.OWNERSHIP_ASSIGNMENT_RULE,
        "current_level": 0,
        "proposals": 1,
        "level_bound_interventions": 1,
        "confirmed_interventions": 1,
        "releases": 1,
        "confirmed_releases": 1,
        "level_bound_unobserved_releases": 0,
        "opposite_assignments": 1,
        "foreign_assignments": 1,
        "renotifications": 0,
        "live_tokens": 0,
        "pending_tokens": 0,
        "maximum_live_tokens": 1,
        "maximum_tokens": 256,
        "maximum_recorded_lifecycle_events": 1_024,
        "event_count": 6,
        "total_event_count": 6,
        "lifecycle_event_count": 4,
        "recorded_event_count": 4,
        "recorded_lifecycle_event_count": 4,
        "omitted_event_count": 2,
        "compacted_nonclaim_count": 2,
        "events_are_lifecycle_only": True,
        "events_have_global_sequence": True,
        "proposal_activated": True,
        "level_bound_activated": True,
        "confirmed_activated": True,
        "nonclaim_kind_counts": {
            "OPPOSITE_ASSIGNMENT": 1,
            "FOREIGN_ASSIGNMENT": 1,
            "RENOTIFIED": 0,
        },
        "nonclaim_stream_digest": {
            "algorithm": "SHA-256",
            "encoding": sieve.NONCLAIM_DIGEST_ENCODING,
            "record_bytes": sieve.NONCLAIM_DIGEST_RECORD_BYTES,
            "field_layout": sieve.NONCLAIM_DIGEST_LAYOUT,
            "record_count": 2,
            "sha256": "ab" * 32,
        },
        "events": events,
        "origin_counts": origin_counts,
    }
    counts = {
        "action_count": 1,
        "level_bindings": 1,
        "confirmed_actions": 1,
        "releases": 1,
        "unobserved_releases": 0,
    }
    return ownership, (_action(),), counts


def _seed_report() -> dict[str, object]:
    return {
        "magic": sieve.PRIORITY_SEED_MAGIC,
        "schema": sieve.PRIORITY_SEED_SCHEMA,
        "payload_bytes": 24_576,
        "payload_sha256": sieve.LIVE_BANK_SHA256,
        "production_seal_enforced": True,
        "expected_production_sha256": sieve.LIVE_BANK_SHA256,
        "source_priority_state_receipt_sha256": (sieve.O1C97_PRIORITY_RECEIPT_SHA256),
        "source_priority_state_receipt_bytes": sieve.O1C97_PRIORITY_RECEIPT_BYTES,
        "source_preparation_manifest_sha256": sieve.O1C100_MANIFEST_SHA256,
        "source_preparation_manifest_bytes": sieve.O1C100_MANIFEST_BYTES,
        "source_terminal_failure_receipt_sha256": (sieve.O1C99_FAILURE_RECEIPT_SHA256),
        "source_terminal_failure_receipt_bytes": (sieve.O1C99_FAILURE_RECEIPT_BYTES),
        "seed_source": sieve.PRIORITY_SEED_SOURCE,
        "live_continuation_bank_identity": True,
        "fresh_seed_parser_used": False,
        "import_roundtrip_exact": True,
        "initial_eligible_coordinate_count": 255,
    }


def test_o1c101_production_bindings_and_native_source_are_exact() -> None:
    assert sieve.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v32-adapter-v1")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v29")
    assert "o1c101" in sieve.PRIORITY_STATE_SCHEMA
    assert "o1c101" in sieve.PRIORITY_ACTION_SCHEMA
    assert sieve.NATIVE_SOURCE_BYTES == SOURCE.stat().st_size
    assert sieve.NATIVE_SOURCE_SHA256 == _sha(SOURCE.read_bytes())
    assert sieve.PRODUCTION_PAGE18_LINEAGE_ORDINAL == 31
    assert sieve.PRODUCTION_PAGE18_BYTES == 2_680_827
    assert sieve.PRODUCTION_PAGE18_LITERAL_COUNT == 669_910
    assert sieve.PRODUCTION_PAGE18_HEADROOM == {
        "clauses": 263,
        "literals": 930_090,
        "serialized_bytes": 5_707_781,
    }
    assert sieve.O1C100_MANIFEST_BYTES == 6_865
    assert sieve.O1C99_FAILURE_RECEIPT_BYTES == 22_520


def test_priority_seed_report_requires_exact_17_field_provenance() -> None:
    report = _seed_report()
    assert len(report) == 17
    assert (
        sieve._validate_seed_report(
            report,
            seed_sha256=sieve.LIVE_BANK_SHA256,
            production_seal=True,
        )
        == report
    )
    for field in tuple(report):
        forged = dict(report)
        forged.pop(field)
        with pytest.raises(O1RelationalSearchError, match="priority seed fields"):
            sieve._validate_seed_report(
                forged,
                seed_sha256=sieve.LIVE_BANK_SHA256,
                production_seal=True,
            )


def test_v3_ownership_replays_global_sequence_gaps_and_action_linkage() -> None:
    ownership, actions, counts = _ownership_fixture()
    assert (
        sieve._validate_ownership_v3(
            ownership,
            actions=actions,
            counts=counts,
        )
        == ownership
    )
    sequences = [event["sequence"] for event in ownership["events"]]  # type: ignore[index]
    assert sequences == [1, 3, 5, 6]
    assert cast(int, ownership["total_event_count"]) == (
        cast(int, ownership["lifecycle_event_count"])
        + cast(int, ownership["compacted_nonclaim_count"])
    )


@pytest.mark.parametrize(
    ("path", "value", "pattern"),
    (
        (("events", 1, "sequence"), 1, "chronology"),
        (("events", 3, "sequence"), 7, "chronology"),
        (("events", 0, "row"), 11, "token binding"),
        (("total_event_count",), 7, "arithmetic"),
        (("nonclaim_kind_counts", "FOREIGN_ASSIGNMENT"), 2, "arithmetic"),
        (("origin_counts", "BOUND_LOSING_CHILD", "proposals"), 0, "origin totals"),
    ),
)
def test_v3_ownership_rejects_gap_counter_origin_and_linkage_tamper(
    path: tuple[object, ...], value: object, pattern: str
) -> None:
    ownership, actions, counts = _ownership_fixture()
    forged: object = copy.deepcopy(ownership)
    cursor = forged
    for part in path[:-1]:
        if isinstance(part, int):
            cursor = cursor[part]  # type: ignore[index]
        else:
            cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._validate_ownership_v3(
            forged,
            actions=actions,
            counts=counts,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("algorithm", "SHA-512"),
        ("encoding", "legacy"),
        ("record_bytes", 41),
        ("field_layout", "opaque"),
        ("record_count", 3),
        ("sha256", "g" * 64),
    ),
)
def test_v3_ownership_validates_commitment_envelope_without_hidden_recompute(
    field: str, value: object
) -> None:
    ownership, actions, counts = _ownership_fixture()
    digest = ownership["nonclaim_stream_digest"]
    assert isinstance(digest, dict)
    digest[field] = value
    with pytest.raises(O1RelationalSearchError, match="nonclaim"):
        sieve._validate_ownership_v3(
            ownership,
            actions=actions,
            counts=counts,
        )


def test_v3_zero_nonclaim_commitment_requires_empty_sha256() -> None:
    ownership, actions, counts = _ownership_fixture()
    ownership["opposite_assignments"] = 0
    ownership["foreign_assignments"] = 0
    ownership["omitted_event_count"] = 0
    ownership["compacted_nonclaim_count"] = 0
    ownership["event_count"] = 4
    ownership["total_event_count"] = 4
    ownership["nonclaim_kind_counts"] = {
        "OPPOSITE_ASSIGNMENT": 0,
        "FOREIGN_ASSIGNMENT": 0,
        "RENOTIFIED": 0,
    }
    digest = ownership["nonclaim_stream_digest"]
    assert isinstance(digest, dict)
    digest["record_count"] = 0
    digest["sha256"] = hashlib.sha256(b"").hexdigest()
    events = ownership["events"]
    assert isinstance(events, list)
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
    sieve._validate_ownership_v3(ownership, actions=actions, counts=counts)
    digest["sha256"] = "ab" * 32
    with pytest.raises(O1RelationalSearchError, match="commitment envelope"):
        sieve._validate_ownership_v3(ownership, actions=actions, counts=counts)


def test_v3_ownership_rejects_action_to_lifecycle_linkage_tamper() -> None:
    ownership, actions, counts = _ownership_fixture()
    forged_action = dict(actions[0])
    forged_action["coordinate_index"] = 11
    with pytest.raises(O1RelationalSearchError, match="action event linkage"):
        sieve._validate_ownership_v3(
            ownership,
            actions=(forged_action,),
            counts=counts,
        )


@pytest.mark.parametrize(
    ("serialized_bytes", "digest", "pattern"),
    (
        (sieve.BURNED_PAGE17_BYTES, sieve.BURNED_PAGE17_SHA256, "burned Page17"),
        (sieve.BURNED_PAGE16_BYTES, sieve.BURNED_PAGE16_SHA256, "burned Page16"),
        (sieve.BURNED_PAGE15_BYTES, sieve.BURNED_PAGE15_SHA256, "burned Page15"),
        (sieve.BURNED_PAGE14_BYTES, sieve.BURNED_PAGE14_SHA256, "burned Page14"),
        (sieve.BURNED_PAGE13_BYTES, sieve.BURNED_PAGE13_SHA256, "burned Page13"),
        (sieve.BURNED_PAGE12_BYTES, sieve.BURNED_PAGE12_SHA256, "burned Page12"),
        (sieve.BURNED_PAGE11_BYTES, sieve.BURNED_PAGE11_SHA256, "burned Page11"),
        (sieve.BURNED_PAGE10_BYTES, sieve.BURNED_PAGE10_SHA256, "burned Page10"),
        (sieve.BURNED_PAGE9_BYTES, sieve.BURNED_PAGE9_SHA256, "burned Page9"),
    ),
)
def test_page18_reader_rejects_every_burned_page_before_acceptance(
    monkeypatch: pytest.MonkeyPatch,
    serialized_bytes: int,
    digest: str,
    pattern: str,
) -> None:
    payload = b"\0" * serialized_bytes
    monkeypatch.setattr(
        sieve._v9._v8._v7._v1,
        "_read_input",
        lambda *_args, **_kwargs: (Path("/sealed"), payload, digest),
    )
    with pytest.raises(O1RelationalSearchError, match=pattern):
        sieve._read_page18("ignored")


def test_page18_reader_accepts_only_exact_fresh_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"\0" * sieve.PRODUCTION_PAGE18_BYTES
    monkeypatch.setattr(
        sieve._v9._v8._v7._v1,
        "_read_input",
        lambda *_args, **_kwargs: (
            Path("/sealed/page-18-active.bin"),
            payload,
            sieve.PRODUCTION_PAGE18_SHA256,
        ),
    )
    path, accepted = sieve._read_page18("ignored")
    assert path == Path("/sealed/page-18-active.bin")
    assert accepted is payload


def test_published_o1c100_bundle_and_both_receipts_are_exact() -> None:
    assert BUNDLE.is_dir()
    assert {path.name for path in BUNDLE.iterdir()} == sieve.O1C100_PUBLISHED_ARTIFACTS
    manifest = MANIFEST.read_bytes()
    receipt = RECEIPT.read_bytes()
    failure = FAILURE_RECEIPT.read_bytes()
    bank = LIVE_BANK.read_bytes()
    page18 = PAGE18.read_bytes()
    assert len(manifest) == sieve.O1C100_MANIFEST_BYTES
    assert _sha(manifest) == sieve.O1C100_MANIFEST_SHA256
    assert len(failure) == sieve.O1C99_FAILURE_RECEIPT_BYTES
    assert _sha(failure) == sieve.O1C99_FAILURE_RECEIPT_SHA256
    assert len(page18) == sieve.PRODUCTION_PAGE18_BYTES
    assert _sha(page18) == sieve.PRODUCTION_PAGE18_SHA256
    sieve._validate_manifest(manifest)
    sieve._validate_receipt(receipt, bank)
    sieve._validate_failure_receipt(failure)


def test_prelaunch_and_recheck_contract_cover_manifest_bank_both_receipts_and_page18() -> (
    None
):
    signature = inspect.signature(sieve._validate_prelaunch)
    assert {
        "manifest_path",
        "receipt_path",
        "failure_receipt_path",
        "bank_path",
        "page18_path",
    }.issubset(signature.parameters)
    run_signature = inspect.signature(sieve.run_joint_score_sieve)
    assert "terminal_failure_receipt_path" in run_signature.parameters
    assert "sealed_page18_path" in run_signature.parameters
    source = Path(sieve.__file__).read_text(encoding="utf-8")
    assert source.count("_execute_native(") == 1
    launch = source.index("execution = _v9._v8._v7._execute_native(")
    for marker in (
        "sealed.failure_receipt_bytes",
        "sealed.manifest_bytes",
        "sealed.receipt_bytes",
        "sealed.bank_bytes",
        "sealed.page18_bytes",
    ):
        assert source.index(marker, launch) > launch


def test_v32_uses_dedicated_v3_ownership_validator_and_unchanged_state_actions() -> (
    None
):
    source = Path(sieve.__file__).read_text(encoding="utf-8")
    assert "_v22._validate_priority_state(" in source
    assert "_v22._validate_actions(" in source
    assert "_validate_ownership_v3(" in source
    assert "_v22._validate_ownership_linkage(" not in source
    assert "_validate_continuation_transition(" in source
    assert "_v9._parse_native_payload(" in source
    assert "truth_key_path" not in source
    assert (
        "target_path" not in inspect.signature(sieve.run_joint_score_sieve).parameters
    )
