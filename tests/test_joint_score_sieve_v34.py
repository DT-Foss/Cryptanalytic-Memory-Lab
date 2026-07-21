from __future__ import annotations

import copy
import hashlib
import inspect
from pathlib import Path
from typing import Mapping, cast

import pytest

import o1_crypto_lab.joint_score_sieve_v34 as sieve
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / sieve.NATIVE_SOURCE_RELATIVE
BUNDLE = ROOT / sieve.O1C104_BUNDLE_RELATIVE
MANIFEST = ROOT / sieve.O1C104_MANIFEST_RELATIVE
PAGE20 = ROOT / sieve.O1C104_PAGE20_RELATIVE
RECEIPT = ROOT / sieve.O1C103_PRIORITY_RECEIPT_RELATIVE
INHERITED_RECEIPT = ROOT / sieve.INHERITED_DERIVED_RECEIPT_RELATIVE
INHERITED_CLOSURE = ROOT / sieve.INHERITED_DERIVED_CLOSURE_RELATIVE
INHERITED_OVERLAY = ROOT / sieve.INHERITED_DERIVED_OVERLAY_RELATIVE
NEW_RECEIPT = ROOT / sieve.NEW_DERIVED_RECEIPT_RELATIVE
NEW_CLOSURE = ROOT / sieve.NEW_DERIVED_CLOSURE_RELATIVE
NEW_OVERLAY = ROOT / sieve.NEW_DERIVED_OVERLAY_RELATIVE
LIVE_BANK = ROOT / sieve.O1C104_LIVE_BANK_RELATIVE


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
        "source_priority_state_receipt_sha256": (
            sieve.O1C103_PRIORITY_RECEIPT_SHA256
        ),
        "source_priority_state_receipt_bytes": sieve.O1C103_PRIORITY_RECEIPT_BYTES,
        "source_preparation_manifest_sha256": sieve.O1C104_MANIFEST_SHA256,
        "source_preparation_manifest_bytes": sieve.O1C104_MANIFEST_BYTES,
        "source_derived_resolution_receipt_sha256": (
            sieve.NEW_DERIVED_RECEIPT_SHA256
        ),
        "source_derived_resolution_receipt_bytes": (
            sieve.NEW_DERIVED_RECEIPT_BYTES
        ),
        "seed_source": sieve.PRIORITY_SEED_SOURCE,
        "live_continuation_bank_identity": True,
        "fresh_seed_parser_used": False,
        "import_roundtrip_exact": True,
        "initial_eligible_coordinate_count": 255,
    }


def test_o1c105_production_bindings_and_native_source_are_exact() -> None:
    assert sieve.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v34-adapter-v1")
    assert sieve.JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v31")
    assert "o1c105" in sieve.PRIORITY_STATE_SCHEMA
    assert "o1c105" in sieve.PRIORITY_ACTION_SCHEMA
    assert sieve.NATIVE_SOURCE_BYTES == SOURCE.stat().st_size
    assert sieve.NATIVE_SOURCE_SHA256 == _sha(SOURCE.read_bytes())
    assert sieve.PRODUCTION_PAGE20_LINEAGE_ORDINAL == 33
    assert sieve.PRODUCTION_PAGE20_BYTES == 2_762_455
    assert sieve.PRODUCTION_PAGE20_LITERAL_COUNT == 690_319
    assert sieve.PRODUCTION_PAGE20_HEADROOM == {
        "clauses": 265,
        "literals": 909_681,
        "serialized_bytes": 5_626_153,
    }
    assert sieve.PURE_EMITTED_CANDIDATE_SHA256 == (
        "1b46e9d8653c0ce7c7366a37ae927df1e301e1b2d7ecffaa056d84d86375bc7a"
    )
    assert sieve.EMITTED_ONLY_ACTIVE_PROJECTION_SHA256 == (
        "99bb42bc553102d2b1c2ae37e80634490b4f63aba5c82ff307667c768a4fd138"
    )
    assert sieve.EMITTED_ONLY_ACTIVE_PROJECTION_SHA256 != (
        sieve.PRODUCTION_PAGE20_SHA256
    )
    assert sieve.GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT == 2_692
    assert sieve.O1C104_MANIFEST_BYTES == 9_830
    assert sieve.INHERITED_DERIVED_RECEIPT_BYTES == 326_232
    assert sieve.NEW_DERIVED_RECEIPT_BYTES == 428_520


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
        (sieve.BURNED_PAGE19_BYTES, sieve.BURNED_PAGE19_SHA256, "burned Page19"),
        (sieve.BURNED_PAGE18_BYTES, sieve.BURNED_PAGE18_SHA256, "burned Page18"),
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
def test_page20_reader_rejects_every_burned_page_before_acceptance(
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
        sieve._read_page20("ignored")


def test_page20_reader_accepts_only_exact_fresh_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"\0" * sieve.PRODUCTION_PAGE20_BYTES
    monkeypatch.setattr(
        sieve._v9._v8._v7._v1,
        "_read_input",
        lambda *_args, **_kwargs: (
            Path("/sealed/page-20-active.bin"),
            payload,
            sieve.PRODUCTION_PAGE20_SHA256,
        ),
    )
    path, accepted = sieve._read_page20("ignored")
    assert path == Path("/sealed/page-20-active.bin")
    assert accepted is payload


def test_published_o1c104_bundle_and_both_namespace_triplets_are_exact() -> None:
    assert BUNDLE.is_dir()
    assert {path.name for path in BUNDLE.iterdir()} == sieve.O1C104_PUBLISHED_ARTIFACTS
    manifest = MANIFEST.read_bytes()
    receipt = RECEIPT.read_bytes()
    inherited_receipt = INHERITED_RECEIPT.read_bytes()
    inherited_closure = INHERITED_CLOSURE.read_bytes()
    inherited_overlay = INHERITED_OVERLAY.read_bytes()
    new_receipt = NEW_RECEIPT.read_bytes()
    new_closure = NEW_CLOSURE.read_bytes()
    new_overlay = NEW_OVERLAY.read_bytes()
    bank = LIVE_BANK.read_bytes()
    page20 = PAGE20.read_bytes()
    assert len(manifest) == sieve.O1C104_MANIFEST_BYTES
    assert _sha(manifest) == sieve.O1C104_MANIFEST_SHA256
    assert len(inherited_receipt) == sieve.INHERITED_DERIVED_RECEIPT_BYTES
    assert _sha(inherited_receipt) == sieve.INHERITED_DERIVED_RECEIPT_SHA256
    assert len(inherited_closure) == sieve.INHERITED_DERIVED_CLOSURE_BYTES
    assert _sha(inherited_closure) == sieve.INHERITED_DERIVED_CLOSURE_SHA256
    assert len(inherited_overlay) == sieve.INHERITED_DERIVED_OVERLAY_BYTES
    assert _sha(inherited_overlay) == sieve.INHERITED_DERIVED_OVERLAY_SHA256
    assert len(new_receipt) == sieve.NEW_DERIVED_RECEIPT_BYTES
    assert _sha(new_receipt) == sieve.NEW_DERIVED_RECEIPT_SHA256
    assert len(new_closure) == sieve.NEW_DERIVED_CLOSURE_BYTES
    assert _sha(new_closure) == sieve.NEW_DERIVED_CLOSURE_SHA256
    assert len(new_overlay) == sieve.NEW_DERIVED_OVERLAY_BYTES
    assert _sha(new_overlay) == sieve.NEW_DERIVED_OVERLAY_SHA256
    assert len(page20) == sieve.PRODUCTION_PAGE20_BYTES
    assert _sha(page20) == sieve.PRODUCTION_PAGE20_SHA256
    sieve._validate_manifest(manifest)
    sieve._validate_priority_receipt(receipt, bank)
    sieve._validate_inherited_derived_receipt(inherited_receipt)
    sieve._validate_new_derived_receipt(new_receipt)


@pytest.mark.parametrize(
    ("parameter", "artifact"),
    (
        ("inherited_derived_receipt_path", INHERITED_RECEIPT),
        ("inherited_derived_closure_path", INHERITED_CLOSURE),
        ("inherited_derived_overlay_path", INHERITED_OVERLAY),
        ("new_derived_receipt_path", NEW_RECEIPT),
        ("new_derived_closure_path", NEW_CLOSURE),
        ("new_derived_overlay_path", NEW_OVERLAY),
    ),
)
def test_prelaunch_rejects_each_namespace_artifact_tamper(
    tmp_path: Path,
    parameter: str,
    artifact: Path,
) -> None:
    executable = tmp_path / "native"
    executable.write_bytes(b"fixture-native-v31\n")
    executable.chmod(0o755)
    payload = artifact.read_bytes()
    tampered = tmp_path / artifact.name
    tampered.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])
    kwargs: dict[str, object] = {
        "source_path": SOURCE,
        "executable_path": executable,
        "manifest_path": MANIFEST,
        "priority_receipt_path": RECEIPT,
        "inherited_derived_receipt_path": INHERITED_RECEIPT,
        "inherited_derived_closure_path": INHERITED_CLOSURE,
        "inherited_derived_overlay_path": INHERITED_OVERLAY,
        "new_derived_receipt_path": NEW_RECEIPT,
        "new_derived_closure_path": NEW_CLOSURE,
        "new_derived_overlay_path": NEW_OVERLAY,
        "bank_path": LIVE_BANK,
        "page20_path": PAGE20,
        "expected_source_sha256": sieve.NATIVE_SOURCE_SHA256,
        "expected_executable_sha256": _sha(executable.read_bytes()),
        "expected_executable_bytes": executable.stat().st_size,
    }
    kwargs[parameter] = tampered
    with pytest.raises(O1RelationalSearchError, match="seal"):
        sieve._validate_prelaunch(**kwargs)  # type: ignore[arg-type]


def test_prelaunch_and_recheck_contract_cover_both_triplets_and_page20() -> None:
    signature = inspect.signature(sieve._validate_prelaunch)
    assert {
        "manifest_path",
        "priority_receipt_path",
        "inherited_derived_receipt_path",
        "inherited_derived_closure_path",
        "inherited_derived_overlay_path",
        "new_derived_receipt_path",
        "new_derived_closure_path",
        "new_derived_overlay_path",
        "bank_path",
        "page20_path",
    }.issubset(signature.parameters)
    run_signature = inspect.signature(sieve.run_joint_score_sieve)
    assert {
        "inherited_derived_resolution_receipt_path",
        "inherited_derived_resolution_closure_path",
        "inherited_derived_resolution_overlay_path",
        "new_derived_resolution_receipt_path",
        "new_derived_resolution_closure_path",
        "new_derived_resolution_overlay_path",
        "sealed_page20_path",
    }.issubset(run_signature.parameters)
    source = Path(sieve.__file__).read_text(encoding="utf-8")
    assert source.count("_execute_native(") == 1
    launch = source.index("execution = _v9._v8._v7._execute_native(")
    for marker in (
        "sealed.inherited_derived_receipt_bytes",
        "sealed.inherited_derived_closure_bytes",
        "sealed.inherited_derived_overlay_bytes",
        "sealed.new_derived_receipt_bytes",
        "sealed.new_derived_closure_bytes",
        "sealed.new_derived_overlay_bytes",
        "sealed.manifest_bytes",
        "sealed.priority_receipt_bytes",
        "sealed.bank_bytes",
        "sealed.page20_bytes",
    ):
        assert source.index(marker, launch) > launch


def test_v34_uses_dedicated_v3_ownership_validator_and_unchanged_state_actions() -> (
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
