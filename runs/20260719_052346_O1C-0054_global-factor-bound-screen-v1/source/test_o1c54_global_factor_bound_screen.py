from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import o1_crypto_lab.o1c54_global_factor_bound_screen as run_module
from o1_crypto_lab.criticality_pair_groups import compile_primary_pair_groups
from o1_crypto_lab.criticality_potential import CriticalityPotentialField
from o1_crypto_lab.full256_broker import public_view_from_publication, verify_reveal
from o1_crypto_lab.o1c54_global_factor_bound_screen import O1C54ScreenError
from o1_crypto_lab.proof_parent_criticality import ParentCriticalityField


ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / run_module.DEFAULT_CONFIG).read_text(encoding="utf-8"))


def _primary_pairs() -> tuple[tuple[int, int], ...]:
    source = CONFIG["source"]
    field = ParentCriticalityField.from_bytes((ROOT / source["field"]).read_bytes())
    potential = CriticalityPotentialField.from_bytes(
        (ROOT / source["primary_potential"]).read_bytes()
    )
    return compile_primary_pair_groups(field, potential).groups


def test_o1c54_identity_budgets_and_authoritative_path_are_frozen() -> None:
    assert run_module.ATTEMPT_ID == "O1C-0054"
    assert run_module.RESULT_SCHEMA == "o1-256-global-factor-bound-screen-result-v1"
    assert run_module.RESULT_RELATIVE == Path(
        "research/O1C0054_GLOBAL_FACTOR_BOUND_SCREEN_RESULT_20260719.json"
    )
    assert run_module.FULL256_BEAM_WIDTH == 256
    assert run_module.PAIR_COUNT == 128
    assert run_module.W11_CERTIFIED_LEAVES == 5
    assert run_module.W11_MAXIMUM_UNSCORED_POPS == 1024
    assert run_module.W11_MAXIMUM_FORWARD_EVALUATIONS == 256
    assert run_module.W11_MAXIMUM_LIVE_NODES == 2048
    assert run_module.W11_TIMEOUT_SECONDS == 120.0
    assert run_module.MAXIMUM_FORWARD_EVALUATIONS == 512
    assert run_module.MAXIMUM_PEAK_RSS_BYTES == 512 * 1024 * 1024
    assert run_module.MAXIMUM_NATIVE_SOLVER_CALLS == 0


def test_consumed_result_hashes_are_exact() -> None:
    o1c47 = (ROOT / run_module.O1C47_RESULT).read_bytes()
    o1c53 = (ROOT / run_module.O1C53_RESULT).read_bytes()
    reveal = (ROOT / CONFIG["source"]["reveal"]).read_bytes()
    assert hashlib.sha256(o1c47).hexdigest() == run_module.O1C47_RESULT_SHA256
    assert hashlib.sha256(o1c53).hexdigest() == run_module.O1C53_RESULT_SHA256
    assert hashlib.sha256(reveal).hexdigest() == run_module.EXPECTED_REVEAL_SHA256
    assert CONFIG["source"]["expected_sha256"]["reveal"] == (
        run_module.EXPECTED_REVEAL_SHA256
    )


def test_o1c47_boundary_requires_rank_five_and_score_provenance() -> None:
    result = json.loads((ROOT / run_module.O1C47_RESULT).read_bytes())
    summary = run_module.validate_o1c47_boundary(result)
    assert summary["primary_w12_deterministic_truth_rank"] == 5
    assert summary["primary_w12_strict_truth_rank"] == 5
    assert summary["primary_potential_sha256"] == (
        "307a0aeac84ee5efa4e6900f2105727bedbaa3a32b941102960a0257554cdf1e"
    )
    assert summary["w11_variables"] == list(run_module.EXPECTED_W11_VARIABLES)

    result["rank"]["12"]["primary"]["deterministic_rank"] = 6
    with pytest.raises(O1C54ScreenError, match="W12 boundary"):
        run_module.validate_o1c47_boundary(result)

    result = json.loads((ROOT / run_module.O1C47_RESULT).read_bytes())
    result["architecture"]["residual_variables"][:2] = result["architecture"][
        "residual_variables"
    ][1::-1]
    with pytest.raises(O1C54ScreenError, match="W11 coordinates"):
        run_module.validate_o1c47_boundary(result)


def test_o1c53_boundary_is_hash_bound_to_the_consumed_target() -> None:
    result = json.loads((ROOT / run_module.O1C53_RESULT).read_bytes())
    summary = run_module.validate_o1c53_boundary(result)
    assert summary["classification"] == "SURVIVOR_SUPPORT_NO_EXACT_W11_CLOSE"
    assert summary["native_solver_calls"] == 1
    result["call_ledger"]["native_solver_calls"] = 2
    with pytest.raises(O1C54ScreenError, match="O1C-0053 boundary"):
        run_module.validate_o1c53_boundary(result)


def test_pair_order_is_exactly_o1c48_then_ascending_completion_pairs() -> None:
    frozen = _primary_pairs()
    complete = run_module.complete_pair_order(frozen)
    assert complete[:63] == frozen
    remaining = sorted(
        set(range(1, 257)).difference({v for pair in frozen for v in pair})
    )
    assert complete[63:] == tuple(zip(remaining[::2], remaining[1::2], strict=True))
    assert len(complete) == 128
    assert {variable for pair in complete for variable in pair} == set(range(1, 257))


def test_pair_order_rejects_reordering_or_overlap() -> None:
    frozen = _primary_pairs()
    with pytest.raises(O1C54ScreenError, match="frozen O1C-0048"):
        run_module.complete_pair_order(tuple(reversed(frozen)))
    broken = list(frozen)
    broken[-1] = (broken[-1][0], frozen[0][0])
    with pytest.raises(O1C54ScreenError, match="frozen O1C-0048"):
        run_module.complete_pair_order(broken)


def test_classifications_are_distinct_and_full256_has_precedence() -> None:
    assert (
        run_module.classify_result(
            full256_public_recovery=True,
            w11_public_recovery=False,
            w11_top5_complete=False,
        )
        == run_module.FULL256_RECOVERY_CLASSIFICATION
    )
    assert (
        run_module.classify_result(
            full256_public_recovery=True,
            w11_public_recovery=True,
            w11_top5_complete=True,
        )
        == run_module.FULL256_RECOVERY_CLASSIFICATION
    )
    assert (
        run_module.classify_result(
            full256_public_recovery=False,
            w11_public_recovery=True,
            w11_top5_complete=True,
        )
        == run_module.W11_TOP5_CLASSIFICATION
    )
    assert (
        run_module.classify_result(
            full256_public_recovery=False,
            w11_public_recovery=False,
            w11_top5_complete=False,
        )
        == run_module.W11_BOUND_FAILURE_CLASSIFICATION
    )
    assert (
        run_module.classify_result(
            full256_public_recovery=False,
            w11_public_recovery=True,
            w11_top5_complete=False,
        )
        == run_module.W11_INCOMPLETE_RECOVERY_CLASSIFICATION
    )


def test_post_full256_gate_refuses_early_reveal_reads(tmp_path: Path) -> None:
    path = tmp_path / "reveal.json"
    payload = b"{}\n"
    path.write_bytes(payload)
    gate = run_module._PostFull256Gate()
    with pytest.raises(O1C54ScreenError, match="before Full256"):
        gate.read_json(path, hashlib.sha256(payload).hexdigest(), "reveal")
    gate.seal("a" * 64)
    assert gate.read_json(path, hashlib.sha256(payload).hexdigest(), "reveal") == {}
    assert gate.describe() == {
        "full256_executed_before_post_reveal_reads": True,
        "full256_execution_receipt_sha256": "a" * 64,
        "post_full256_reads": 1,
    }


def test_public_input_preparation_never_reads_reveal_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reveal_path = (ROOT / CONFIG["source"]["reveal"]).resolve()
    original = Path.read_bytes
    reads: list[Path] = []

    def guarded_read(path: Path) -> bytes:
        resolved = path.resolve()
        reads.append(resolved)
        if resolved == reveal_path:
            raise AssertionError("reveal bytes read during public preparation")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    monkeypatch.setattr(run_module, "_git_commit", lambda _: "1" * 40)
    monkeypatch.setattr(run_module, "_commit_bound_bytes", lambda *args: None)
    prepared = run_module._prepare_public_inputs(ROOT / run_module.DEFAULT_CONFIG)
    assert prepared.public.digest() == run_module.EXPECTED_PUBLIC_VIEW_SHA256
    assert reveal_path not in reads


def test_post_reveal_diagnostic_records_first_lost_pair_and_hamming() -> None:
    pairs = tuple((2 * index + 1, 2 * index + 2) for index in range(128))
    truth = bytes(range(32))
    truth_integer = run_module._key_integer(truth)
    retained: list[tuple[int, ...]] = []
    assigned = 0
    for stage, pair in enumerate(pairs, 1):
        assigned |= 1 << (pair[0] - 1)
        assigned |= 1 << (pair[1] - 1)
        truth_prefix = truth_integer & assigned
        retained.append((truth_prefix if stage < 7 else truth_prefix ^ 1,))
    candidates = (truth_integer ^ 1, truth_integer ^ 3)
    diagnostic = run_module.post_reveal_beam_diagnostics(
        retained_masks_by_stage=retained,
        pair_order=pairs,
        final_candidates=candidates,
        truth_key=truth,
    )
    assert diagnostic["truth_prefix_survived_every_stage"] is False
    assert diagnostic["first_lost_stage"] == 7
    assert diagnostic["first_lost_pair"] == [13, 14]
    assert diagnostic["final_beam_truth_present"] is False
    assert diagnostic["final_beam_top_hamming"] == 1
    assert diagnostic["final_beam_minimum_hamming"] == 1


def test_full256_and_w11_work_ledgers_enforce_every_cap() -> None:
    full = run_module._PublicFull256Outcome(
        final_candidates=tuple(range(256)),
        retained_masks_by_stage=(
            tuple(range(4)),
            tuple(range(16)),
            tuple(range(64)),
            *(tuple(range(256)) for _ in range(125)),
        ),
        public_match_indices=(),
        core={
            "beam_width": 256,
            "pair_count": 128,
            "stage_count": 128,
            "forward_evaluations": 256,
            "public_verifications": 256,
            "parent_expansions": 31829,
            "child_bound_evaluations": 127316,
            "maximum_retained_nodes": 256,
        },
    )
    assert (
        run_module._validate_public_full256_outcome(full)["forward_evaluations"] == 256
    )
    bad_full = run_module._PublicFull256Outcome(
        final_candidates=full.final_candidates,
        retained_masks_by_stage=full.retained_masks_by_stage,
        public_match_indices=(),
        core={**full.core, "forward_evaluations": 257},
    )
    with pytest.raises(O1C54ScreenError, match="Full256 core work"):
        run_module._validate_public_full256_outcome(bad_full)

    w11 = run_module._W11Outcome(
        certified_candidates=(0, 1, 2, 3, 4),
        completed_top5=True,
        public_match_indices=(),
        core={
            "residual_variables": list(run_module.EXPECTED_W11_VARIABLES),
            "target_leaves": 5,
            "certified_leaves": 5,
            "completed": True,
            "unscored_pops": 1024,
            "forward_evaluations": 256,
            "public_verifications": 256,
            "maximum_live_nodes": 2048,
            "elapsed_seconds": 120.0,
        },
    )
    assert run_module._validate_w11_outcome(w11)["unscored_pops"] == 1024
    bad_w11 = run_module._W11Outcome(
        certified_candidates=w11.certified_candidates,
        completed_top5=True,
        public_match_indices=(),
        core={**w11.core, "maximum_live_nodes": 2049},
    )
    with pytest.raises(O1C54ScreenError, match="W11 core work"):
        run_module._validate_w11_outcome(bad_w11)


@pytest.mark.parametrize(
    ("full_recovers", "expected_classification"),
    (
        (False, run_module.W11_BOUND_FAILURE_CLASSIFICATION),
        (True, run_module.FULL256_RECOVERY_CLASSIFICATION),
    ),
)
def test_run_is_structurally_full256_first_and_w11_never_controls_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    full_recovers: bool,
    expected_classification: str,
) -> None:
    source = CONFIG["source"]
    publication = json.loads((ROOT / source["publication"]).read_text(encoding="utf-8"))
    public = public_view_from_publication(publication)
    reveal = verify_reveal(
        json.loads((ROOT / source["reveal"]).read_text(encoding="utf-8"))
    )
    truth = bytes.fromhex(reveal["commitment_preimage"]["key_hex"])
    pairs = tuple((2 * index + 1, 2 * index + 2) for index in range(128))
    events: list[str] = []
    public_inputs = run_module._PublicInputs(
        root=tmp_path,
        public=public,
        publication_sha256="a" * 64,
        primary_potential_payload=b"potential",
        primary_potential_sha256=run_module.EXPECTED_PRIMARY_POTENTIAL_SHA256,
        semantic_map_path=tmp_path / "semantic.json",
        pair_order=pairs,
        source_commit="1" * 40,
        source_sha256={"core": "b" * 64, "runner": "c" * 64},
        reveal_path=tmp_path / "reveal.json",
        reveal_sha256="d" * 64,
        o1c47_path=tmp_path / "o1c47.json",
    )

    def prepare(_: str | Path) -> run_module._PublicInputs:
        events.append("prepare-public")
        return public_inputs

    def full256(**_: object) -> run_module._PublicFull256Outcome:
        events.append("full256")
        candidates = list(range(256))
        if full_recovers:
            candidates[0] = run_module._key_integer(truth)
        return run_module._PublicFull256Outcome(
            final_candidates=tuple(candidates),
            retained_masks_by_stage=(
                tuple(range(4)),
                tuple(range(16)),
                tuple(range(64)),
                *(tuple(range(256)) for _ in range(125)),
            ),
            public_match_indices=((0,) if full_recovers else ()),
            core={
                "beam_width": 256,
                "pair_count": 128,
                "stage_count": 128,
                "forward_evaluations": 256,
                "public_verifications": 256,
                "parent_expansions": 31829,
                "child_bound_evaluations": 127316,
                "maximum_retained_nodes": 256,
            },
        )

    def read_post(
        _: run_module._PublicInputs, gate: run_module._PostFull256Gate
    ) -> run_module._PostRevealInputs:
        assert gate.describe()["full256_executed_before_post_reveal_reads"] is True
        events.append("reveal")
        return run_module._PostRevealInputs(
            truth_key=truth,
            reveal=reveal,
            o1c47_boundary={"primary_w12_deterministic_truth_rank": 5},
            o1c53_boundary={"classification": "closed"},
        )

    def w11(**_: object) -> run_module._W11Outcome:
        events.append("w11-failure")
        return run_module._W11Outcome(
            certified_candidates=(0, 1, 2, 3, 4),
            completed_top5=True,
            public_match_indices=(),
            core={
                "residual_variables": list(run_module.EXPECTED_W11_VARIABLES),
                "target_leaves": 5,
                "certified_leaves": 5,
                "completed": True,
                "unscored_pops": 5,
                "forward_evaluations": 5,
                "public_verifications": 5,
                "maximum_live_nodes": 9,
                "elapsed_seconds": 0.01,
            },
        )

    def atomic(_: Path, value: object) -> bytes:
        events.append("atomic-write")
        return json.dumps(value).encode("utf-8")

    monkeypatch.setattr(run_module, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(run_module, "_prepare_public_inputs", prepare)
    monkeypatch.setattr(run_module, "_execute_public_full256", full256)
    monkeypatch.setattr(run_module, "_read_post_reveal_inputs", read_post)
    monkeypatch.setattr(run_module, "_execute_w11", w11)
    monkeypatch.setattr(run_module, "_atomic_json", atomic)
    monkeypatch.setattr(run_module, "_peak_rss_bytes", lambda: 1)
    result = run_module.run()
    assert events == [
        "prepare-public",
        "full256",
        "reveal",
        "w11-failure",
        "atomic-write",
    ]
    assert result["boundary"]["attacker_valid_full256_executed_first"] is True
    assert result["boundary"]["w11_authorized_or_suppressed_full256"] is False
    assert result["call_ledger"]["full256_calls"] == 1
    assert result["call_ledger"]["post_reveal_w11_calls"] == 1
    assert result["classification"] == expected_classification


def test_output_path_refuses_wrong_or_existing_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(run_module, "lab_root", lambda: tmp_path)
    with pytest.raises(O1C54ScreenError, match="authoritative result path"):
        run_module.run(output_path=tmp_path / "wrong.json")
    authoritative = tmp_path / run_module.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True, exist_ok=True)
    authoritative.write_text("occupied\n", encoding="utf-8")
    try:
        with pytest.raises(O1C54ScreenError, match="already exists"):
            run_module.run()
    finally:
        authoritative.unlink()
