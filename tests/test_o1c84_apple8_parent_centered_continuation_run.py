from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, cast

import pytest

import o1_crypto_lab.o1c84_apple8_parent_centered_continuation_run as runner
from o1_crypto_lab import joint_score_sieve_v23 as v23
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1c83_apple8_causal_rollover_prepare import (
    PreparedCausalRolloverArtifacts,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import ThresholdNoGoodClause


FAKE_PAGE9 = b"page-nine-fixture\n"
FAKE_BANK = bytes(range(64))
FAKE_NATIVE = b"fake-native-v20-executable\n"
KNOWN_CLAUSES = (
    ThresholdNoGoodClause((1,)),
    ThresholdNoGoodClause((3,)),
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _writable_tree(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)
    root.chmod(0o755)


def _all_keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            result.add(str(key))
            result.update(_all_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(_all_keys(nested))
    return result


class Fixture:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self.adapter_calls = 0
        self.compiler_calls = 0
        self.intent_seen = False
        self.fail_adapter = False
        self.mutate_after_build: Path | None = None

        monkeypatch.setattr(runner, "PAGE9_SHA256", _sha(FAKE_PAGE9))
        monkeypatch.setattr(runner, "PAGE9_SERIALIZED_BYTES", len(FAKE_PAGE9))
        monkeypatch.setattr(runner, "CONTINUATION_BANK_SHA256", _sha(FAKE_BANK))
        monkeypatch.setattr(runner, "CONTINUATION_BANK_BYTES", len(FAKE_BANK))
        monkeypatch.setattr(runner, "ATTIC_UNION_CLAUSE_COUNT", len(KNOWN_CLAUSES))
        monkeypatch.setattr(runner, "MINIMUM_DISK_FREE_BYTES", 1)
        monkeypatch.setattr(
            runner, "MAXIMUM_PERSISTENT_ARTIFACT_BYTES", 10_000_000
        )

        self.parent_capsule = root / runner.DEFAULT_PARENT_CAPSULE_RELATIVE
        self.parent_capsule.mkdir(parents=True)
        self.parent_manifest = b"fixture parent manifest\n"
        (self.parent_capsule / "artifacts.sha256").write_bytes(self.parent_manifest)
        monkeypatch.setattr(
            runner, "PARENT_CAPSULE_MANIFEST_SHA256", _sha(self.parent_manifest)
        )
        self.parent_result = root / runner.DEFAULT_PARENT_RESULT_RELATIVE
        self.parent_result.parent.mkdir(parents=True, exist_ok=True)
        self.parent_result.write_bytes(canonical_json_bytes({"fixture": "parent"}))
        monkeypatch.setattr(
            runner, "PARENT_RESULT_SHA256", _sha(self.parent_result.read_bytes())
        )

        self.receipt = canonical_json_bytes(
            {
                "schema": "o1-256-o1c82-live-parent-centered-priority-state-v1",
                "candidate_population": 255,
                "candidate_order_sha256": runner.CONTINUATION_CANDIDATE_ORDER_SHA256,
                "bank_bytes": len(FAKE_BANK),
                "bank_hex": FAKE_BANK.hex(),
                "current_bank_sha256": _sha(FAKE_BANK),
            }
        )
        self.receipt_path = root / runner.PRIORITY_RECEIPT_RELATIVE
        self.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        self.receipt_path.write_bytes(self.receipt)
        monkeypatch.setattr(
            runner, "PARENT_PRIORITY_STATE_SHA256", _sha(self.receipt)
        )
        monkeypatch.setattr(
            runner, "PARENT_PRIORITY_STATE_BYTES", len(self.receipt)
        )

        payloads = {
            runner.ACTIVE_PROJECTION_NAME: FAKE_PAGE9,
            runner.ACTIVATION_LEDGER_NAME: canonical_json_bytes({"ledger": 22}),
            runner.COMMON_CORE_AUDIT_NAME: canonical_json_bytes({"core": False}),
            runner.CONTINUATION_BANK_NAME: FAKE_BANK,
            runner.NEW_CHUNK_NAME: b"new-chunk\n",
            runner.OCCURRENCES_NAME: canonical_json_bytes({"occurrences": 807}),
            runner.RELATIONS_NAME: canonical_json_bytes({"relations": 9}),
            runner.RESIDENCY_NAME: canonical_json_bytes({"lineage": 22}),
        }
        manifest: dict[str, object] = {
            "schema": "o1-256-o1c83-page9-causal-rollover-preparation-v1",
            "attempt_id": "O1C-0083",
            "authorization": {
                "science_call_authorized": False,
                "intent_created": False,
                "page9_burned": False,
                "lineage22_burned": False,
            },
            "page9": {
                "lineage_ordinal": 22,
                "active_sha256": _sha(FAKE_PAGE9),
                "serialized_bytes": len(FAKE_PAGE9),
                "fresh_identity": True,
            },
            "attic": {"union_clause_count": len(KNOWN_CLAUSES)},
            "final_priority_bank": {
                "sha256": _sha(FAKE_BANK),
                "serialized_bytes": len(FAKE_BANK),
                "receipt_sha256": _sha(self.receipt),
                "receipt_serialized_bytes": len(self.receipt),
                "receipt_bank_hex_byte_equal": True,
                "fresh_seed_parser_compatible": False,
            },
            "artifacts": {
                name: {
                    "serialized_bytes": len(payload),
                    "sha256": _sha(payload),
                }
                for name, payload in sorted(payloads.items())
            },
        }
        manifest_payload = canonical_json_bytes(manifest)
        payloads[runner.PREPARATION_MANIFEST_NAME] = manifest_payload
        monkeypatch.setattr(
            runner, "PUBLISHED_MANIFEST_SHA256", _sha(manifest_payload)
        )
        monkeypatch.setattr(
            runner, "PUBLISHED_MANIFEST_BYTES", len(manifest_payload)
        )
        self.prepared_bundle = PreparedCausalRolloverArtifacts(
            state=cast(
                Any,
                SimpleNamespace(
                    attic=SimpleNamespace(
                        union_vault=SimpleNamespace(clauses=KNOWN_CLAUSES)
                    )
                ),
            ),
            artifacts=payloads,
            manifest=manifest,
        )
        self.published = root / runner.PUBLISHED_PREPARATION_RELATIVE
        self.published.mkdir(parents=True)
        for name, payload in payloads.items():
            (self.published / name).write_bytes(payload)

        for index, relative in enumerate(runner.SOURCE_PATHS.values()):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(f"fixture-source-{index}:{relative}\n".encode())
        self.inputs = {
            "cnf": self._file("inputs/public.cnf", b"p cnf 1 0\n"),
            "potential": self._file("inputs/public.potential", b"potential\n"),
            "grouping": self._file("inputs/public.grouping", b"grouping\n"),
            "o1c73_config": self._file(
                "inputs/o1c73-config.json", canonical_json_bytes({"fixture": 73})
            ),
        }
        toolchain = root / "toolchain"
        toolchain.mkdir()
        self.compiler = toolchain / "c++"
        self.compiler.write_bytes(b"#!/bin/sh\nexit 1\n")
        self.compiler.chmod(0o755)
        self.include = toolchain / "include"
        self.include.mkdir()
        self.library = toolchain / "libcadical.a"
        self.library.write_bytes(b"fixture-cadical-library\n")
        self.config_path = root / runner.CONFIG_RELATIVE
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_config()

    def _file(self, relative: str, payload: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def prepared(self, **kwargs: object) -> PreparedCausalRolloverArtifacts:
        assert Path(cast(str | Path, kwargs["capsule_dir"])) == self.parent_capsule
        assert (
            Path(cast(str | Path, kwargs["parent_result_path"]))
            == self.parent_result
        )
        assert set(kwargs) == {"capsule_dir", "parent_result_path"}
        return self.prepared_bundle

    def system(self, root: Path) -> dict[str, object]:
        assert root == self.root
        return {
            "system": "Darwin",
            "machine": "arm64",
            "physical_memory_bytes": 16 * 1024**3,
            "available_memory_bytes": 8 * 1024**3,
            "disk_free_bytes": 8 * 1024**3,
            "sibling_solver_pids": [],
        }

    def command(self, argv: list[str], **kwargs: object) -> SimpleNamespace:
        assert kwargs["cwd"] == self.root
        if argv[-1] == "--version":
            return SimpleNamespace(
                returncode=0, stdout=b"fixture clang 1\n", stderr=b""
            )
        self.compiler_calls += 1
        assert "-DO1_CRYPTO_LAB_O1C84_PUBLIC_FIXTURE" not in argv
        assert tuple(argv[1 : 1 + len(runner.COMPILER_FLAGS)]) == runner.COMPILER_FLAGS
        output = Path(argv[argv.index("-o") + 1])
        output.write_bytes(FAKE_NATIVE)
        if self.mutate_after_build is not None:
            self.mutate_after_build.write_bytes(b"changed-after-preflight\n")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    def native_result(
        self,
        *,
        semantic: str = runner.PROOF_MINING_SEMANTIC,
        confirmed: bool = True,
        threshold_prunes: int = 0,
        emitted: int = 0,
        active_new: int = 0,
        status: int = 0,
        emitted_literal: int = 2,
    ) -> v23.JointScoreSieveV23Result:
        actions: dict[str, object] = {
            "action_count": 1,
            "actions": [
                {
                    "semantic": semantic,
                    "confirmed": confirmed,
                    "coincident_v6_pending": False,
                }
            ],
        }
        state: dict[str, object] = {
            "bank_bytes": len(FAKE_BANK),
            "current_bank_sha256": _sha(FAKE_BANK),
            "probe_trace": {"count": 255},
        }
        priority_seed = {
            "payload_sha256": _sha(FAKE_BANK),
            "payload_bytes": len(FAKE_BANK),
            "seed_source": "sealed-live-continuation-bank",
            "live_continuation_bank_identity": True,
            "fresh_seed_parser_used": False,
        }
        vault: dict[str, object] = {
            "fully_emitted_clause_count": emitted,
            "emitted_new_clause_count": active_new,
            "fully_emitted_clauses": [
                {"classification": "new", "literals": [emitted_literal]}
                for _ in range(emitted)
            ],
        }
        base = {"pending_clause_count": 0, "threshold_prunes": threshold_prunes}
        resources = {
            "peak_rss_bytes": 64 * 1024**2,
            "wall_microseconds": 50_000,
            "cpu_microseconds": 20_000,
        }
        stats = {
            "requested_conflicts": 128,
            "solve_conflicts": 17,
            "billed_conflicts": 17,
        }
        key = b"fixture-key" if status == 10 else None
        raw: dict[str, object] = {
            "schema": v23.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "seed": 0,
            "active_vault_sha256": _sha(FAKE_PAGE9),
            "priority_state": state,
            "priority_actions": actions,
            "decision_ownership": {"schema": "fixture-ownership"},
            "base_sieve": base,
            "vault": vault,
        }
        stdout = canonical_json_bytes(raw).decode("ascii")
        return v23.JointScoreSieveV23Result(
            status=status,
            conflict_limit=128,
            threshold=runner.THRESHOLD,
            key_model=key,
            stats=cast(Any, stats),
            resources=cast(Any, resources),
            base_result=cast(Any, None),
            priority_seed=priority_seed,
            priority_state=state,
            priority_actions=actions,
            decision_ownership=cast(dict[str, object], raw["decision_ownership"]),
            next_priority_seed=FAKE_BANK,
            normalized_summary={},
            raw=raw,
            native_stdout=stdout,
            native_stdout_sha256=_sha(stdout.encode()),
            command=(),
        )

    def adapter(self, **kwargs: object) -> object:
        self.adapter_calls += 1
        executable = Path(cast(str | Path, kwargs["executable"]))
        intent = executable.parents[1] / "episodes/00/intent.json"
        assert intent.is_file()
        document = json.loads(intent.read_bytes())
        assert document["page9_burned"] is True
        assert document["lineage22_burned"] is True
        assert kwargs["seed"] == 0
        assert kwargs["conflict_limit"] == 128
        assert kwargs["public_fixture"] is False
        assert kwargs["expected_source_sha256"] == self.source_sha["native_v20"]
        assert kwargs["expected_executable_sha256"] == _sha(FAKE_NATIVE)
        assert Path(cast(str | Path, kwargs["vault_path"])).read_bytes() == FAKE_PAGE9
        assert (
            Path(cast(str | Path, kwargs["priority_seed_path"])).read_bytes()
            == FAKE_BANK
        )
        assert (
            Path(cast(str | Path, kwargs["rollover_manifest_path"])).read_bytes()
            == self.prepared_bundle.artifacts[runner.PREPARATION_MANIFEST_NAME]
        )
        assert (
            Path(cast(str | Path, kwargs["priority_state_receipt_path"])).read_bytes()
            == self.receipt
        )
        assert kwargs["sealed_page9_path"] == kwargs["vault_path"]
        self.intent_seen = True
        if self.fail_adapter:
            raise RuntimeError("fixture native process failed")
        return self.native_result()

    def write_config(self) -> None:
        self.source_sha = {
            name: _sha((self.root / relative).read_bytes())
            for name, relative in runner.SOURCE_PATHS.items()
        }
        config = {
            "schema": runner.CONFIG_SCHEMA,
            "attempt_id": runner.ATTEMPT_ID,
            "parent": {
                "capsule": runner.DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix(),
                "capsule_manifest_sha256": _sha(self.parent_manifest),
                "result": runner.DEFAULT_PARENT_RESULT_RELATIVE.as_posix(),
                "result_sha256": _sha(self.parent_result.read_bytes()),
            },
            "preparation": {
                "published_directory": runner.PUBLISHED_PREPARATION_RELATIVE.as_posix(),
                "manifest": (
                    runner.PUBLISHED_PREPARATION_RELATIVE
                    / runner.PREPARATION_MANIFEST_NAME
                ).as_posix(),
                "manifest_sha256": runner.PUBLISHED_MANIFEST_SHA256,
                "manifest_bytes": runner.PUBLISHED_MANIFEST_BYTES,
                "priority_state_receipt": runner.PRIORITY_RECEIPT_RELATIVE.as_posix(),
                "priority_state_receipt_sha256": runner.PARENT_PRIORITY_STATE_SHA256,
                "priority_state_receipt_bytes": runner.PARENT_PRIORITY_STATE_BYTES,
                "candidate_order_sha256": runner.CONTINUATION_CANDIDATE_ORDER_SHA256,
            },
            "inputs": {
                **{
                    name: path.relative_to(self.root).as_posix()
                    for name, path in self.inputs.items()
                },
                **{
                    f"{name}_sha256": _sha(path.read_bytes())
                    for name, path in self.inputs.items()
                },
            },
            "native": {
                "source": runner.SOURCE_PATHS["native_v20"],
                "source_sha256": self.source_sha["native_v20"],
                "compiler": str(self.compiler),
                "compiler_flags": list(runner.COMPILER_FLAGS),
                "cadical_include": str(self.include),
                "cadical_library": str(self.library),
                "cadical_library_sha256": _sha(self.library.read_bytes()),
                "expected_executable_sha256": _sha(FAKE_NATIVE),
                "expected_executable_bytes": len(FAKE_NATIVE),
                "adapter_schema": v23.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA,
                "result_schema": v23.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
                "page9_sha256": _sha(FAKE_PAGE9),
                "page9_bytes": len(FAKE_PAGE9),
                "continuation_bank_sha256": _sha(FAKE_BANK),
                "continuation_bank_bytes": len(FAKE_BANK),
                "candidate_order_sha256": runner.CONTINUATION_CANDIDATE_ORDER_SHA256,
            },
            "source": {
                "paths": runner.SOURCE_PATHS,
                "expected_sha256": self.source_sha,
            },
            "budgets": {
                "required_system": "Darwin",
                "required_machine": "arm64",
                "lineage_call_ordinals": [22],
                "local_episode_ordinals": [0],
                "seed": 0,
                "threshold": runner.THRESHOLD,
                "requested_conflicts": 128,
                "maximum_native_solver_calls": 1,
                "timeout_seconds": 45.0,
                "memory_limit_bytes": 536_870_912,
                "minimum_available_memory_bytes": 536_870_912,
                "minimum_disk_free_bytes": 1,
                "maximum_persistent_artifact_bytes": 10_000_000,
                "maximum_fresh_targets": 0,
                "maximum_fresh_reveal_calls": 0,
                "maximum_refits": 0,
                "maximum_mps_calls": 0,
                "maximum_gpu_calls": 0,
                "retry_authorized": False,
                "replay_authorized": False,
            },
            "next_action": "Burn Page 9 / lineage 22 once; never retry or replay.",
        }
        self.config_path.write_bytes(canonical_json_bytes(config))

    def execute(self) -> dict[str, object]:
        fixed = datetime(2026, 7, 20, 16, 0, 0, tzinfo=timezone.utc)
        return runner.run(
            self.config_path,
            root=self.root,
            prepare_fn=self.prepared,
            adapter_run=self.adapter,
            command_runner=self.command,
            system_probe=self.system,
            public_verifier=lambda key: key == b"fixture-key",
            now=lambda: fixed,
        )


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Fixture]:
    value = Fixture(tmp_path.resolve(), monkeypatch)
    yield value
    _writable_tree(tmp_path)


def test_preflight_regenerates_and_byte_compares_exact_published_bundle(
    fixture: Fixture,
) -> None:
    row = runner.preflight(
        fixture.config_path,
        root=fixture.root,
        prepare_fn=fixture.prepared,
        system_probe=fixture.system,
    )
    assert row["passed"] is True
    assert row["native_solver_calls"] == 0
    published = cast(dict[str, object], row["published_preparation"])
    prepared_rows = cast(dict[str, object], row["prepared_artifacts"])
    assert published["byte_equal_to_regeneration"] is True
    assert row["global_novelty_baseline_clause_count"] == len(KNOWN_CLAUSES)
    assert set(prepared_rows) == runner.PREPARATION_ARTIFACT_NAMES
    assert fixture.adapter_calls == fixture.compiler_calls == 0


def test_preflight_rejects_published_mutation_without_call(fixture: Fixture) -> None:
    (fixture.published / runner.OCCURRENCES_NAME).write_bytes(b"mutated\n")
    with pytest.raises(runner.O1C84RunError, match="differs from regeneration"):
        runner.preflight(
            fixture.config_path,
            root=fixture.root,
            prepare_fn=fixture.prepared,
            system_probe=fixture.system,
        )
    assert fixture.adapter_calls == fixture.compiler_calls == 0


def test_all_seals_precede_intent_then_exactly_one_terminal_call(
    fixture: Fixture,
) -> None:
    result = fixture.execute()
    assert fixture.intent_seen is True
    assert fixture.adapter_calls == fixture.compiler_calls == 1
    assert result["classification"] == runner.ACTIVATION_ONLY
    assert result["science_gain"] is False
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert episode["page9_burned"] is True
    assert episode["lineage22_burned"] is True
    capsule = fixture.root / cast(str, result["capsule"])
    initial = capsule / "initial"
    assert {path.name for path in initial.iterdir()} == runner.STAGED_INITIAL_NAMES
    assert (initial / runner.RECEIPT_NAME).read_bytes() == fixture.receipt
    assert fixture.execute() == result
    assert fixture.adapter_calls == fixture.compiler_calls == 1


def test_mutation_before_final_seal_never_burns_or_calls(fixture: Fixture) -> None:
    fixture.mutate_after_build = fixture.inputs["potential"]
    with pytest.raises(runner.O1C84RunError, match="changed before native call"):
        fixture.execute()
    capsules = list((fixture.root / "runs").glob(f"*_{runner.CAPSULE_SUFFIX}"))
    assert len(capsules) == 1
    assert not (capsules[0] / "episodes/00/intent.json").exists()
    assert fixture.adapter_calls == 0
    with pytest.raises(runner.O1C84RunError, match="pre-intent capsule"):
        fixture.execute()
    assert fixture.adapter_calls == 0


def test_failure_after_intent_is_terminal_and_never_retried(fixture: Fixture) -> None:
    fixture.fail_adapter = True
    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert episode["terminal_failure"]["phase"] == "CALL"
    assert episode["page9_burned"] is True
    assert episode["lineage22_burned"] is True
    assert episode["native_calls_consumed"] == 1
    assert fixture.execute() == result
    assert fixture.adapter_calls == 1


def test_manifest_consistent_cross_attempt_capsule_is_not_republished(
    fixture: Fixture,
) -> None:
    capsule = fixture.root / "runs" / f"fixture_{runner.CAPSULE_SUFFIX}"
    capsule.mkdir(parents=True)
    result = {
        "schema": "o1-256-wrong-result-v1",
        "attempt_id": "O1C-0083",
        "capsule": capsule.relative_to(fixture.root).as_posix(),
    }
    (capsule / "result.json").write_bytes(canonical_json_bytes(result))
    (capsule / "RUN.md").write_bytes(b"# wrong attempt\n")
    manifest, _ = runner._manifest_bytes(capsule)
    (capsule / "artifacts.sha256").write_bytes(manifest)

    with pytest.raises(runner.O1C84RunError, match="capsule result differs"):
        fixture.execute()
    assert not (fixture.root / runner.RESULT_RELATIVE).exists()
    assert fixture.adapter_calls == fixture.compiler_calls == 0


def test_authoritative_result_cannot_mask_burned_incomplete_capsule(
    fixture: Fixture,
) -> None:
    capsule = fixture.root / "runs" / f"fixture_{runner.CAPSULE_SUFFIX}"
    intent = capsule / "episodes/00/intent.json"
    intent.parent.mkdir(parents=True)
    intent.write_bytes(canonical_json_bytes({"page9_burned": True}))
    authoritative = fixture.root / runner.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True, exist_ok=True)
    authoritative.write_bytes(
        canonical_json_bytes(
            {
                "schema": runner.RESULT_SCHEMA,
                "attempt_id": runner.ATTEMPT_ID,
                "capsule": capsule.relative_to(fixture.root).as_posix(),
            }
        )
    )

    with pytest.raises(runner.O1C84RunError, match="burned incomplete capsule"):
        fixture.execute()
    assert fixture.adapter_calls == fixture.compiler_calls == 0


def test_novelty_uses_complete_o1c83_attic_union(fixture: Fixture) -> None:
    duplicate = fixture.native_result(emitted=1, active_new=1, emitted_literal=1)
    evidence = runner._validate_native_result(
        duplicate, cast(str, duplicate.native_stdout).encode()
    )
    _, science, classification, _ = runner._science_and_operation(
        evidence,
        globally_known_clauses=frozenset(
            clause.serialized for clause in KNOWN_CLAUSES
        ),
    )
    assert science["globally_novel_clauses"] == 0
    assert science["active_page9_new_clauses"] == 1
    assert classification == runner.ACTIVATION_ONLY

    novel = fixture.native_result(emitted=1, active_new=1, emitted_literal=2)
    novel_evidence = runner._validate_native_result(
        novel, cast(str, novel.native_stdout).encode()
    )
    _, novel_science, novel_classification, _ = runner._science_and_operation(
        novel_evidence,
        globally_known_clauses=frozenset(
            clause.serialized for clause in KNOWN_CLAUSES
        ),
    )
    assert novel_science["globally_novel_clauses"] == 1
    assert novel_classification == runner.SCIENCE_CLAUSE


def test_sealed_production_gate_and_no_stale_page_or_lineage_fields() -> None:
    production = Path(__file__).parents[1] / runner.CONFIG_RELATIVE
    source = (Path(__file__).parents[1] / runner.SOURCE_PATHS["runner"]).read_text()
    config = json.loads(production.read_bytes())
    assert runner._pending(config) == ()
    assert runner.load_config(production) == config
    assert "joint_score_sieve_v23" in source
    assert "prepare_o1c83_causal_rollover" in source
    assert "active_page9_new_clauses" in source
    assert "public_fixture=False" in source
    assert 'retry_authorized\": True' not in source
    assert 'replay_authorized\": True' not in source
    stale_page = "page" + "8"
    stale_lineage = "lineage" + "21"
    assert stale_page not in _all_keys(config)
    assert stale_lineage not in _all_keys(config)
    assert stale_page not in source.lower()
    assert stale_lineage not in source.lower()
    assert config["budgets"]["lineage_call_ordinals"] == [22]
    assert config["budgets"]["maximum_native_solver_calls"] == 1
    assert config["budgets"]["retry_authorized"] is False
    assert config["budgets"]["replay_authorized"] is False
