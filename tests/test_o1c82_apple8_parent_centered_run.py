from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator, cast

import pytest

import o1_crypto_lab.o1c82_apple8_parent_centered_run as runner
from o1_crypto_lab import joint_score_sieve_v22 as v22
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.o1c82_apple8_parent_centered_prepare import (
    PreparedParentCenteredArtifacts,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import ThresholdNoGoodClause


FAKE_PAGE8 = b"page-eight-fixture\n"
FAKE_SEED = bytes(range(64))
FAKE_SEED_MANIFEST = canonical_json_bytes({"fixture": "seed-manifest"})
FAKE_NATIVE = b"fake-native-v19-executable\n"


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


class Fixture:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self.adapter_calls = 0
        self.compiler_calls = 0
        self.intent_seen = False
        self.fail_adapter = False
        self.mutate_after_build: Path | None = None
        monkeypatch.setattr(runner, "PAGE8_SHA256", _sha(FAKE_PAGE8))
        monkeypatch.setattr(runner, "PAGE8_SERIALIZED_BYTES", len(FAKE_PAGE8))
        monkeypatch.setattr(runner, "EXPECTED_BANK_SHA256", _sha(FAKE_SEED))
        monkeypatch.setattr(runner, "BANK_BYTES", len(FAKE_SEED))
        monkeypatch.setattr(runner, "SEED_MANIFEST_SHA256", _sha(FAKE_SEED_MANIFEST))
        monkeypatch.setattr(runner, "MINIMUM_DISK_FREE_BYTES", 1)
        monkeypatch.setattr(runner, "MAXIMUM_PERSISTENT_ARTIFACT_BYTES", 10_000_000)

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
        self.seed_manifest = root / runner.DEFAULT_SEED_MANIFEST_RELATIVE
        self.seed_manifest.parent.mkdir(parents=True, exist_ok=True)
        self.seed_manifest.write_bytes(FAKE_SEED_MANIFEST)

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

    def prepared(self, **kwargs: object) -> PreparedParentCenteredArtifacts:
        assert Path(cast(str | Path, kwargs["capsule_dir"])) == self.parent_capsule
        assert (
            Path(cast(str | Path, kwargs["parent_result_path"])) == self.parent_result
        )
        assert (
            Path(cast(str | Path, kwargs["seed_manifest_path"])) == self.seed_manifest
        )
        artifacts = {
            runner.ACTIVE_PROJECTION_NAME: FAKE_PAGE8,
            runner.ACTIVATION_LEDGER_NAME: canonical_json_bytes({"ledger": 21}),
            runner.EMPTY_ROLLOVER_NAME: b"rollover\n",
            runner.RESIDENCY_NAME: canonical_json_bytes({"lineage": 21}),
            runner.SEED_BANK_NAME: FAKE_SEED,
            runner.SEED_MANIFEST_NAME: FAKE_SEED_MANIFEST,
        }
        manifest: dict[str, object] = {
            "authorization": {
                "science_call_authorized": False,
                "intent_created": False,
                "page8_burned": False,
                "lineage21_burned": False,
            },
            "page8": {
                "lineage_ordinal": 21,
                "active_sha256": _sha(FAKE_PAGE8),
                "fresh_identity": True,
            },
            "seed": {"bank_sha256": _sha(FAKE_SEED), "bank_bytes": len(FAKE_SEED)},
            "artifacts": {
                name: {"serialized_bytes": len(payload), "sha256": _sha(payload)}
                for name, payload in sorted(artifacts.items())
            },
        }
        artifacts[runner.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(manifest)
        state = SimpleNamespace(
            attic=SimpleNamespace(
                union_vault=SimpleNamespace(clauses=(ThresholdNoGoodClause((1,)),))
            )
        )
        return PreparedParentCenteredArtifacts(
            state=cast(Any, state), artifacts=artifacts, manifest=manifest
        )

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
        assert "-DO1_CRYPTO_LAB_O1C82_PUBLIC_FIXTURE" not in argv
        assert tuple(argv[1:7]) == runner.COMPILER_FLAGS
        output = Path(argv[argv.index("-o") + 1])
        output.write_bytes(FAKE_NATIVE)
        if self.mutate_after_build is not None:
            self.mutate_after_build.write_bytes(b"changed-after-preflight\n")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    def native_result(
        self,
        *,
        semantic: str = v22.PROOF_MINING_SEMANTIC,
        confirmed: bool = True,
        threshold_prunes: int = 0,
        emitted: int = 0,
        novel: int = 0,
        status: int = 0,
        emitted_literal: int = 2,
    ) -> v22.JointScoreSieveV22Result:
        action = {
            "semantic": semantic,
            "confirmed": confirmed,
            "coincident_v6_pending": False,
        }
        actions: dict[str, object] = {"action_count": 1, "actions": [action]}
        state: dict[str, object] = {
            "bank_bytes": len(FAKE_SEED),
            "current_bank_sha256": _sha(FAKE_SEED),
            "probe_trace": {"count": 255},
        }
        priority_seed = {
            "payload_sha256": _sha(FAKE_SEED),
            "payload_bytes": len(FAKE_SEED),
        }
        vault: dict[str, object] = {
            "fully_emitted_clause_count": emitted,
            "emitted_new_clause_count": novel,
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
            "schema": v22.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "seed": 0,
            "active_vault_sha256": _sha(FAKE_PAGE8),
            "priority_state": state,
            "priority_actions": actions,
            "decision_ownership": {"schema": "fixture-ownership"},
            "base_sieve": base,
            "vault": vault,
        }
        stdout = canonical_json_bytes(raw).decode("ascii")
        return v22.JointScoreSieveV22Result(
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
            next_priority_seed=FAKE_SEED,
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
        assert document["page8_burned"] is True
        assert document["lineage21_burned"] is True
        assert kwargs["seed"] == 0
        assert kwargs["conflict_limit"] == 128
        assert kwargs["memory_limit_bytes"] == 536_870_912
        assert kwargs["public_fixture"] is False
        self.intent_seen = True
        if self.fail_adapter:
            raise RuntimeError("fixture native process failed")
        return self.native_result()

    def write_config(self) -> None:
        sources = {
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
                "seed_manifest": runner.DEFAULT_SEED_MANIFEST_RELATIVE.as_posix(),
                "seed_manifest_sha256": _sha(FAKE_SEED_MANIFEST),
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
                "source": runner.SOURCE_PATHS["native_v19"],
                "source_sha256": sources["native_v19"],
                "compiler": str(self.compiler),
                "compiler_flags": list(runner.COMPILER_FLAGS),
                "cadical_include": str(self.include),
                "cadical_library": str(self.library),
                "cadical_library_sha256": _sha(self.library.read_bytes()),
                "expected_executable_sha256": _sha(FAKE_NATIVE),
                "expected_executable_bytes": len(FAKE_NATIVE),
                "adapter_schema": v22.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA,
                "result_schema": v22.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
                "page8_sha256": _sha(FAKE_PAGE8),
                "page8_bytes": len(FAKE_PAGE8),
                "priority_seed_sha256": _sha(FAKE_SEED),
                "priority_seed_bytes": len(FAKE_SEED),
            },
            "source": {
                "paths": runner.SOURCE_PATHS,
                "expected_sha256": sources,
            },
            "budgets": {
                "required_system": "Darwin",
                "required_machine": "arm64",
                "lineage_call_ordinals": [21],
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
            "next_action": "Burn Page 8 / lineage 21 once; never retry or replay.",
        }
        self.config_path.write_bytes(canonical_json_bytes(config))

    def execute(self) -> dict[str, object]:
        fixed = datetime(2026, 7, 20, 15, 0, 0, tzinfo=timezone.utc)
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


def test_preflight_is_zero_call_and_rejects_sha_or_noncanonical_config(
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
    assert fixture.adapter_calls == 0
    assert fixture.compiler_calls == 0

    payload = fixture.config_path.read_bytes()
    document = json.loads(payload)
    fixture.config_path.write_bytes(json.dumps(document).encode())
    with pytest.raises(runner.O1C82RunError, match="canonical JSON"):
        runner.preflight(
            fixture.config_path,
            root=fixture.root,
            prepare_fn=fixture.prepared,
            system_probe=fixture.system,
        )


def test_burn_precedes_one_call_failure_first_is_not_science_and_bank_roundtrips(
    fixture: Fixture,
) -> None:
    result = fixture.execute()
    assert fixture.intent_seen is True
    assert fixture.adapter_calls == 1
    assert fixture.compiler_calls == 1
    assert result["classification"] == runner.ACTIVATION_ONLY
    assert result["operational_activation"] is True
    assert result["science_gain"] is False
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert episode["native_calls_consumed"] == 1
    assert episode["requested_conflicts"] == 128
    assert episode["science"]["failure_first_action_alone_is_science_gain"] is False
    capsule = fixture.root / cast(str, result["capsule"])
    assert (capsule / "episodes/00" / runner.FINAL_BANK_NAME).read_bytes() == FAKE_SEED
    manifest = (capsule / "artifacts.sha256").read_text()
    assert runner.FINAL_BANK_NAME in manifest
    assert "native-stdout.json" in manifest
    assert (fixture.root / runner.RESULT_RELATIVE).read_bytes() == (
        capsule / "result.json"
    ).read_bytes()

    assert fixture.execute() == result
    assert fixture.adapter_calls == 1
    assert fixture.compiler_calls == 1


def test_native_failure_after_burn_is_terminal_and_never_retried(
    fixture: Fixture,
) -> None:
    fixture.fail_adapter = True
    result = fixture.execute()
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert result["science_gain"] is False
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert episode["completed"] is False
    assert episode["native_call_issued"] is True
    assert episode["native_calls_consumed"] == 1
    assert episode["requested_conflicts"] == 128
    assert episode["terminal_failure"]["phase"] == "CALL"
    assert episode["page8_burned"] is True
    assert fixture.execute() == result
    assert fixture.adapter_calls == 1


def test_call_window_mutation_burns_without_issuing_native_call(
    fixture: Fixture,
) -> None:
    fixture.mutate_after_build = fixture.inputs["potential"]
    result = fixture.execute()
    episode = cast(list[dict[str, Any]], result["episodes"])[0]
    assert result["classification"] == runner.OPERATIONAL_TERMINAL
    assert episode["terminal_failure"]["phase"] == "PRE_CALL"
    assert episode["native_calls_consumed"] == 0
    assert episode["requested_conflicts"] == 0
    assert episode["page8_burned"] is True
    assert fixture.adapter_calls == 0


def test_verifier_and_global_union_are_established_before_capsule_creation(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def rejected_verifier(**_: object) -> Callable[[bytes], bool]:
        raise runner.O1C82RunError("fixture verifier rejected")

    monkeypatch.setattr(runner, "_public_verifier", rejected_verifier)
    with pytest.raises(runner.O1C82RunError, match="verifier rejected"):
        runner.run(
            fixture.config_path,
            root=fixture.root,
            prepare_fn=fixture.prepared,
            adapter_run=fixture.adapter,
            command_runner=fixture.command,
            system_probe=fixture.system,
        )
    runs = fixture.root / "runs"
    assert not list(runs.glob(f"*_{runner.CAPSULE_SUFFIX}"))
    assert fixture.compiler_calls == 0
    assert fixture.adapter_calls == 0


def test_science_classification_requires_concrete_certified_evidence(
    fixture: Fixture,
) -> None:
    proof = runner._validate_native_result(
        fixture.native_result(),
        cast(str, fixture.native_result().native_stdout).encode(),
    )
    _, science, classification, _ = runner._science_and_operation(proof)
    assert science["science_gain"] is False
    assert classification == runner.ACTIVATION_ONLY

    result = fixture.native_result(
        semantic=v22.CERTIFIED_CROSSING_SEMANTIC,
        confirmed=True,
        threshold_prunes=1,
        emitted=1,
        novel=1,
    )
    evidence = runner._validate_native_result(
        result, cast(str, result.native_stdout).encode()
    )
    _, science, classification, _ = runner._science_and_operation(
        evidence,
        globally_known_clauses=frozenset({ThresholdNoGoodClause((1,)).serialized}),
    )
    assert science["science_gain"] is True
    assert science["actual_certified_prunes"] == 1
    assert classification == runner.SCIENCE_PRUNE

    duplicate = fixture.native_result(emitted=1, novel=1, emitted_literal=1)
    duplicate_evidence = runner._validate_native_result(
        duplicate, cast(str, duplicate.native_stdout).encode()
    )
    _, duplicate_science, duplicate_classification, _ = runner._science_and_operation(
        duplicate_evidence,
        globally_known_clauses=frozenset({ThresholdNoGoodClause((1,)).serialized}),
    )
    assert duplicate_science["globally_novel_clauses"] == 0
    assert duplicate_classification == runner.ACTIVATION_ONLY

    sat = fixture.native_result(status=10)
    sat_evidence = runner._validate_native_result(
        sat, cast(str, sat.native_stdout).encode()
    )
    with pytest.raises(runner.O1C82RunError, match="public ChaCha verification"):
        runner._science_and_operation(sat_evidence, public_model_verified=False)
    _, sat_science, sat_classification, _ = runner._science_and_operation(
        sat_evidence, public_model_verified=True
    )
    assert sat_science["science_gain"] is True
    assert sat_classification == runner.SCIENCE_MODEL


def test_contract_forbids_replay_reveal_target_truth_and_accelerators() -> None:
    source = (Path(__file__).parents[1] / runner.SOURCE_PATHS["runner"]).read_text()
    assert "prepare_o1c82_parent_centered" in source
    assert "joint_score_sieve_v22" in source
    assert "memory_limit_bytes=MEMORY_LIMIT_BYTES" in source
    assert '"public_fixture": False' not in source
    assert "public_fixture=False" in source
    assert 'retry_authorized": True' not in source
    assert 'replay_authorized": True' not in source
    assert runner.MEMORY_LIMIT_BYTES == 512 * 1024**2
    assert runner.REQUESTED_CONFLICTS == 128
    assert runner.THRESHOLD == 14.606178797892962
