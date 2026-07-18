from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.o1c22_postresult_composer import (
    decision_policy,
    next_operator_graph,
)
from o1_crypto_lab.o1c22_postresult_composer_run import (
    O1C22PostResultComposerRunError,
    _load_bound_o1c22_source,
    load_o1c22_postresult_composer_run_config,
)
from o1_crypto_lab.o1c23_selection_authority import (
    O1C23SelectionAuthorityError,
    load_producer_authentic_o1c22_source,
    load_trusted_manager_verified_o1c22_source,
    preflight_o1c23_selection_authority,
    verify_o1c22_producer_heldout_freeze,
    verify_o1c23_decision_graph,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c22_postresult_composer_v1.json"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_test_support(filename: str, module_name: str) -> ModuleType:
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        module_name, ROOT / "tests" / filename
    )
    if spec is None or spec.loader is None:  # pragma: no cover - static path.
        raise AssertionError(f"cannot load test support: {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _rehash(document: dict[str, object], digest_field: str) -> dict[str, object]:
    unsigned = dict(document)
    unsigned.pop(digest_field, None)
    return {
        **unsigned,
        digest_field: _sha(canonical_json_bytes(unsigned)),
    }


class SemanticSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.support = _load_test_support(
            "test_o1c22_postresult_composer.py",
            "_o1c23_semantic_test_support",
        )

    def _base_decisions(self) -> tuple[dict[str, object], dict[str, object]]:
        passing = self.support._compose(self.support._result())
        no_signal = self.support._compose(
            self.support._result(
                classification="NO_REAL_PACKET_SIGNAL",
                raw=(-0.2, -0.1, -0.2, -0.1),
                normalized=(-0.3, -0.2, -0.1, -0.2),
                int8=(-0.2, -0.1, -0.3, -0.4),
            )
        )
        return passing, no_signal

    def test_every_registered_operator_is_accepted_and_deeply_immutable(self) -> None:
        passing, no_signal = self._base_decisions()
        templates = decision_policy()["templates"]
        seen: set[str] = set()
        for rule_key, raw_template in templates.items():
            with self.subTest(rule=rule_key):
                template = dict(raw_template)
                base = no_signal if template["uses_a539_a541_transfer"] else passing
                decision = json.loads(json.dumps(base))
                reason = decision["reason_metrics"]
                operator_unsigned = {
                    **template,
                    "source_result_sha256": decision["source"]["result_sha256"],
                    "policy_sha256": decision["policy_sha256"],
                    "reason": reason,
                }
                fingerprint = _sha(canonical_json_bytes(operator_unsigned))
                operator = {
                    **operator_unsigned,
                    "operator_fingerprint": fingerprint,
                    "decision_token": f"o1c22d-{fingerprint[:24]}",
                }
                decision["operator"] = operator
                decision["o1o"]["decision_token"] = operator["decision_token"]
                decision["o1o"]["expected_fragment_key"] = operator["fragment_key"]
                prospective = (
                    operator["target_consumption"] == "ONE_NEWLY_BROKERED_TARGET"
                )
                decision["fresh_target_proposed"] = prospective
                unsigned = dict(decision)
                unsigned.pop("decision_sha256", None)
                decision["decision_sha256"] = _sha(canonical_json_bytes(unsigned))
                graph = next_operator_graph(
                    decision,
                    causal_sha256="1" * 64,
                    fragment_sha256="2" * 64,
                    native_generated_sha256="3" * 64,
                )
                receipt = verify_o1c23_decision_graph(decision, graph)
                self.assertEqual(receipt.operator_id, operator["operator_id"])
                self.assertFalse(receipt.describe()["scientific_decision_authority"])
                self.assertFalse(receipt.describe()["attempt_reservation_authorized"])
                with self.assertRaises(TypeError):
                    receipt.operator["operator_id"] = "tampered"  # type: ignore[index]
                with self.assertRaises(TypeError):
                    receipt.operator["reason"]["tampered"] = True  # type: ignore[index]
                seen.add(receipt.operator_id)
        self.assertEqual(
            seen,
            {str(template["operator_id"]) for template in templates.values()},
        )

    def test_graph_recomposition_rejects_semantic_tampering(self) -> None:
        passing, _ = self._base_decisions()
        graph = next_operator_graph(
            passing,
            causal_sha256="a" * 64,
            fragment_sha256="b" * 64,
            native_generated_sha256="c" * 64,
        )
        graph["resources"]["sibling_writes"] = 1
        with self.assertRaisesRegex(
            O1C23SelectionAuthorityError,
            "operator graph differs",
        ):
            verify_o1c23_decision_graph(passing, graph)


class _PendingManager:
    def __init__(self, root: Path) -> None:
        self.lab_root = root

    def finalized_attempt(self, _attempt_id: str) -> None:
        return None


class MissingSourcePreflightTests(unittest.TestCase):
    def test_missing_o1c23_returns_before_config_load_or_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = _PendingManager(root)
            with patch(
                "o1_crypto_lab.o1c23_selection_authority."
                "load_o1c22_postresult_composer_run_config"
            ) as config_loader:
                result = preflight_o1c23_selection_authority(
                    root,
                    manager=manager,  # type: ignore[arg-type]
                )
            config_loader.assert_not_called()
            self.assertFalse(result.ready)
            self.assertEqual(result.report["status"], "prerequisite-pending")
            self.assertFalse(result.report["attempt_reservation_authorized"])
            with self.assertRaises(TypeError):
                result.report["status"] = "ready"  # type: ignore[index]


class _O1C22Manager:
    def __init__(self, root: Path, finalized: object) -> None:
        self.lab_root = root
        self.finalized = finalized

    def finalized_attempt(self, attempt_id: str) -> object | None:
        return self.finalized if attempt_id == "O1C-0022" else None

    def verify(self, _path: Path) -> object:
        return self.finalized.verification


class ProducerAuthenticCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not (ROOT.parent / "O1-O/forge/core").is_dir():
            raise unittest.SkipTest("formal sibling O1-O source is unavailable")
        cls.support = _load_test_support(
            "test_o1c22_postresult_composer_run.py",
            "_o1c23_producer_test_support",
        )
        cls.config = load_o1c22_postresult_composer_run_config(CONFIG, root=ROOT)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.finalized = cls.support._write_synthetic_exact_capsule(
            Path(cls.temporary.name) / "producer-authentic-o1c22",
            cls.config,
        )
        cls._add_producer_entropy_field(cls.finalized.path)
        cls.manager = _O1C22Manager(ROOT, cls.finalized)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    @staticmethod
    def _add_producer_entropy_field(capsule: Path) -> None:
        index_path = capsule / "artifacts/artifact_index.json"
        index = json.loads(index_path.read_bytes())
        entries = index["artifacts"]
        for fold_index in range(4):
            relative = f"folds/build-{fold_index:04d}/heldout/prediction_freeze.json"
            path = capsule / "artifacts" / relative
            document = json.loads(path.read_bytes())
            document["scientific_entropy_calls"] = 0
            document = _rehash(document, "freeze_sha256")
            payload = canonical_json_bytes(document)
            path.write_bytes(payload)
            entries[relative]["sha256"] = _sha(payload)
            entries[relative]["bytes"] = len(payload)
        indexed_bytes = sum(entry["bytes"] for entry in entries.values())
        index["indexed_artifact_bytes"] = indexed_bytes
        index_payload = canonical_json_bytes(index)
        index_path.write_bytes(index_payload)
        metrics_path = capsule / "metrics.json"
        outer_metrics = json.loads(metrics_path.read_bytes())
        outer_metrics["values"]["persistent_artifact_bytes"] = indexed_bytes + len(
            index_payload
        )
        metrics_path.write_bytes(canonical_json_bytes(outer_metrics))

    def _heldout(self, fold_index: int = 0) -> dict[str, object]:
        path = self.finalized.path / (
            f"artifacts/folds/build-{fold_index:04d}/heldout/prediction_freeze.json"
        )
        return json.loads(path.read_bytes())

    def test_real_producer_shape_rejected_by_frozen_but_accepted_by_successor(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            O1C22PostResultComposerRunError,
            "held-out freeze 0 differs",
        ):
            _load_bound_o1c22_source(self.config, self.finalized)

        source = load_producer_authentic_o1c22_source(
            self.config,
            self.manager,  # type: ignore[arg-type]
            self.finalized,
        )
        self.assertEqual(source.finalized.path, self.finalized.path)
        self.assertEqual(
            source.finalized.manifest_sha256,
            self.finalized.manifest_sha256,
        )
        self.assertEqual(
            source.artifact_index_sha256,
            _sha((self.finalized.path / "artifacts/artifact_index.json").read_bytes()),
        )
        original_pass_bytes = (
            len((self.finalized.path / "config.json").read_bytes())
            + len((self.finalized.path / "metrics.json").read_bytes())
            + len((self.finalized.path / "artifacts/artifact_index.json").read_bytes())
            + json.loads(
                (self.finalized.path / "artifacts/artifact_index.json").read_bytes()
            )["indexed_artifact_bytes"]
        )
        self.assertGreater(source.source_artifact_bytes_read, original_pass_bytes)
        self.assertLessEqual(
            source.source_artifact_bytes_read,
            self.config.budgets.maximum_source_artifact_bytes_read,
        )

    def test_producer_field_is_exact_zero_not_optional_or_extensible(self) -> None:
        authentic = self._heldout()
        self.assertEqual(
            verify_o1c22_producer_heldout_freeze(authentic, fold_index=0),
            authentic,
        )
        variants: list[tuple[str, dict[str, object]]] = []
        omitted = dict(authentic)
        omitted.pop("scientific_entropy_calls")
        variants.append(("omitted", _rehash(omitted, "freeze_sha256")))
        nonzero = dict(authentic)
        nonzero["scientific_entropy_calls"] = 1
        variants.append(("nonzero", _rehash(nonzero, "freeze_sha256")))
        extra = dict(authentic)
        extra["unregistered_field"] = 0
        variants.append(("extra", _rehash(extra, "freeze_sha256")))
        for name, document in variants:
            with (
                self.subTest(name=name),
                self.assertRaises(O1C23SelectionAuthorityError),
            ):
                verify_o1c22_producer_heldout_freeze(document, fold_index=0)

    def test_trusted_projection_never_opens_real_label_payload(self) -> None:
        label_path = (self.finalized.path / "artifacts/labels.bitpack").resolve()
        original_read = Path.read_bytes

        def guarded_read(path: Path) -> bytes:
            if path.resolve() == label_path:
                raise AssertionError("trusted compatibility pass opened real labels")
            return original_read(path)

        with patch.object(Path, "read_bytes", guarded_read):
            source = load_trusted_manager_verified_o1c22_source(
                self.config, self.finalized
            )
        self.assertEqual(source.finalized.path, self.finalized.path)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
