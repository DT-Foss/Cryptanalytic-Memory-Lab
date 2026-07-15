import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.artifacts import ManifestError, ReadOnlyArtifactSource
from o1_crypto_lab.isolation import IsolationPolicy, IsolationViolation


class ArtifactTests(unittest.TestCase):
    def test_verifies_before_read_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "result.json"
            artifact.write_text('{"value": 7}\n', encoding="utf-8")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            manifest = root / "manifest.sha256"
            manifest.write_text(f"{digest}  result.json\n", encoding="utf-8")
            source = ReadOnlyArtifactSource(root, manifest)
            self.assertEqual(source.read_json("result.json"), {"value": 7})
            verified = source.verify()
            self.assertTrue(verified.ok)
            self.assertEqual(verified.schema, "o1-crypto-source-verification-v1")
            self.assertEqual(
                verified.manifest_sha256,
                hashlib.sha256(manifest.read_bytes()).hexdigest(),
            )
            artifact.write_text('{"value": 9}\n', encoding="utf-8")
            with self.assertRaises(ManifestError):
                source.read_json("result.json")
            artifact.write_text('{"value": 8}\n', encoding="utf-8")
            fresh = ReadOnlyArtifactSource(root, manifest)
            report = fresh.verify()
            self.assertFalse(report.ok)
            self.assertEqual(report.mismatched, ("result.json",))
            with self.assertRaises(ManifestError):
                fresh.read_bytes("result.json")

    def test_manifest_is_pinned_at_source_construction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "member"
            artifact.write_bytes(b"one")
            digest = hashlib.sha256(b"one").hexdigest()
            manifest = root / "manifest.sha256"
            manifest.write_text(f"{digest}  member\n", encoding="utf-8")
            source = ReadOnlyArtifactSource(root, manifest)
            manifest.write_text(f"{'0' * 64}  member\n", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "changed after it was pinned"):
                source.verify()

    def test_rejects_traversal_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            digest = "0" * 64
            manifest = root / "manifest.sha256"
            manifest.write_text(f"{digest}  ../escape\n", encoding="utf-8")
            with self.assertRaises(ManifestError):
                ReadOnlyArtifactSource(root, manifest)
            manifest.write_text(
                f"{digest}  member\n{digest}  member\n", encoding="utf-8"
            )
            with self.assertRaises(ManifestError):
                ReadOnlyArtifactSource(root, manifest)


class IsolationTests(unittest.TestCase):
    def test_atomic_output_is_confined_to_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runs").mkdir()
            policy = IsolationPolicy(root)
            destination = policy.atomic_write_json("runs/test.json", {"ok": True})
            self.assertEqual(json.loads(destination.read_text()), {"ok": True})
            self.assertEqual(list((root / "runs").glob(".*.tmp")), [])
            with self.assertRaises(IsolationViolation):
                policy.atomic_write_json("outside.json", {})
            with self.assertRaises(IsolationViolation):
                policy.atomic_write_json(root / "runs-evil" / "file.json", {})
            with self.assertRaises(IsolationViolation):
                policy.atomic_write_json("runs", {})
            with self.assertRaises(ValueError):
                policy.atomic_write_json("runs/nonfinite.json", {"value": float("nan")})
            self.assertFalse((root / "runs/nonfinite.json").exists())

    def test_runs_symlink_cannot_escape_lab(self):
        with (
            tempfile.TemporaryDirectory() as lab,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(lab)
            (root / "runs").symlink_to(Path(outside), target_is_directory=True)
            policy = IsolationPolicy(root)
            with self.assertRaisesRegex(IsolationViolation, "symbolic link"):
                policy.atomic_write_json("runs/escape.json", {"bad": True})
            self.assertFalse((Path(outside) / "escape.json").exists())

    def test_output_file_symlink_cannot_escape_lab(self):
        with (
            tempfile.TemporaryDirectory() as lab,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(lab)
            (root / "runs").mkdir()
            outside_file = Path(outside) / "captured.json"
            outside_file.write_text("unchanged", encoding="utf-8")
            (root / "runs" / "linked.json").symlink_to(outside_file)
            policy = IsolationPolicy(root)
            with self.assertRaises(IsolationViolation):
                policy.atomic_write_json("runs/linked.json", {"bad": True})
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
