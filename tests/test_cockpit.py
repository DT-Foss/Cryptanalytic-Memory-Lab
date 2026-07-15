import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.cockpit import CockpitFile, CockpitWriter
from o1_crypto_lab.isolation import IsolationViolation


class CockpitWriterTests(unittest.TestCase):
    def _lab(self, root: Path) -> None:
        (root / "research").mkdir()
        for selected in CockpitFile:
            path = root / selected.value
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("initial\n", encoding="utf-8")

    def test_replace_and_append_only_allow_enumerated_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._lab(root)
            writer = CockpitWriter(root)
            writer.replace(CockpitFile.STATUS, "new\n")
            writer.append(CockpitFile.ATTEMPT_LOG, "attempt\n")
            self.assertEqual((root / "STATUS.md").read_text(), "new\n")
            self.assertEqual(
                (root / "research/ATTEMPT_LOG.md").read_text(),
                "initial\nattempt\n",
            )
            with self.assertRaises(IsolationViolation):
                writer.replace("README.md", "bad")  # type: ignore[arg-type]

    def test_parent_and_destination_symlinks_are_rejected(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(temporary)
            (root / "STATUS.md").write_text("safe\n")
            (root / "research").symlink_to(Path(outside), target_is_directory=True)
            writer = CockpitWriter(root)
            with self.assertRaises(OSError):
                writer.append(CockpitFile.ATTEMPT_LOG, "bad\n")
            (root / "STATUS.md").unlink()
            captured = Path(outside) / "captured"
            captured.write_text("unchanged", encoding="utf-8")
            (root / "STATUS.md").symlink_to(captured)
            with self.assertRaises(IsolationViolation):
                writer.replace(CockpitFile.STATUS, "bad\n")
            self.assertEqual(captured.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
