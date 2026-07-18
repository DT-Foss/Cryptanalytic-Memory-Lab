from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from o1_crypto_lab.o1c19_causal_vault_bridge import (
    FrozenMedianAbsQuantizer as LegacyQuantizer,
)
from o1_crypto_lab.o1c19_causal_vault_bridge import (
    PacketDeltaExtraction as LegacyExtraction,
)
from o1_crypto_lab.o1c19_causal_vault_bridge import PacketDeltaGroup as LegacyGroup
from o1_crypto_lab.o1c19_causal_vault_bridge import (
    active_coordinate_sequence_sha256 as legacy_active_sha256,
)
from o1_crypto_lab.o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
HORIZONS = (64, 65, 96)
WORK = (128, 2, 62)


class O1C22PacketCodecCompatibilityTests(unittest.TestCase):
    def test_lightweight_wire_abi_is_byte_exact_with_pinned_producer(self) -> None:
        coordinates = (0, 17, 255)
        legacy_active = legacy_active_sha256(coordinates)
        lightweight_active = active_coordinate_sequence_sha256(coordinates)
        self.assertEqual(lightweight_active, legacy_active)

        legacy_groups = tuple(
            LegacyGroup(
                source_stream_sha256="1" * 64,
                action_pool_sha256="2" * 64,
                reader_state_sha256="3" * 64,
                active_coordinates_sha256=legacy_active,
                pair_sha256=f"{coordinate:064x}",
                coordinate=coordinate,
                horizons=HORIZONS,
                incremental_deltas=(
                    coordinate / 8.0,
                    -(coordinate + 1) / 16.0,
                    (coordinate - 7) / 32.0,
                ),
                incremental_work_units=WORK,
                group_salt=28,
            )
            for coordinate in coordinates
        )
        lightweight_groups = tuple(
            PacketDeltaGroup(
                source_stream_sha256=group.source_stream_sha256,
                action_pool_sha256=group.action_pool_sha256,
                reader_state_sha256=group.reader_state_sha256,
                active_coordinates_sha256=group.active_coordinates_sha256,
                pair_sha256=group.pair_sha256,
                coordinate=group.coordinate,
                horizons=group.horizons,
                incremental_deltas=group.incremental_deltas,
                incremental_work_units=group.incremental_work_units,
                group_salt=group.group_salt,
            )
            for group in legacy_groups
        )
        for legacy, lightweight in zip(legacy_groups, lightweight_groups):
            self.assertEqual(lightweight.to_bytes(), legacy.to_bytes())
            self.assertEqual(lightweight.group_id, legacy.group_id)
            self.assertEqual(lightweight.group_sha256, legacy.group_sha256)
            self.assertEqual(
                PacketDeltaGroup.from_bytes(legacy.to_bytes()).to_bytes(),
                legacy.to_bytes(),
            )
            self.assertEqual(
                LegacyGroup.from_bytes(lightweight.to_bytes()).to_bytes(),
                lightweight.to_bytes(),
            )

        legacy_quantizer = LegacyQuantizer.fit_public_replays(legacy_groups)
        lightweight_quantizer = FrozenMedianAbsQuantizer.fit_public_replays(
            lightweight_groups
        )
        self.assertEqual(lightweight_quantizer.to_bytes(), legacy_quantizer.to_bytes())
        self.assertEqual(lightweight_quantizer.sha256, legacy_quantizer.sha256)
        self.assertEqual(
            LegacyQuantizer.from_bytes(lightweight_quantizer.to_bytes()).to_bytes(),
            lightweight_quantizer.to_bytes(),
        )

        shared = {
            "source_stream_sha256": "1" * 64,
            "action_pool_sha256": "2" * 64,
            "active_coordinates": coordinates,
            "ordered_horizons": HORIZONS,
            "reader_state_sha256": "3" * 64,
            "reader_state_bytes": 96,
            "slow_state_sha256": "4" * 64,
            "slow_state_bytes": 32,
            "final_fast_state_sha256": "5" * 64,
            "final_fast_state_bytes": 512,
            "physical_work_units": len(coordinates) * sum(WORK),
            "observed_slots": len(coordinates) * len(HORIZONS),
        }
        legacy_extraction = LegacyExtraction(groups=legacy_groups, **shared)
        lightweight_extraction = PacketDeltaExtraction(
            groups=lightweight_groups, **shared
        )
        self.assertEqual(lightweight_extraction.to_bytes(), legacy_extraction.to_bytes())
        self.assertEqual(
            lightweight_extraction.public_packet_ledger_sha256,
            legacy_extraction.public_packet_ledger_sha256,
        )
        self.assertEqual(
            PacketDeltaExtraction.from_bytes(legacy_extraction.to_bytes()).to_bytes(),
            legacy_extraction.to_bytes(),
        )

    def test_formal_runner_import_does_not_load_torch_or_legacy_bridge(self) -> None:
        source = ROOT / "src"
        script = (
            "import sys;"
            f"sys.path.insert(0,{str(source)!r});"
            "import o1_crypto_lab.o1c22_polyphase_bridge_run;"
            "assert 'torch' not in sys.modules;"
            "assert 'o1_crypto_lab.o1c19_causal_vault_bridge' not in sys.modules"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
