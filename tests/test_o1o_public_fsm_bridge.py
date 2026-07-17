from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

import o1_crypto_lab.o1o_public_fsm_bridge as bridge_module
from o1_crypto_lab.causal_evidence_stream import OutcomePublicFSMState
from o1_crypto_lab.o1o_public_fsm_bridge import (
    BRIDGE_INTENTS_FILENAME,
    CAUSAL_HEADER_BYTES,
    CAUSAL_MAGIC,
    CAUSAL_VERSION,
    COEFFICIENT_TABLE_BYTES,
    O1OPublicFSMBridgeError,
    PUBLIC_FSM_FRAGMENT_FILENAME,
    PUBLIC_FSM_FRAGMENT_KEY,
    PUBLIC_FSM_INTENT,
    PUBLIC_FSM_RECEIPT_SCHEMA,
    PUBLIC_FSM_STATE_BYTES,
    PublicFSMGroupEvent,
    decode_public_fsm_bridge,
    encode_public_fsm_bridge,
    encode_public_fsm_fragment_document,
    encode_public_fsm_group_stream,
    generate_public_fsm_wrapper,
    initial_public_fsm_state,
    public_fsm_fragment_document,
    public_fsm_replay_cli,
    replay_public_fsm_group,
    replay_public_fsm_request,
    replay_public_fsm_stream,
    run_public_fsm_replay,
)

_MASK64 = (1 << 64) - 1
_CONFIG = SimpleNamespace(n_bits=256, regime_count=4)


def _table() -> np.ndarray:
    regime = np.arange(4, dtype=np.int16)[:, None, None] * 8
    family = np.arange(8, dtype=np.int16)[None, :, None] * 2
    quality = np.arange(2, dtype=np.int16)[None, None, :]
    return (regime + family + quality + 1).astype(np.int8)


def _fixture_event(
    group_id: int, marker_symbol: int, shift: int
) -> PublicFSMGroupEvent:
    coordinates = np.roll(np.arange(256, dtype=np.int64), shift)
    families = coordinates % 8
    qualities = (coordinates // 8) % 2
    votes = np.where((coordinates + group_id) % 3 == 0, -1, 1)
    # Keep coordinate zero positive so the delayed-marker assertion is simple.
    votes[np.flatnonzero(coordinates == 0)] = 1
    return PublicFSMGroupEvent(
        group_id=group_id,
        coordinates=coordinates.tolist(),
        families=families.tolist(),
        qualities=qualities.tolist(),
        evidence_votes=votes.tolist(),
        marker_symbol=marker_symbol,
    )


def _native_transition(
    state: OutcomePublicFSMState,
    table: np.ndarray,
    event: PublicFSMGroupEvent,
) -> None:
    """The native O1C-0021 transition, isolated from its Torch reader."""

    if state.last_group_id != event.group_id:
        for coordinate, family, quality, vote in zip(
            event.coordinates,
            event.families,
            event.qualities,
            event.evidence_votes,
        ):
            coefficient = int(table[state.previous_symbol, family, quality])
            state.add(coordinate, coefficient * vote)
        state.previous_symbol = event.marker_symbol
    state.last_group_id = event.group_id


class O1OCausalCodecTests(unittest.TestCase):
    def test_native_binary_format_parity_and_roundtrip(self) -> None:
        table = _table()
        payload = encode_public_fsm_bridge(table)
        self.assertEqual(payload[:6], CAUSAL_MAGIC)
        self.assertEqual(
            int.from_bytes(payload[6:CAUSAL_HEADER_BYTES], "big"), CAUSAL_VERSION
        )

        # Independent decode exactly as O1-O's compile/load path does it.
        graph = bridge_module._unpack_messagepack(
            zlib.decompress(payload[CAUSAL_HEADER_BYTES:])
        )
        self.assertEqual(len(graph["triplets"]), 1)
        self.assertEqual(
            graph["triplets"][0],
            {
                "trigger": "compose 256 bit causal evidence public fsm",
                "mechanism": "pipeline",
                "outcome": "outcome_table_public_fsm",
                "confidence": 1.0,
            },
        )
        bridge_metadata = graph["metadata"]["bridge"]
        self.assertEqual(bridge_metadata["coefficient_table_shape"], [4, 8, 2])
        self.assertEqual(
            len(bridge_metadata["coefficient_table_i8"]), COEFFICIENT_TABLE_BYTES
        )
        self.assertEqual(
            bridge_metadata["native_selection_fixture"], BRIDGE_INTENTS_FILENAME
        )
        self.assertEqual(
            bridge_metadata["native_selection_test"],
            "optional-disposable-copy-only",
        )

        digest = hashlib.sha256(payload).hexdigest()
        decoded = decode_public_fsm_bridge(payload, expected_sha256=digest)
        self.assertEqual(decoded.causal_sha256, digest)
        np.testing.assert_array_equal(decoded.coefficient_table, table)
        copied = decoded.coefficient_table
        copied.fill(0)
        np.testing.assert_array_equal(decoded.coefficient_table, table)

    def test_forced_minimal_messagepack_fallback_is_native_byte_identical(self) -> None:
        table = _table()
        native_payload = encode_public_fsm_bridge(table)
        with patch.object(bridge_module, "msgpack", None):
            fallback_payload = encode_public_fsm_bridge(table)
            fallback_decoded = decode_public_fsm_bridge(fallback_payload)

        self.assertEqual(fallback_payload, native_payload)
        np.testing.assert_array_equal(fallback_decoded.coefficient_table, table)
        graph = bridge_module._unpack_messagepack(
            zlib.decompress(fallback_payload[CAUSAL_HEADER_BYTES:])
        )
        self.assertEqual(graph["triplets"][0]["outcome"], PUBLIC_FSM_FRAGMENT_KEY)

        # The fallback decoder also accepts bytes emitted by native msgpack.
        with patch.object(bridge_module, "msgpack", None):
            np.testing.assert_array_equal(
                decode_public_fsm_bridge(native_payload).coefficient_table,
                table,
            )

    def test_header_compression_schema_table_and_capsule_tampering_rejected(
        self,
    ) -> None:
        payload = encode_public_fsm_bridge(_table())
        digest = hashlib.sha256(payload).hexdigest()

        cases = []
        wrong_magic = bytearray(payload)
        wrong_magic[0] ^= 1
        cases.append(bytes(wrong_magic))
        cases.append(payload[:6] + struct.pack(">H", 2) + payload[8:])
        corrupted = bytearray(payload)
        corrupted[-1] ^= 1
        cases.append(bytes(corrupted))
        cases.append(payload + zlib.compress(b"trailing-stream"))
        for candidate in cases:
            with self.subTest(candidate=hashlib.sha256(candidate).hexdigest()[:8]):
                with self.assertRaises(O1OPublicFSMBridgeError):
                    decode_public_fsm_bridge(candidate)

        graph = bridge_module._unpack_messagepack(zlib.decompress(payload[8:]))
        bridge_metadata = graph["metadata"]["bridge"]
        table_bytes = bytearray(bridge_metadata["coefficient_table_i8"])
        table_bytes[0] ^= 1
        bridge_metadata["coefficient_table_i8"] = bytes(table_bytes)
        semantic_tamper = (
            b"CAUSAL"
            + struct.pack(">H", 1)
            + zlib.compress(bridge_module._pack_messagepack(graph), level=9)
        )
        with self.assertRaisesRegex(
            O1OPublicFSMBridgeError, "coefficient digest differs"
        ):
            decode_public_fsm_bridge(semantic_tamper)

        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "capsule digest differs"):
            decode_public_fsm_bridge(payload, expected_sha256="0" * 64)
        self.assertEqual(
            decode_public_fsm_bridge(payload, expected_sha256=digest).causal_sha256,
            digest,
        )


class O1OFragmentPipelineTests(unittest.TestCase):
    def test_fragment_document_has_standard_schema_and_canonical_bytes(self) -> None:
        document = public_fsm_fragment_document()
        self.assertEqual(set(document), {PUBLIC_FSM_FRAGMENT_KEY})
        fragment = document[PUBLIC_FSM_FRAGMENT_KEY]
        self.assertEqual(set(fragment), {"code", "description", "imports"})
        self.assertIsInstance(fragment["code"], str)
        self.assertEqual(
            fragment["imports"],
            ["o1_crypto_lab.o1o_public_fsm_bridge"],
        )
        compile(str(fragment["code"]), "generated_public_fsm.py", "exec")

        encoded = encode_public_fsm_fragment_document()
        self.assertEqual(json.loads(encoded), document)
        self.assertEqual(
            encoded,
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii"),
        )
        fragment["imports"].append("mutated")  # type: ignore[union-attr]
        self.assertEqual(
            public_fsm_fragment_document()[PUBLIC_FSM_FRAGMENT_KEY]["imports"],
            ["o1_crypto_lab.o1o_public_fsm_bridge"],
        )

    def test_generated_wrapper_invokes_local_replay_and_emits_exact_receipt(
        self,
    ) -> None:
        payload = encode_public_fsm_bridge(_table())
        events = (
            _fixture_event(group_id=501, marker_symbol=2, shift=3),
            _fixture_event(group_id=501, marker_symbol=2, shift=3),
            _fixture_event(group_id=502, marker_symbol=1, shift=17),
        )
        stream = encode_public_fsm_group_stream(events)
        source = generate_public_fsm_wrapper(payload, intent=PUBLIC_FSM_INTENT)
        namespace: dict[str, object] = {"__name__": "generated_fixture"}
        exec(compile(source, "generated_public_fsm.py", "exec"), namespace)
        generated_replay = namespace["replay_o1o_public_fsm"]
        self.assertTrue(callable(generated_replay))
        actual = generated_replay(payload, stream)  # type: ignore[operator]
        expected = replay_public_fsm_request(payload, stream)
        self.assertEqual(actual, expected)

        document = json.loads(actual)
        self.assertEqual(document["schema"], PUBLIC_FSM_RECEIPT_SCHEMA)
        self.assertEqual(document["fragment_key"], PUBLIC_FSM_FRAGMENT_KEY)
        self.assertEqual(document["group_count"], 3)
        self.assertEqual(document["accepted_group_count"], 2)
        self.assertEqual(document["duplicate_group_count"], 1)
        expected_state = replay_public_fsm_stream(
            decode_public_fsm_bridge(payload), events
        )
        self.assertEqual(bytes.fromhex(document["final_state_hex"]), expected_state)
        self.assertEqual(
            actual,
            json.dumps(
                document, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("ascii"),
        )

        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "no bridge triplet"):
            generate_public_fsm_wrapper(payload, intent="a different operation")
        noncanonical = stream.replace(b'{"coordinates"', b'{ "coordinates"', 1)
        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "not canonical"):
            replay_public_fsm_request(payload, noncanonical)

    def test_read_only_cli_accepts_paths_stdin_and_optional_273_byte_state(
        self,
    ) -> None:
        payload = encode_public_fsm_bridge(_table())
        bridge = decode_public_fsm_bridge(payload)
        first = _fixture_event(group_id=601, marker_symbol=3, shift=5)
        initial_state = replay_public_fsm_group(
            bridge, initial_public_fsm_state(), first
        )
        groups = encode_public_fsm_group_stream(
            (_fixture_event(group_id=602, marker_symbol=1, shift=19),)
        )
        expected = replay_public_fsm_request(
            payload, groups, initial_state=initial_state
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path = root / BRIDGE_INTENTS_FILENAME
            groups_path = root / "groups.jsonl"
            graph_path.write_bytes(payload)
            groups_path.write_bytes(groups)
            before = {path.name: path.read_bytes() for path in root.iterdir()}

            output = io.BytesIO()
            code = public_fsm_replay_cli(
                [
                    "--graph",
                    str(graph_path),
                    "--groups",
                    str(groups_path),
                    "--state-hex",
                    initial_state.hex(),
                ],
                output_stream=output,
            )
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue(), expected + b"\n")
            self.assertEqual(
                {path.name: path.read_bytes() for path in root.iterdir()}, before
            )

            stdin_output = io.BytesIO()
            self.assertEqual(
                public_fsm_replay_cli(
                    [
                        "--graph",
                        str(graph_path),
                        "--groups",
                        "-",
                        "--state-hex",
                        initial_state.hex(),
                    ],
                    input_stream=io.BytesIO(groups),
                    output_stream=stdin_output,
                ),
                0,
            )
            self.assertEqual(stdin_output.getvalue(), expected + b"\n")

        result = run_public_fsm_replay(payload, groups, initial_state=initial_state)
        self.assertEqual(
            result.final_state, bytes.fromhex(json.loads(expected)["final_state_hex"])
        )

    def test_optional_native_o1o_loader_and_assembler_from_environment(self) -> None:
        configured = os.environ.get("O1O_FORGE_ROOT")
        if not configured:
            self.skipTest("set O1O_FORGE_ROOT to run native O1-O fixture integration")
        forge_root = Path(configured).resolve()
        if (forge_root / "forge" / "core").is_dir():
            forge_root = forge_root / "forge"
        if not (forge_root / "core").is_dir():
            self.fail("O1O_FORGE_ROOT must name the repository or its forge directory")

        child = r"""
import hashlib
import json
import sys
from pathlib import Path

forge_root = Path(sys.argv[1])
sys.path.insert(0, str(forge_root))
from core.code_assembler import CodeAssembler
from core.knowledge_engine import KnowledgeEngine

knowledge = KnowledgeEngine(Path(sys.argv[2]))
intent = {
    "raw": sys.argv[4],
    "entities": [],
    "params": {},
    "mode": "BUILD",
    "confidence": 1.0,
    "requires_output": False,
}
paths = knowledge.infer(intent, top_k=1)
if not paths:
    raise RuntimeError("native O1-O did not select the bridge triplet")
assembler = CodeAssembler(Path(sys.argv[3]), knowledge)
generated = assembler.assemble(paths[0], intent)
compile(generated, "native_generated_public_fsm.py", "exec")
print(json.dumps({
    "fragment_loaded": "outcome_table_public_fsm" in assembler.fragments,
    "generated_sha256": hashlib.sha256(generated.encode()).hexdigest(),
    "has_wrapper": "replay_o1o_public_fsm" in generated,
    "selected": paths[0][0]["triplet"]["outcome"],
    "used": assembler.last_used_fragments,
}, sort_keys=True))
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge_dir = root / "knowledge"
            fragments_dir = root / "fragments"
            knowledge_dir.mkdir()
            fragments_dir.mkdir()
            (knowledge_dir / BRIDGE_INTENTS_FILENAME).write_bytes(
                encode_public_fsm_bridge(_table())
            )
            (fragments_dir / PUBLIC_FSM_FRAGMENT_FILENAME).write_bytes(
                encode_public_fsm_fragment_document()
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    child,
                    str(forge_root),
                    str(knowledge_dir),
                    str(fragments_dir),
                    PUBLIC_FSM_INTENT,
                ],
                cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        native = json.loads(completed.stdout.splitlines()[-1])
        self.assertTrue(native["fragment_loaded"])
        self.assertTrue(native["has_wrapper"])
        self.assertEqual(native["selected"], PUBLIC_FSM_FRAGMENT_KEY)
        self.assertIn(PUBLIC_FSM_FRAGMENT_KEY, native["used"])


class O1OPublicFSMReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.table = _table()
        self.bridge = decode_public_fsm_bridge(encode_public_fsm_bridge(self.table))

    def test_273_byte_replay_matches_native_duplicate_and_marker_transition(
        self,
    ) -> None:
        first = _fixture_event(group_id=101, marker_symbol=3, shift=11)
        second = _fixture_event(group_id=102, marker_symbol=1, shift=29)
        events = (first, first, second)

        bridge_state = initial_public_fsm_state()
        self.assertEqual(len(bridge_state), PUBLIC_FSM_STATE_BYTES)
        native_state = OutcomePublicFSMState.initial(_CONFIG)

        bridge_state = replay_public_fsm_group(self.bridge, bridge_state, first)
        _native_transition(native_state, self.table, first)
        self.assertEqual(bridge_state, native_state.to_bytes(_CONFIG))
        # Initial regime zero is used before marker 3 is committed.
        self.assertEqual(int(np.frombuffer(bridge_state[:256], dtype=np.int8)[0]), 1)

        before_duplicate = bridge_state
        bridge_state = replay_public_fsm_group(self.bridge, bridge_state, first)
        _native_transition(native_state, self.table, first)
        self.assertIs(bridge_state, before_duplicate)
        self.assertEqual(bridge_state, native_state.to_bytes(_CONFIG))

        bridge_state = replay_public_fsm_group(self.bridge, bridge_state, second)
        _native_transition(native_state, self.table, second)
        self.assertEqual(bridge_state, native_state.to_bytes(_CONFIG))
        # The second group observes the previously committed marker 3:
        # table[0,0,0] + table[3,0,0] = 1 + 25.
        self.assertEqual(int(np.frombuffer(bridge_state[:256], dtype=np.int8)[0]), 26)
        previous_symbol, last_group_id, accepted_updates = struct.unpack(
            "<BQQ", bridge_state[256:]
        )
        self.assertEqual((previous_symbol, last_group_id), (1, 102))
        self.assertEqual(accepted_updates, 512)
        self.assertEqual(replay_public_fsm_stream(self.bridge, events), bridge_state)

    def test_validation_is_atomic_and_saturation_matches_native(self) -> None:
        event = _fixture_event(group_id=301, marker_symbol=2, shift=7)
        saturated = bytes([127]) * 256 + struct.pack("<BQQ", 0, _MASK64, 0)
        result = replay_public_fsm_group(self.bridge, saturated, event)
        native = OutcomePublicFSMState.from_bytes(saturated, config=_CONFIG)
        _native_transition(native, self.table, event)
        self.assertEqual(result, native.to_bytes(_CONFIG))
        self.assertTrue(bool((np.frombuffer(result[:256], dtype=np.int8) <= 127).all()))
        self.assertFalse(
            bool((np.frombuffer(result[:256], dtype=np.int8) == -128).any())
        )

        malformed_duplicate = PublicFSMGroupEvent(
            group_id=301,
            coordinates=event.coordinates[:-1],
            families=event.families,
            qualities=event.qualities,
            evidence_votes=event.evidence_votes,
            marker_symbol=2,
        )
        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "width differs"):
            replay_public_fsm_group(self.bridge, result, malformed_duplicate)

        almost_overflowed = bytes(256) + struct.pack("<BQQ", 0, _MASK64, _MASK64 - 255)
        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "counter overflow"):
            replay_public_fsm_group(self.bridge, almost_overflowed, event)

        forbidden = bytearray(initial_public_fsm_state())
        forbidden[17] = 0x80
        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "forbids -128"):
            replay_public_fsm_group(self.bridge, bytes(forbidden), event)

    def test_json_shaped_event_parser_rejects_coercions(self) -> None:
        event = _fixture_event(group_id=401, marker_symbol=0, shift=0)
        mapping = {
            "group_id": event.group_id,
            "coordinates": event.coordinates,
            "families": event.families,
            "qualities": event.qualities,
            "evidence_votes": event.evidence_votes,
            "marker_symbol": event.marker_symbol,
        }
        parsed = PublicFSMGroupEvent.from_mapping(mapping)
        self.assertEqual(
            replay_public_fsm_group(self.bridge, initial_public_fsm_state(), parsed),
            replay_public_fsm_group(self.bridge, initial_public_fsm_state(), event),
        )
        coerced = dict(mapping)
        coerced["group_id"] = True
        with self.assertRaisesRegex(O1OPublicFSMBridgeError, "group_id differs"):
            replay_public_fsm_group(
                self.bridge,
                initial_public_fsm_state(),
                PublicFSMGroupEvent.from_mapping(coerced),
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
