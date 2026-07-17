from __future__ import annotations

import copy
import json
import unittest

from o1_crypto_lab.full256_broker import (
    ENTROPY_BYTES,
    Full256BrokerError,
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_publication,
    verify_reveal,
)


class DeterministicEntropy:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.requests: list[int] = []

    def __call__(self, size: int) -> bytes:
        self.requests.append(size)
        return self.payload


class Full256BrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entropy = bytes((41 * index + 7) & 0xFF for index in range(ENTROPY_BYTES))
        self.source = DeterministicEntropy(self.entropy)
        self.broker = Full256TargetBroker(
            block_count=2,
            entropy_source=self.source,
            entropy_source_id="test.deterministic-v1",
            target_id="sealed-full256-test",
        )

    def test_publication_has_only_attacker_view_and_commitment(self) -> None:
        publication = self.broker.publish()
        self.assertEqual(self.source.requests, [ENTROPY_BYTES])
        self.assertEqual(publication["public_view"]["unknown_key_bits"], 256)
        self.assertEqual(len(publication["public_view"]["output_blocks_hex"]), 2)
        encoded = json.dumps(publication, sort_keys=True)
        self.assertNotIn(self.entropy[:32].hex(), encoded)
        self.assertNotIn(self.entropy[48:80].hex(), encoded)
        self.assertNotIn("target_trace", encoded.replace("target_trace_included", ""))
        self.assertEqual(verify_publication(publication), publication)
        self.assertEqual(
            public_view_from_publication(publication).digest(),
            publication["public_view_sha256"],
        )
        self.assertEqual(self.broker.phase, "PUBLISHED")

    def test_reveal_requires_exact_freeze_and_is_one_shot(self) -> None:
        publication = self.broker.publish()
        receipt = make_freeze_receipt(
            publication, frozen_artifact_sha256="a" * 64
        )
        tampered = copy.deepcopy(receipt)
        tampered["frozen_artifact_sha256"] = "b" * 64
        with self.assertRaisesRegex(Full256BrokerError, "receipt SHA"):
            self.broker.reveal(tampered)
        reveal = self.broker.reveal(receipt)
        self.assertEqual(verify_reveal(reveal), reveal)
        self.assertEqual(
            reveal["commitment_preimage"]["key_hex"], self.entropy[:32].hex()
        )
        self.assertEqual(self.broker.phase, "REVEALED")
        with self.assertRaisesRegex(Full256BrokerError, "already"):
            self.broker.reveal(receipt)

    def test_reveal_before_publish_and_public_tampering_fail(self) -> None:
        with self.assertRaisesRegex(Full256BrokerError, "published"):
            self.broker.reveal({})
        publication = self.broker.publish()
        tampered = copy.deepcopy(publication)
        tampered["public_view"]["output_blocks_hex"][0] = "00" * 64
        with self.assertRaises(Full256BrokerError):
            verify_publication(tampered)


if __name__ == "__main__":
    unittest.main()
