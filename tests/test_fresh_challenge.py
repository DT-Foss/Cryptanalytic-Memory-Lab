from __future__ import annotations

import copy
import hashlib
import unittest

from o1_crypto_lab.fresh_challenge import (
    ASSIGNMENT_MASK,
    BLOCK_COUNT,
    ENTROPY_BYTES_PER_TARGET,
    FreshChallengeBroker,
    FreshChallengeError,
    KNOWN_KEY_MASK_WORDS,
    KNOWN_KEY_VALUE_WORDS,
    canonical_json_bytes,
    chacha20_block,
    load_canonical_json,
    make_freeze_receipt,
    verify_publication,
    verify_reveal,
)


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class DeterministicEntropy:
    def __init__(self, records: list[bytes]) -> None:
        self.records = list(records)
        self.requests: list[int] = []

    def __call__(self, size: int) -> bytes:
        self.requests.append(size)
        if not self.records:
            raise AssertionError("unexpected entropy request")
        return self.records.pop(0)


def _record(seed: int) -> bytes:
    return bytes(
        (seed + 37 * index) & 0xFF for index in range(ENTROPY_BYTES_PER_TARGET)
    )


def _receipts(publication: dict[str, object]) -> list[dict[str, object]]:
    targets = publication["targets"]
    assert isinstance(targets, list)
    return [
        make_freeze_receipt(
            target,
            frozen_order_sha256=hashlib.sha256(f"order-{index}".encode()).hexdigest(),
        )
        for index, target in enumerate(targets)
    ]


class ChaCha20BlockTests(unittest.TestCase):
    def test_rfc8439_section_2_3_2_block_vector(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        expected = bytes.fromhex(
            "10f1e7e4d13b5915500fdd1fa32071c4"
            "c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e"
        )
        self.assertEqual(chacha20_block(key, 1, nonce), expected)

    def test_block_input_types_and_ranges_are_fail_closed(self) -> None:
        with self.assertRaises(FreshChallengeError):
            chacha20_block(b"x" * 31, 0, b"n" * 12)
        with self.assertRaises(FreshChallengeError):
            chacha20_block(b"x" * 32, True, b"n" * 12)
        with self.assertRaises(FreshChallengeError):
            chacha20_block(b"x" * 32, 1 << 32, b"n" * 12)
        with self.assertRaises(FreshChallengeError):
            chacha20_block(b"x" * 32, 0, b"n" * 11)


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_ascii_round_trip_and_noncanonical_rejection(self) -> None:
        raw = canonical_json_bytes({"z": [1, False], "a": "\u2600"})
        self.assertEqual(raw, b'{"a":"\\u2600","z":[1,false]}')
        self.assertEqual(load_canonical_json(raw), {"a": "\u2600", "z": [1, False]})
        with self.assertRaisesRegex(FreshChallengeError, "not in canonical"):
            load_canonical_json(b'{"z":1, "a":2}')
        with self.assertRaisesRegex(FreshChallengeError, "duplicate"):
            load_canonical_json(b'{"a":1,"a":2}')
        with self.assertRaises(FreshChallengeError):
            canonical_json_bytes({"x": float("nan")})


class FreshChallengeConstructionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.records = [_record(3), _record(91)]
        self.source = DeterministicEntropy(self.records.copy())
        self.broker = FreshChallengeBroker(
            2,
            entropy_source=self.source,
            entropy_source_id="test.deterministic-v1",
        )
        self.publication = self.broker.publish()

    def test_deterministic_w46_public_construction(self) -> None:
        self.assertEqual(self.source.requests, [ENTROPY_BYTES_PER_TARGET] * 2)
        self.assertEqual(self.publication["target_count"], 2)
        targets = self.publication["targets"]
        assert isinstance(targets, list)
        challenge = targets[0]["challenge"]
        assignment = int.from_bytes(self.records[0][:6], "little") & ASSIGNMENT_MASK
        counter_base = int.from_bytes(self.records[0][6:10], "little")
        self.assertEqual(challenge["rounds"], 20)
        self.assertEqual(challenge["block_count"], BLOCK_COUNT)
        self.assertEqual(challenge["counter_base"], counter_base)
        self.assertEqual(
            challenge["counter_schedule"],
            [(counter_base + index) & 0xFFFFFFFF for index in range(BLOCK_COUNT)],
        )
        self.assertEqual(challenge["unknown_key_bits"], 46)
        self.assertEqual(challenge["known_key_bits"], 210)
        self.assertEqual(challenge["unknown_global_bit_interval"], [0, 45])
        self.assertEqual(challenge["known_key_mask_words"], list(KNOWN_KEY_MASK_WORDS))
        self.assertEqual(
            challenge["known_key_value_words"], list(KNOWN_KEY_VALUE_WORDS)
        )
        self.assertEqual(len(challenge["target_words"]), 8)
        self.assertTrue(all(len(block) == 16 for block in challenge["target_words"]))
        self.assertNotIn("assignment", challenge)
        self.assertNotIn("key_words", challenge)
        self.assertFalse(challenge["secret_key_included"])
        self.assertFalse(challenge["assignment_included"])

        # The assignment exists only to make this assertion demonstrate that
        # the fixture is non-trivial; it is never returned by publish().
        self.assertNotEqual(assignment, 0)
        self.assertEqual(verify_publication(self.publication), self.publication)

    def test_publication_is_detached_and_reproducible(self) -> None:
        source = DeterministicEntropy(self.records.copy())
        twin = FreshChallengeBroker(
            2,
            entropy_source=source,
            entropy_source_id="test.deterministic-v1",
        ).publish()
        self.assertEqual(twin, self.publication)
        targets = self.publication["targets"]
        assert isinstance(targets, list)
        targets[0]["challenge"]["target_words"][0][0] ^= 1
        pristine = self.broker.publish()
        self.assertEqual(twin, pristine)

    def test_public_challenge_contains_no_assignment_or_complete_key(self) -> None:
        forbidden = {"assignment", "assignment_bits", "key_words", "entropy_hex"}

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden.isdisjoint(value))
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(self.publication)
        encoded = canonical_json_bytes(self.publication)
        self.assertNotIn(b'"assignment":', encoded)
        self.assertNotIn(b'"key_words":', encoded)
        self.assertNotIn(b'"entropy_hex":', encoded)

    def test_commitment_binds_entropy_provenance_even_when_challenge_matches(
        self,
    ) -> None:
        first = FreshChallengeBroker(
            1,
            entropy_source=DeterministicEntropy([self.records[0]]),
            entropy_source_id="source.alpha",
        ).publish()
        second = FreshChallengeBroker(
            1,
            entropy_source=DeterministicEntropy([self.records[0]]),
            entropy_source_id="source.beta",
        ).publish()
        first_target = first["targets"][0]
        second_target = second["targets"][0]
        self.assertEqual(first_target["challenge"], second_target["challenge"])
        self.assertNotEqual(
            first_target["commitment"]["entropy_provenance_sha256"],
            second_target["commitment"]["entropy_provenance_sha256"],
        )
        self.assertNotEqual(
            first_target["commitment"]["commitment_sha256"],
            second_target["commitment"]["commitment_sha256"],
        )

    def test_public_tampering_is_rejected_before_publication_hash(self) -> None:
        tampered = copy.deepcopy(self.publication)
        tampered["targets"][0]["challenge"]["target_words"][0][0] ^= 1
        with self.assertRaisesRegex(FreshChallengeError, "target block 0"):
            verify_publication(tampered)


class BrokerLifecycleTests(unittest.TestCase):
    def _broker(self, count: int = 2) -> FreshChallengeBroker:
        return FreshChallengeBroker(
            count,
            entropy_source=DeterministicEntropy(
                [_record(13 + index) for index in range(count)]
            ),
            entropy_source_id="test.lifecycle-v1",
        )

    def test_reveal_requires_prior_publication(self) -> None:
        broker = self._broker(1)
        with self.assertRaisesRegex(FreshChallengeError, "published before reveal"):
            broker.reveal([])

    def test_incomplete_duplicate_wrong_and_tampered_receipts_are_rejected(
        self,
    ) -> None:
        broker = self._broker(2)
        publication = broker.publish()
        receipts = _receipts(publication)
        with self.assertRaisesRegex(FreshChallengeError, "exactly one"):
            broker.reveal(receipts[:1])
        with self.assertRaisesRegex(FreshChallengeError, "duplicate or replayed"):
            broker.reveal([receipts[0], receipts[0]])

        wrong_target = copy.deepcopy(receipts)
        wrong_target[1]["target_id"] = "fresh-w46-9999"
        with self.assertRaisesRegex(FreshChallengeError, "target set"):
            broker.reveal(wrong_target)

        wrong_binding = copy.deepcopy(receipts)
        wrong_binding[0]["target_commitment_sha256"] = "0" * 64
        with self.assertRaisesRegex(FreshChallengeError, "target commitment"):
            broker.reveal(wrong_binding)

        incomplete = copy.deepcopy(receipts)
        incomplete[0]["freeze_complete"] = False
        unsigned = {
            key: value
            for key, value in incomplete[0].items()
            if key != "receipt_sha256"
        }
        incomplete[0]["receipt_sha256"] = _sha(unsigned)
        with self.assertRaisesRegex(FreshChallengeError, "not complete"):
            broker.reveal(incomplete)

        tampered = copy.deepcopy(receipts)
        tampered[0]["frozen_order_sha256"] = "f" * 64
        with self.assertRaisesRegex(FreshChallengeError, "receipt SHA-256"):
            broker.reveal(tampered)

    def test_exact_complete_receipts_release_all_labels_once(self) -> None:
        broker = self._broker(2)
        publication = broker.publish()
        receipts = _receipts(publication)
        reveal = broker.reveal(receipts)
        self.assertEqual(broker.phase, "revealed")
        self.assertTrue(reveal["all_targets_verified"])
        self.assertEqual(len(reveal["reveals"]), 2)
        self.assertEqual(verify_reveal(publication, reveal, receipts), reveal)

        for public_target, target_reveal in zip(
            publication["targets"], reveal["reveals"]
        ):
            self.assertEqual(
                target_reveal["public_challenge_sha256"],
                public_target["commitment"]["public_challenge_sha256"],
            )
            self.assertEqual(len(target_reveal["assignment_bits"]), 46)
            assignment = target_reveal["assignment"]
            key_words = target_reveal["key_words"]
            self.assertEqual(key_words[0], assignment & 0xFFFFFFFF)
            self.assertEqual(key_words[1] & 0x3FFF, assignment >> 32)

        with self.assertRaisesRegex(FreshChallengeError, "cannot be replayed"):
            broker.reveal(receipts)

    def test_stateless_reveal_verifier_recomputes_assignment_key_and_blocks(
        self,
    ) -> None:
        broker = self._broker(1)
        publication = broker.publish()
        receipts = _receipts(publication)
        reveal = broker.reveal(receipts)

        wrong_assignment = copy.deepcopy(reveal)
        wrong_assignment["reveals"][0]["assignment"] ^= 1
        with self.assertRaisesRegex(FreshChallengeError, "assignment bits"):
            verify_reveal(publication, wrong_assignment, receipts)

        wrong_entropy = copy.deepcopy(reveal)
        provenance = wrong_entropy["reveals"][0]["entropy_provenance"]
        entropy = bytearray.fromhex(provenance["entropy_hex"])
        entropy[-1] ^= 1
        provenance["entropy_hex"] = bytes(entropy).hex()
        provenance["entropy_sha256"] = hashlib.sha256(entropy).hexdigest()
        with self.assertRaisesRegex(FreshChallengeError, "reconstruct"):
            verify_reveal(publication, wrong_entropy, receipts)

        wrong_receipt = copy.deepcopy(receipts)
        wrong_receipt[0]["frozen_candidate_count"] = 4095
        unsigned = {
            key: value
            for key, value in wrong_receipt[0].items()
            if key != "receipt_sha256"
        }
        wrong_receipt[0]["receipt_sha256"] = _sha(unsigned)
        with self.assertRaisesRegex(FreshChallengeError, "outside"):
            verify_reveal(publication, reveal, wrong_receipt)


if __name__ == "__main__":
    unittest.main()
