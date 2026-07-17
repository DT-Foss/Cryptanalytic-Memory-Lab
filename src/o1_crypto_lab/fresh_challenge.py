"""Self-contained fresh W46 ChaCha20 challenge and reveal broker.

The broker is deliberately independent of every historical research tree.  It
draws one fixed-size entropy record per target, publishes only the material a
solver is allowed to see, and retains the 46-bit assignment until every target
has one exact, commitment-bound freeze receipt.

All wire documents are strict canonical finite ASCII JSON values.  The module
performs no file I/O and depends only on the Python standard library.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass
from typing import Callable, Mapping


UINT32_MASK = (1 << 32) - 1
ASSIGNMENT_BITS = 46
ASSIGNMENT_MASK = (1 << ASSIGNMENT_BITS) - 1
KNOWN_KEY_BITS = 256 - ASSIGNMENT_BITS
BLOCK_COUNT = 8
TARGET_CANDIDATE_COUNT = 1 << 12
ENTROPY_BYTES_PER_TARGET = 6 + 4 + 12

PUBLIC_CHALLENGE_SCHEMA = "o1-crypto-fresh-w46-public-challenge-v1"
TARGET_COMMITMENT_SCHEMA = "o1-crypto-fresh-w46-target-commitment-v1"
COMMITMENT_PREIMAGE_SCHEMA = "o1-crypto-fresh-w46-commitment-preimage-v1"
PUBLICATION_SCHEMA = "o1-crypto-fresh-w46-publication-v1"
ENTROPY_PROVENANCE_SCHEMA = "o1-crypto-fresh-w46-entropy-provenance-v1"
FREEZE_RECEIPT_SCHEMA = "o1-crypto-fresh-w46-freeze-receipt-v1"
TARGET_REVEAL_SCHEMA = "o1-crypto-fresh-w46-target-reveal-v1"
REVEAL_SCHEMA = "o1-crypto-fresh-w46-reveal-v1"

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
HEX_RE = re.compile(r"[0-9a-f]*\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")

# Key bytes 00..1f, interpreted as eight RFC 8439 little-endian words, provide
# a public fixed known-key value.  Global key bits 0..45 are replaced by the
# fresh assignment, so the first word and low fourteen bits of the second word
# are deliberately zero in the public known value.
KNOWN_KEY_MASK_WORDS = (
    0x00000000,
    0xFFFFC000,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
)
_RFC_KEY_WORDS = tuple(struct.unpack("<8I", bytes(range(32))))
KNOWN_KEY_VALUE_WORDS = tuple(
    word & mask for word, mask in zip(_RFC_KEY_WORDS, KNOWN_KEY_MASK_WORDS)
)


class FreshChallengeError(ValueError):
    """A challenge, commitment, receipt, or reveal invariant differs."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the unique finite ASCII JSON encoding used by every commitment."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FreshChallengeError("value is not canonical finite ASCII JSON") from exc


def load_canonical_json(raw: bytes) -> object:
    """Decode an exact canonical JSON byte string and reject duplicate keys."""

    if not isinstance(raw, bytes):
        raise FreshChallengeError("canonical JSON input must be bytes")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise FreshChallengeError(f"duplicate canonical JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FreshChallengeError(f"non-finite JSON constant: {token}")
            ),
        )
    except FreshChallengeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreshChallengeError("canonical JSON input is invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise FreshChallengeError("JSON input is not in canonical ASCII form")
    return value


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _clone(value: object) -> object:
    return load_canonical_json(canonical_json_bytes(value))


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise FreshChallengeError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise FreshChallengeError(f"{field} must be a list")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise FreshChallengeError(
            f"{field} schema keys differ; missing={missing}, unexpected={unexpected}"
        )


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FreshChallengeError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise FreshChallengeError(f"{field} is outside [{minimum}, {maximum}]")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise FreshChallengeError(f"{field} must be boolean")
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise FreshChallengeError(f"{field} must be a lowercase SHA-256")
    return value


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise FreshChallengeError(f"{field} must be a finite ASCII identifier")
    return value


def _hex(value: object, field: str, byte_length: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != byte_length * 2
        or HEX_RE.fullmatch(value) is None
    ):
        raise FreshChallengeError(
            f"{field} must be exactly {byte_length} lowercase hexadecimal bytes"
        )
    return value


def _word_list(value: object, field: str, length: int) -> list[int]:
    rows = _list(value, field)
    if len(rows) != length:
        raise FreshChallengeError(f"{field} must contain exactly {length} words")
    return [
        _integer(word, f"{field}[{index}]", 0, UINT32_MASK)
        for index, word in enumerate(rows)
    ]


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & UINT32_MASK) | (value >> (32 - distance))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & UINT32_MASK
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & UINT32_MASK
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & UINT32_MASK
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & UINT32_MASK
    state[b] = _rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return one RFC 8439 ChaCha20 block using exactly twenty rounds."""

    if not isinstance(key, bytes) or len(key) != 32:
        raise FreshChallengeError("ChaCha20 key must be exactly 32 bytes")
    if isinstance(counter, bool) or not isinstance(counter, int):
        raise FreshChallengeError("ChaCha20 counter must be an integer")
    if not 0 <= counter <= UINT32_MASK:
        raise FreshChallengeError("ChaCha20 counter must be uint32")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise FreshChallengeError("ChaCha20 nonce must be exactly 12 bytes")

    initial = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    ]
    state = initial.copy()
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack(
        "<16I",
        *((state[index] + initial[index]) & UINT32_MASK for index in range(16)),
    )


def _key_words(assignment: int) -> tuple[int, ...]:
    _integer(assignment, "assignment", 0, ASSIGNMENT_MASK)
    words = list(KNOWN_KEY_VALUE_WORDS)
    words[0] = assignment & UINT32_MASK
    words[1] |= (assignment >> 32) & ((1 << 14) - 1)
    for index, (word, mask, known) in enumerate(
        zip(words, KNOWN_KEY_MASK_WORDS, KNOWN_KEY_VALUE_WORDS)
    ):
        if word & mask != known:
            raise AssertionError(f"derived key violates known word {index}")
    return tuple(words)


def _entropy_provenance(entropy: bytes, source_id: str) -> dict[str, object]:
    return {
        "schema": ENTROPY_PROVENANCE_SCHEMA,
        "source_id": _identifier(source_id, "entropy source_id"),
        "requested_bytes": ENTROPY_BYTES_PER_TARGET,
        "entropy_hex": entropy.hex(),
        "entropy_sha256": hashlib.sha256(entropy).hexdigest(),
    }


def _validate_entropy_provenance(value: object) -> dict[str, object]:
    row = _mapping(value, "entropy_provenance")
    _exact_keys(
        row,
        {
            "schema",
            "source_id",
            "requested_bytes",
            "entropy_hex",
            "entropy_sha256",
        },
        "entropy_provenance",
    )
    if row.get("schema") != ENTROPY_PROVENANCE_SCHEMA:
        raise FreshChallengeError("entropy provenance schema differs")
    source_id = _identifier(row.get("source_id"), "entropy_provenance.source_id")
    requested = _integer(
        row.get("requested_bytes"),
        "entropy_provenance.requested_bytes",
        ENTROPY_BYTES_PER_TARGET,
        ENTROPY_BYTES_PER_TARGET,
    )
    entropy_hex = _hex(
        row.get("entropy_hex"),
        "entropy_provenance.entropy_hex",
        ENTROPY_BYTES_PER_TARGET,
    )
    digest = _sha256(row.get("entropy_sha256"), "entropy_provenance.entropy_sha256")
    entropy = bytes.fromhex(entropy_hex)
    if hashlib.sha256(entropy).hexdigest() != digest:
        raise FreshChallengeError("entropy provenance SHA-256 differs")
    return {
        "schema": ENTROPY_PROVENANCE_SCHEMA,
        "source_id": source_id,
        "requested_bytes": requested,
        "entropy_hex": entropy_hex,
        "entropy_sha256": digest,
    }


def _construct_public_challenge(
    entropy: bytes, target_id: str
) -> tuple[dict[str, object], int]:
    if not isinstance(entropy, bytes) or len(entropy) != ENTROPY_BYTES_PER_TARGET:
        raise FreshChallengeError(
            f"entropy source must return exactly {ENTROPY_BYTES_PER_TARGET} bytes"
        )
    target_id = _identifier(target_id, "target_id")
    assignment = int.from_bytes(entropy[:6], "little") & ASSIGNMENT_MASK
    counter_base = int.from_bytes(entropy[6:10], "little")
    nonce = entropy[10:22]
    nonce_words = list(struct.unpack("<3I", nonce))
    counters = [
        (counter_base + block_index) & UINT32_MASK for block_index in range(BLOCK_COUNT)
    ]
    key = struct.pack("<8I", *_key_words(assignment))
    blocks = [chacha20_block(key, counter, nonce) for counter in counters]
    target_words = [list(struct.unpack("<16I", block)) for block in blocks]
    challenge: dict[str, object] = {
        "schema": PUBLIC_CHALLENGE_SCHEMA,
        "target_id": target_id,
        "rounds": 20,
        "block_count": BLOCK_COUNT,
        "counter_base": counter_base,
        "counter_schedule": counters,
        "nonce_words": nonce_words,
        "target_words": target_words,
        "target_block_sha256": [hashlib.sha256(block).hexdigest() for block in blocks],
        "unknown_key_bits": ASSIGNMENT_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_global_bit_interval": [0, ASSIGNMENT_BITS - 1],
        "known_key_mask_words": list(KNOWN_KEY_MASK_WORDS),
        "known_key_value_words": list(KNOWN_KEY_VALUE_WORDS),
        "secret_key_included": False,
        "assignment_included": False,
    }
    _validate_public_challenge(challenge)
    return challenge, assignment


def _validate_public_challenge(value: object) -> dict[str, object]:
    row = _mapping(value, "public_challenge")
    expected_keys = {
        "schema",
        "target_id",
        "rounds",
        "block_count",
        "counter_base",
        "counter_schedule",
        "nonce_words",
        "target_words",
        "target_block_sha256",
        "unknown_key_bits",
        "known_key_bits",
        "unknown_global_bit_interval",
        "known_key_mask_words",
        "known_key_value_words",
        "secret_key_included",
        "assignment_included",
    }
    _exact_keys(row, expected_keys, "public_challenge")
    if row.get("schema") != PUBLIC_CHALLENGE_SCHEMA:
        raise FreshChallengeError("public challenge schema differs")
    _identifier(row.get("target_id"), "public_challenge.target_id")
    _integer(row.get("rounds"), "public_challenge.rounds", 20, 20)
    _integer(
        row.get("block_count"),
        "public_challenge.block_count",
        BLOCK_COUNT,
        BLOCK_COUNT,
    )
    counter_base = _integer(
        row.get("counter_base"), "public_challenge.counter_base", 0, UINT32_MASK
    )
    counters = _word_list(
        row.get("counter_schedule"), "public_challenge.counter_schedule", BLOCK_COUNT
    )
    expected_counters = [
        (counter_base + block_index) & UINT32_MASK for block_index in range(BLOCK_COUNT)
    ]
    if counters != expected_counters:
        raise FreshChallengeError("public challenge counter schedule differs")
    _word_list(row.get("nonce_words"), "public_challenge.nonce_words", 3)
    target_rows = _list(row.get("target_words"), "public_challenge.target_words")
    if len(target_rows) != BLOCK_COUNT:
        raise FreshChallengeError("public challenge must contain eight target blocks")
    target_words = [
        _word_list(block, f"public_challenge.target_words[{index}]", 16)
        for index, block in enumerate(target_rows)
    ]
    digests = _list(
        row.get("target_block_sha256"), "public_challenge.target_block_sha256"
    )
    if len(digests) != BLOCK_COUNT:
        raise FreshChallengeError("public challenge must contain eight block hashes")
    for index, (words, digest) in enumerate(zip(target_words, digests)):
        expected = hashlib.sha256(struct.pack("<16I", *words)).hexdigest()
        if _sha256(digest, f"target_block_sha256[{index}]") != expected:
            raise FreshChallengeError(f"target block {index} SHA-256 differs")
    _integer(
        row.get("unknown_key_bits"),
        "public_challenge.unknown_key_bits",
        ASSIGNMENT_BITS,
        ASSIGNMENT_BITS,
    )
    _integer(
        row.get("known_key_bits"),
        "public_challenge.known_key_bits",
        KNOWN_KEY_BITS,
        KNOWN_KEY_BITS,
    )
    interval = _list(
        row.get("unknown_global_bit_interval"),
        "public_challenge.unknown_global_bit_interval",
    )
    if interval != [0, ASSIGNMENT_BITS - 1]:
        raise FreshChallengeError("public challenge unknown bit interval differs")
    if _word_list(
        row.get("known_key_mask_words"),
        "public_challenge.known_key_mask_words",
        8,
    ) != list(KNOWN_KEY_MASK_WORDS):
        raise FreshChallengeError("public challenge known-key mask differs")
    if _word_list(
        row.get("known_key_value_words"),
        "public_challenge.known_key_value_words",
        8,
    ) != list(KNOWN_KEY_VALUE_WORDS):
        raise FreshChallengeError("public challenge known-key value differs")
    if _boolean(row.get("secret_key_included"), "public_challenge.secret_key_included"):
        raise FreshChallengeError("public challenge must not include the secret key")
    if _boolean(row.get("assignment_included"), "public_challenge.assignment_included"):
        raise FreshChallengeError("public challenge must not include the assignment")
    cloned = _clone(row)
    assert isinstance(cloned, dict)
    return cloned


def _commitment_preimage(
    *,
    target_id: str,
    assignment: int,
    provenance: Mapping[str, object],
    challenge: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": COMMITMENT_PREIMAGE_SCHEMA,
        "target_id": target_id,
        "assignment": assignment,
        "assignment_bits": f"{assignment:046b}",
        "entropy_provenance": dict(provenance),
        "public_challenge": dict(challenge),
    }


def _target_commitment(
    *,
    target_id: str,
    assignment: int,
    provenance: Mapping[str, object],
    challenge: Mapping[str, object],
) -> dict[str, object]:
    preimage = _commitment_preimage(
        target_id=target_id,
        assignment=assignment,
        provenance=provenance,
        challenge=challenge,
    )
    return {
        "schema": TARGET_COMMITMENT_SCHEMA,
        "target_id": target_id,
        "public_challenge_sha256": _canonical_sha256(challenge),
        "entropy_provenance_sha256": _canonical_sha256(provenance),
        "commitment_sha256": _canonical_sha256(preimage),
    }


def _validate_target_commitment(
    value: object, *, challenge: Mapping[str, object]
) -> dict[str, object]:
    row = _mapping(value, "target_commitment")
    _exact_keys(
        row,
        {
            "schema",
            "target_id",
            "public_challenge_sha256",
            "entropy_provenance_sha256",
            "commitment_sha256",
        },
        "target_commitment",
    )
    if row.get("schema") != TARGET_COMMITMENT_SCHEMA:
        raise FreshChallengeError("target commitment schema differs")
    target_id = _identifier(row.get("target_id"), "target_commitment.target_id")
    if target_id != challenge.get("target_id"):
        raise FreshChallengeError("target commitment target differs")
    challenge_sha = _sha256(
        row.get("public_challenge_sha256"),
        "target_commitment.public_challenge_sha256",
    )
    if challenge_sha != _canonical_sha256(challenge):
        raise FreshChallengeError("target commitment challenge hash differs")
    _sha256(
        row.get("entropy_provenance_sha256"),
        "target_commitment.entropy_provenance_sha256",
    )
    _sha256(row.get("commitment_sha256"), "target_commitment.commitment_sha256")
    cloned = _clone(row)
    assert isinstance(cloned, dict)
    return cloned


def verify_publication(value: object) -> dict[str, object]:
    """Validate and return a detached canonical public challenge publication."""

    row = _mapping(value, "publication")
    _exact_keys(
        row,
        {"schema", "target_count", "targets", "publication_sha256"},
        "publication",
    )
    if row.get("schema") != PUBLICATION_SCHEMA:
        raise FreshChallengeError("publication schema differs")
    target_count = _integer(row.get("target_count"), "publication.target_count", 1, 256)
    targets = _list(row.get("targets"), "publication.targets")
    if len(targets) != target_count:
        raise FreshChallengeError("publication target count differs")
    identifiers: set[str] = set()
    canonical_targets: list[dict[str, object]] = []
    for index, item in enumerate(targets):
        target = _mapping(item, f"publication.targets[{index}]")
        _exact_keys(
            target, {"challenge", "commitment"}, f"publication.targets[{index}]"
        )
        challenge = _validate_public_challenge(target.get("challenge"))
        target_id = str(challenge["target_id"])
        if target_id in identifiers:
            raise FreshChallengeError("publication target identifiers are not unique")
        identifiers.add(target_id)
        commitment = _validate_target_commitment(
            target.get("commitment"), challenge=challenge
        )
        canonical_targets.append({"challenge": challenge, "commitment": commitment})
    unsigned = {
        "schema": PUBLICATION_SCHEMA,
        "target_count": target_count,
        "targets": canonical_targets,
    }
    supplied_sha = _sha256(
        row.get("publication_sha256"), "publication.publication_sha256"
    )
    if supplied_sha != _canonical_sha256(unsigned):
        raise FreshChallengeError("publication SHA-256 differs")
    unsigned["publication_sha256"] = supplied_sha
    return unsigned


def make_freeze_receipt(
    public_target: object,
    *,
    frozen_order_sha256: str,
) -> dict[str, object]:
    """Create a self-hashed complete Direct12 freeze receipt for one target."""

    target = _mapping(public_target, "public_target")
    _exact_keys(target, {"challenge", "commitment"}, "public_target")
    challenge = _validate_public_challenge(target.get("challenge"))
    commitment = _validate_target_commitment(
        target.get("commitment"), challenge=challenge
    )
    receipt: dict[str, object] = {
        "schema": FREEZE_RECEIPT_SCHEMA,
        "target_id": challenge["target_id"],
        "public_challenge_sha256": commitment["public_challenge_sha256"],
        "target_commitment_sha256": commitment["commitment_sha256"],
        "frozen_order_sha256": _sha256(frozen_order_sha256, "frozen_order_sha256"),
        "frozen_candidate_count": TARGET_CANDIDATE_COUNT,
        "freeze_complete": True,
        "target_labels_used": 0,
    }
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    return receipt


def _validate_freeze_receipt(
    value: object,
    *,
    public_target: Mapping[str, object],
) -> dict[str, object]:
    row = _mapping(value, "freeze_receipt")
    expected_keys = {
        "schema",
        "target_id",
        "public_challenge_sha256",
        "target_commitment_sha256",
        "frozen_order_sha256",
        "frozen_candidate_count",
        "freeze_complete",
        "target_labels_used",
        "receipt_sha256",
    }
    _exact_keys(row, expected_keys, "freeze_receipt")
    if row.get("schema") != FREEZE_RECEIPT_SCHEMA:
        raise FreshChallengeError("freeze receipt schema differs")
    challenge = _mapping(public_target.get("challenge"), "public_target.challenge")
    commitment = _mapping(public_target.get("commitment"), "public_target.commitment")
    if _identifier(row.get("target_id"), "freeze_receipt.target_id") != challenge.get(
        "target_id"
    ):
        raise FreshChallengeError("freeze receipt target differs")
    if _sha256(
        row.get("public_challenge_sha256"),
        "freeze_receipt.public_challenge_sha256",
    ) != commitment.get("public_challenge_sha256"):
        raise FreshChallengeError("freeze receipt challenge commitment differs")
    if _sha256(
        row.get("target_commitment_sha256"),
        "freeze_receipt.target_commitment_sha256",
    ) != commitment.get("commitment_sha256"):
        raise FreshChallengeError("freeze receipt target commitment differs")
    _sha256(row.get("frozen_order_sha256"), "freeze_receipt.frozen_order_sha256")
    _integer(
        row.get("frozen_candidate_count"),
        "freeze_receipt.frozen_candidate_count",
        TARGET_CANDIDATE_COUNT,
        TARGET_CANDIDATE_COUNT,
    )
    if not _boolean(row.get("freeze_complete"), "freeze_receipt.freeze_complete"):
        raise FreshChallengeError("freeze receipt is not complete")
    if (
        _integer(
            row.get("target_labels_used"),
            "freeze_receipt.target_labels_used",
            0,
            0,
        )
        != 0
    ):
        raise FreshChallengeError("freeze receipt used target labels")
    supplied_sha = _sha256(row.get("receipt_sha256"), "freeze_receipt.receipt_sha256")
    unsigned = {key: item for key, item in row.items() if key != "receipt_sha256"}
    if supplied_sha != _canonical_sha256(unsigned):
        raise FreshChallengeError("freeze receipt SHA-256 differs")
    cloned = _clone(row)
    assert isinstance(cloned, dict)
    return cloned


@dataclass(frozen=True)
class _SealedTarget:
    target_id: str
    assignment: int
    provenance: Mapping[str, object]
    challenge: Mapping[str, object]
    commitment: Mapping[str, object]


class FreshChallengeBroker:
    """Generate, publish, then jointly reveal a finite fresh W46 target set."""

    def __init__(
        self,
        target_count: int,
        *,
        entropy_source: Callable[[int], bytes] = os.urandom,
        entropy_source_id: str = "os.urandom",
    ) -> None:
        target_count = _integer(target_count, "target_count", 1, 256)
        if not callable(entropy_source):
            raise FreshChallengeError("entropy_source must be callable")
        source_id = _identifier(entropy_source_id, "entropy_source_id")
        sealed: list[_SealedTarget] = []
        for index in range(target_count):
            entropy = entropy_source(ENTROPY_BYTES_PER_TARGET)
            if (
                not isinstance(entropy, bytes)
                or len(entropy) != ENTROPY_BYTES_PER_TARGET
            ):
                raise FreshChallengeError(
                    f"entropy source must return exactly {ENTROPY_BYTES_PER_TARGET} bytes"
                )
            target_id = f"fresh-w46-{index:04d}"
            challenge, assignment = _construct_public_challenge(entropy, target_id)
            provenance = _entropy_provenance(entropy, source_id)
            commitment = _target_commitment(
                target_id=target_id,
                assignment=assignment,
                provenance=provenance,
                challenge=challenge,
            )
            sealed.append(
                _SealedTarget(
                    target_id=target_id,
                    assignment=assignment,
                    provenance=provenance,
                    challenge=challenge,
                    commitment=commitment,
                )
            )
        self._sealed = tuple(sealed)
        self._phase = "sealed"
        self._publication = self._build_publication()

    @property
    def phase(self) -> str:
        return self._phase

    def _build_publication(self) -> dict[str, object]:
        publication: dict[str, object] = {
            "schema": PUBLICATION_SCHEMA,
            "target_count": len(self._sealed),
            "targets": [
                {
                    "challenge": dict(target.challenge),
                    "commitment": dict(target.commitment),
                }
                for target in self._sealed
            ],
        }
        publication["publication_sha256"] = _canonical_sha256(publication)
        return verify_publication(publication)

    def publish(self) -> dict[str, object]:
        """Release the stable public target set without any assignment material."""

        if self._phase == "revealed":
            raise FreshChallengeError("public challenge broker is already revealed")
        self._phase = "published"
        cloned = _clone(self._publication)
        assert isinstance(cloned, dict)
        return cloned

    def reveal(self, receipts: object) -> dict[str, object]:
        """Reveal every label atomically after one exact receipt per target."""

        if self._phase == "sealed":
            raise FreshChallengeError(
                "public challenges must be published before reveal"
            )
        if self._phase == "revealed":
            raise FreshChallengeError("reveal receipts cannot be replayed")
        rows = _list(receipts, "receipts")
        if len(rows) != len(self._sealed):
            raise FreshChallengeError("reveal requires exactly one receipt per target")
        public_targets = self._publication["targets"]
        assert isinstance(public_targets, list)
        supplied_by_id: dict[str, object] = {}
        for raw in rows:
            receipt = _mapping(raw, "freeze_receipt")
            target_id = _identifier(
                receipt.get("target_id"), "freeze_receipt.target_id"
            )
            if target_id in supplied_by_id:
                raise FreshChallengeError("duplicate or replayed target receipt")
            supplied_by_id[target_id] = raw
        expected_ids = {target.target_id for target in self._sealed}
        if set(supplied_by_id) != expected_ids:
            raise FreshChallengeError("freeze receipt target set differs")

        canonical_receipts: list[dict[str, object]] = []
        reveals: list[dict[str, object]] = []
        for sealed, public_target in zip(self._sealed, public_targets):
            assert isinstance(public_target, dict)
            receipt = _validate_freeze_receipt(
                supplied_by_id[sealed.target_id], public_target=public_target
            )
            canonical_receipts.append(receipt)
            reveal = {
                "schema": TARGET_REVEAL_SCHEMA,
                "target_id": sealed.target_id,
                "assignment": sealed.assignment,
                "assignment_bits": f"{sealed.assignment:046b}",
                "key_words": list(_key_words(sealed.assignment)),
                "entropy_provenance": dict(sealed.provenance),
                "public_challenge_sha256": sealed.commitment["public_challenge_sha256"],
                "target_commitment_sha256": sealed.commitment["commitment_sha256"],
                "freeze_receipt_sha256": receipt["receipt_sha256"],
            }
            reveals.append(reveal)
        receipt_set_sha = _canonical_sha256(
            [receipt["receipt_sha256"] for receipt in canonical_receipts]
        )
        result: dict[str, object] = {
            "schema": REVEAL_SCHEMA,
            "publication_sha256": self._publication["publication_sha256"],
            "target_count": len(self._sealed),
            "receipt_set_sha256": receipt_set_sha,
            "reveals": reveals,
            "all_targets_verified": True,
        }
        result["reveal_sha256"] = _canonical_sha256(result)
        verified = verify_reveal(self._publication, result, canonical_receipts)
        self._phase = "revealed"
        return verified


def verify_reveal(
    publication: object,
    reveal: object,
    receipts: object,
) -> dict[str, object]:
    """Independently reconstruct every target and validate an atomic reveal."""

    public = verify_publication(publication)
    row = _mapping(reveal, "reveal")
    _exact_keys(
        row,
        {
            "schema",
            "publication_sha256",
            "target_count",
            "receipt_set_sha256",
            "reveals",
            "all_targets_verified",
            "reveal_sha256",
        },
        "reveal",
    )
    if row.get("schema") != REVEAL_SCHEMA:
        raise FreshChallengeError("reveal schema differs")
    if _sha256(
        row.get("publication_sha256"), "reveal.publication_sha256"
    ) != public.get("publication_sha256"):
        raise FreshChallengeError("reveal publication commitment differs")
    target_count = _integer(row.get("target_count"), "reveal.target_count", 1, 256)
    if target_count != public.get("target_count"):
        raise FreshChallengeError("reveal target count differs")
    if not _boolean(row.get("all_targets_verified"), "reveal.all_targets_verified"):
        raise FreshChallengeError("reveal verification flag differs")

    receipt_rows = _list(receipts, "receipts")
    reveal_rows = _list(row.get("reveals"), "reveal.reveals")
    public_targets = _list(public.get("targets"), "publication.targets")
    if len(receipt_rows) != target_count or len(reveal_rows) != target_count:
        raise FreshChallengeError("reveal is not a complete target cover")
    receipt_by_id: dict[str, object] = {}
    for raw_receipt in receipt_rows:
        receipt_map = _mapping(raw_receipt, "freeze_receipt")
        target_id = _identifier(
            receipt_map.get("target_id"), "freeze_receipt.target_id"
        )
        if target_id in receipt_by_id:
            raise FreshChallengeError("duplicate or replayed target receipt")
        receipt_by_id[target_id] = raw_receipt

    canonical_receipts: list[dict[str, object]] = []
    canonical_reveals: list[dict[str, object]] = []
    seen_reveals: set[str] = set()
    for index, (public_target, raw_reveal) in enumerate(
        zip(public_targets, reveal_rows)
    ):
        public_target_map = _mapping(public_target, f"publication.targets[{index}]")
        challenge = _mapping(
            public_target_map.get("challenge"), "public_target.challenge"
        )
        commitment = _mapping(
            public_target_map.get("commitment"), "public_target.commitment"
        )
        target_id = _identifier(
            challenge.get("target_id"), "public_challenge.target_id"
        )
        if target_id not in receipt_by_id:
            raise FreshChallengeError("reveal receipt target set differs")
        receipt = _validate_freeze_receipt(
            receipt_by_id[target_id], public_target=public_target_map
        )
        canonical_receipts.append(receipt)

        target_reveal = _mapping(raw_reveal, f"reveal.reveals[{index}]")
        _exact_keys(
            target_reveal,
            {
                "schema",
                "target_id",
                "assignment",
                "assignment_bits",
                "key_words",
                "entropy_provenance",
                "public_challenge_sha256",
                "target_commitment_sha256",
                "freeze_receipt_sha256",
            },
            f"reveal.reveals[{index}]",
        )
        if target_reveal.get("schema") != TARGET_REVEAL_SCHEMA:
            raise FreshChallengeError("target reveal schema differs")
        reveal_target_id = _identifier(
            target_reveal.get("target_id"), "target_reveal.target_id"
        )
        if reveal_target_id != target_id or reveal_target_id in seen_reveals:
            raise FreshChallengeError("target reveal identity or order differs")
        seen_reveals.add(reveal_target_id)
        assignment = _integer(
            target_reveal.get("assignment"),
            "target_reveal.assignment",
            0,
            ASSIGNMENT_MASK,
        )
        assignment_bits = target_reveal.get("assignment_bits")
        if (
            not isinstance(assignment_bits, str)
            or assignment_bits != f"{assignment:046b}"
        ):
            raise FreshChallengeError("target reveal assignment bits differ")
        key_words = _word_list(
            target_reveal.get("key_words"), "target_reveal.key_words", 8
        )
        if key_words != list(_key_words(assignment)):
            raise FreshChallengeError("target reveal key words differ")
        provenance = _validate_entropy_provenance(
            target_reveal.get("entropy_provenance")
        )
        entropy = bytes.fromhex(str(provenance["entropy_hex"]))
        if int.from_bytes(entropy[:6], "little") & ASSIGNMENT_MASK != assignment:
            raise FreshChallengeError("target reveal assignment/entropy differs")
        reconstructed, reconstructed_assignment = _construct_public_challenge(
            entropy, target_id
        )
        if reconstructed_assignment != assignment or reconstructed != challenge:
            raise FreshChallengeError(
                "target reveal does not reconstruct its challenge"
            )
        if _canonical_sha256(provenance) != commitment.get("entropy_provenance_sha256"):
            raise FreshChallengeError("target reveal entropy commitment differs")
        challenge_sha = _sha256(
            target_reveal.get("public_challenge_sha256"),
            "target_reveal.public_challenge_sha256",
        )
        if challenge_sha != commitment.get("public_challenge_sha256"):
            raise FreshChallengeError("target reveal challenge commitment differs")
        target_commitment_sha = _sha256(
            target_reveal.get("target_commitment_sha256"),
            "target_reveal.target_commitment_sha256",
        )
        expected_commitment = _canonical_sha256(
            _commitment_preimage(
                target_id=target_id,
                assignment=assignment,
                provenance=provenance,
                challenge=challenge,
            )
        )
        if (
            target_commitment_sha != commitment.get("commitment_sha256")
            or target_commitment_sha != expected_commitment
        ):
            raise FreshChallengeError("target reveal commitment differs")
        if _sha256(
            target_reveal.get("freeze_receipt_sha256"),
            "target_reveal.freeze_receipt_sha256",
        ) != receipt.get("receipt_sha256"):
            raise FreshChallengeError("target reveal freeze receipt differs")
        cloned_reveal = _clone(target_reveal)
        assert isinstance(cloned_reveal, dict)
        canonical_reveals.append(cloned_reveal)

    if set(receipt_by_id) != seen_reveals:
        raise FreshChallengeError("reveal receipt target set differs")
    expected_receipt_set_sha = _canonical_sha256(
        [receipt["receipt_sha256"] for receipt in canonical_receipts]
    )
    if (
        _sha256(row.get("receipt_set_sha256"), "reveal.receipt_set_sha256")
        != expected_receipt_set_sha
    ):
        raise FreshChallengeError("reveal receipt-set commitment differs")
    unsigned = {
        "schema": REVEAL_SCHEMA,
        "publication_sha256": public["publication_sha256"],
        "target_count": target_count,
        "receipt_set_sha256": expected_receipt_set_sha,
        "reveals": canonical_reveals,
        "all_targets_verified": True,
    }
    supplied_reveal_sha = _sha256(row.get("reveal_sha256"), "reveal.reveal_sha256")
    if supplied_reveal_sha != _canonical_sha256(unsigned):
        raise FreshChallengeError("reveal SHA-256 differs")
    unsigned["reveal_sha256"] = supplied_reveal_sha
    return unsigned


__all__ = [
    "ASSIGNMENT_BITS",
    "ASSIGNMENT_MASK",
    "BLOCK_COUNT",
    "ENTROPY_BYTES_PER_TARGET",
    "FreshChallengeBroker",
    "FreshChallengeError",
    "KNOWN_KEY_BITS",
    "KNOWN_KEY_MASK_WORDS",
    "KNOWN_KEY_VALUE_WORDS",
    "canonical_json_bytes",
    "chacha20_block",
    "load_canonical_json",
    "make_freeze_receipt",
    "verify_publication",
    "verify_reveal",
]
