"""Read-only BUILD adapter for the sibling A448 eight-block corpus.

The sibling artifacts were generated for a W46 known-complement experiment and
therefore publish 210 key bits.  Those privileged fields are used here only to
reconstruct BUILD labels.  The returned deployment object is a
``PublicTargetView`` containing exactly counter, nonce, and eight output blocks;
the known complement is never retained in that object.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .chacha_trace import UINT32_MASK, chacha20_blocks
from .living_inverse import PublicTargetView


A448_SOURCE_SPECS = (
    (
        "A359",
        32,
        "research/results/v1/"
        "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_prepared_v1.json",
    ),
    (
        "A363",
        32,
        "research/results/v1/"
        "chacha20_round20_w46_polarity_invariant_validation_a363_prepared_v1.json",
    ),
    (
        "A367",
        64,
        "research/results/v1/"
        "chacha20_round20_w46_cross_corpus_invariant_validation_a367_prepared_v1.json",
    ),
)
A448_TARGETS = 128
A448_BLOCKS = 8
A448_TARGETS_PER_BLOCK = 16
A448_W46_WIDTH = 46
_MASK32 = (1 << 32) - 1


class A448KnownKeyCorpusError(ValueError):
    """A sibling BUILD row or public relation differs from the A448 contract."""


@dataclass(frozen=True)
class A448KnownKeyTarget:
    """One BUILD teacher with a physically separate all-public deployment view."""

    source: str
    source_index: int
    block: int
    label: str
    public: PublicTargetView
    teacher_key: bytes

    def validate(self) -> None:
        if self.source not in {row[0] for row in A448_SOURCE_SPECS}:
            raise A448KnownKeyCorpusError("A448 source differs")
        if (
            isinstance(self.source_index, bool)
            or not isinstance(self.source_index, int)
            or self.source_index < 0
            or isinstance(self.block, bool)
            or not isinstance(self.block, int)
            or not 0 <= self.block < A448_BLOCKS
            or not isinstance(self.label, str)
            or not self.label
            or not isinstance(self.teacher_key, bytes)
            or len(self.teacher_key) != 32
        ):
            raise A448KnownKeyCorpusError("A448 target identity or teacher differs")
        self.public.validate()
        if self.public.block_count != A448_BLOCKS:
            raise A448KnownKeyCorpusError("A448 target must contain eight blocks")
        expected = chacha20_blocks(
            self.teacher_key,
            self.public.counter_schedule[0],
            self.public.nonce,
            A448_BLOCKS,
        )
        if expected != self.public.output_blocks:
            raise A448KnownKeyCorpusError("A448 teacher does not reproduce public output")


def default_sibling_root() -> Path:
    return Path(__file__).resolve().parents[2].parent / "arx-carry-leak"


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise A448KnownKeyCorpusError(f"{field} must be an object")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise A448KnownKeyCorpusError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _word_sequence(
    value: object, field: str, count: int
) -> tuple[int, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise A448KnownKeyCorpusError(f"{field} must be a word sequence")
    words = tuple(
        _integer(word, f"{field}[{index}]", 0, _MASK32)
        for index, word in enumerate(value)
    )
    if len(words) != count:
        raise A448KnownKeyCorpusError(f"{field} must contain {count} uint32 words")
    return words


def _target_blocks(value: object) -> tuple[bytes, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise A448KnownKeyCorpusError("target_words must be an eight-block sequence")
    blocks = []
    for index, raw in enumerate(value):
        words = _word_sequence(raw, f"target_words[{index}]", 16)
        blocks.append(struct.pack("<16I", *words))
    if len(blocks) != A448_BLOCKS:
        raise A448KnownKeyCorpusError("target_words must contain eight blocks")
    return tuple(blocks)


def _teacher_key(challenge: Mapping[str, object], assignment: int) -> bytes:
    words = list(
        _word_sequence(challenge.get("known_zeroed_key_words"), "known key", 8)
    )
    if words[0] != 0 or words[1] & ((1 << 14) - 1):
        raise A448KnownKeyCorpusError("known key does not zero coordinates 0..45")
    words[0] = assignment & _MASK32
    words[1] |= assignment >> 32
    return struct.pack("<8I", *words)


def target_from_a448_artifacts(
    *,
    sibling_root: str | Path,
    source: str,
    source_index: int,
    block: int,
    prepared_row: Mapping[str, object],
) -> A448KnownKeyTarget:
    """Build one public-only target plus separate BUILD label from anchored rows."""

    root = Path(sibling_root).resolve(strict=True)
    label = prepared_row.get("label")
    if not isinstance(label, str) or not label:
        raise A448KnownKeyCorpusError("prepared label differs")
    assignment = _integer(
        prepared_row.get("assignment"),
        "assignment",
        0,
        (1 << A448_W46_WIDTH) - 1,
    )
    public_ref = _mapping(prepared_row.get("public_challenge"), "public challenge ref")
    relative = public_ref.get("path")
    if not isinstance(relative, str) or not relative:
        raise A448KnownKeyCorpusError("public challenge path differs")
    challenge_path = (root / relative).resolve(strict=True)
    if not challenge_path.is_relative_to(root):
        raise A448KnownKeyCorpusError("public challenge escapes sibling root")
    try:
        challenge = _mapping(
            json.loads(challenge_path.read_text(encoding="utf-8")),
            "public challenge",
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise A448KnownKeyCorpusError("public challenge is unreadable") from exc
    if (
        challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("unknown_key_bits") != A448_W46_WIDTH
        or challenge.get("known_key_bits") != 256 - A448_W46_WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("known_material_derivation_label") != label
        or challenge.get("public_output_blocks") != A448_BLOCKS
    ):
        raise A448KnownKeyCorpusError("public challenge semantics differ")
    counter = _integer(
        challenge.get("counter_start"),
        "counter_start",
        0,
        UINT32_MASK - (A448_BLOCKS - 1),
    )
    nonce_words = _word_sequence(challenge.get("nonce_words"), "nonce_words", 3)
    public = PublicTargetView(
        counter_schedule=tuple(counter + offset for offset in range(A448_BLOCKS)),
        nonce=struct.pack("<3I", *nonce_words),
        output_blocks=_target_blocks(challenge.get("target_words")),
    )
    result = A448KnownKeyTarget(
        source=source,
        source_index=source_index,
        block=block,
        label=label,
        public=public,
        teacher_key=_teacher_key(challenge, assignment),
    )
    result.validate()
    return result


def load_a448_knownkey_corpus(
    sibling_root: str | Path | None = None,
) -> tuple[A448KnownKeyTarget, ...]:
    """Load all 128 A448 BUILD teachers without writing to the sibling repo."""

    root = (
        default_sibling_root() if sibling_root is None else Path(sibling_root)
    ).resolve(strict=True)
    targets: list[A448KnownKeyTarget] = []
    block_offset = 0
    for source, count, relative in A448_SOURCE_SPECS:
        prepared_path = (root / relative).resolve(strict=True)
        if not prepared_path.is_relative_to(root):
            raise A448KnownKeyCorpusError("prepared corpus escapes sibling root")
        try:
            prepared = _mapping(
                json.loads(prepared_path.read_text(encoding="utf-8")),
                f"{source} prepared corpus",
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise A448KnownKeyCorpusError(
                f"{source} prepared corpus is unreadable"
            ) from exc
        rows = prepared.get("rows")
        if not isinstance(rows, list) or len(rows) != count:
            raise A448KnownKeyCorpusError(f"{source} prepared row count differs")
        for source_index, raw_row in enumerate(rows):
            row = _mapping(raw_row, f"{source} row {source_index}")
            if row.get("index") != source_index:
                raise A448KnownKeyCorpusError(f"{source} row order differs")
            targets.append(
                target_from_a448_artifacts(
                    sibling_root=root,
                    source=source,
                    source_index=source_index,
                    block=block_offset + source_index // A448_TARGETS_PER_BLOCK,
                    prepared_row=row,
                )
            )
        block_offset += count // A448_TARGETS_PER_BLOCK
    if (
        len(targets) != A448_TARGETS
        or len({target.teacher_key for target in targets}) != A448_TARGETS
        or len({target.public.digest() for target in targets}) != A448_TARGETS
        or {target.block for target in targets} != set(range(A448_BLOCKS))
    ):
        raise A448KnownKeyCorpusError("complete A448 corpus identity differs")
    return tuple(targets)


__all__ = [
    "A448_BLOCKS",
    "A448KnownKeyCorpusError",
    "A448KnownKeyTarget",
    "A448_TARGETS",
    "default_sibling_root",
    "load_a448_knownkey_corpus",
    "target_from_a448_artifacts",
]
