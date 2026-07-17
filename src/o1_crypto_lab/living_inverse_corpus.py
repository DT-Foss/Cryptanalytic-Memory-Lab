"""Memory-bounded generated corpora for full-256 Living Inverse readers."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .chacha_trace import ChaChaBlockTrace, chacha20_block_trace
from .living_inverse import (
    ContrastFamily,
    KEY_BITS,
    PublicTargetView,
    canonical_json_bytes,
    key_bits,
    propose_contrast_key,
    public_target_feature_vector,
)

PUBLIC_FEATURE_DIMENSION = 640
TEACHER_FEATURE_DIMENSION = 656
CANDIDATE_FEATURE_DIMENSION = 2576


class ReaderCorpusError(ValueError):
    """Raised when a generated corpus or attacker proposal differs."""


def _seed_bytes(domain: str, seed: int, length: int) -> bytes:
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ReaderCorpusError("seed must be an integer")
    return hashlib.shake_256(canonical_json_bytes([domain, seed])).digest(length)


def _structured_key(seed: int, index: int) -> bytes:
    material = _seed_bytes(f"structured/{index}", seed, 64)
    family = index % 4
    if family == 0:
        return material[:4] * 8
    if family == 1:
        result = bytearray(32)
        flips = 1 + (index % 16)
        used: set[int] = set()
        cursor = 0
        while len(used) < flips:
            coordinate = material[cursor % len(material)] + 256 * (
                material[(cursor + 1) % len(material)] & 1
            )
            used.add(coordinate % KEY_BITS)
            cursor += 2
        for coordinate in used:
            result[coordinate // 8] ^= 1 << (coordinate % 8)
        return bytes(result)
    if family == 2:
        patterns = (0x00, 0xFF, 0xAA, 0x55)
        base = bytearray([patterns[(index // 4) % len(patterns)]]) * 32
        for offset in range(4):
            base[(material[offset] + offset * 7) % 32] ^= material[8 + offset]
        return bytes(base)
    gray = index ^ (index >> 1)
    word = (gray & 0xFFFFFFFF).to_bytes(4, "little")
    return b"".join(
        bytes(
            left ^ right for left, right in zip(word, material[4 * lane : 4 * lane + 4])
        )
        for lane in range(8)
    )


def _uniform_key(seed: int, split: str, index: int) -> bytes:
    return _seed_bytes(f"uniform/{split}/{index}", seed, 32)


def teacher_trace_vector(trace: ChaChaBlockTrace) -> np.ndarray:
    trace.validate()
    values = [
        word.bit_count() / 32.0 for state in trace.round_states[1:] for word in state
    ]
    values.extend(
        mask.bit_count() / 32.0 for row in trace.round_carry_masks for mask in row
    )
    values.extend(mask.bit_count() / 32.0 for mask in trace.feedforward_carry_masks)
    result = np.asarray(values, dtype=np.float32)
    if result.shape != (TEACHER_FEATURE_DIMENSION,):
        raise AssertionError("teacher trace feature dimension differs")
    return result


@dataclass(frozen=True)
class ReaderTarget:
    target_id: str
    split: str
    distribution: str
    key: bytes
    public: PublicTargetView
    trace: ChaChaBlockTrace
    public_features: np.ndarray
    key_labels: np.ndarray
    teacher_features: np.ndarray

    def _validate_against_trace(self, expected_trace: ChaChaBlockTrace) -> None:
        if self.split not in {"TRAIN", "CALIBRATION", "DEVELOPMENT"}:
            raise ReaderCorpusError("reader target split differs")
        if self.distribution not in {"STRUCTURED", "UNIFORM"}:
            raise ReaderCorpusError("reader target distribution differs")
        if self.distribution == "STRUCTURED" and self.split != "TRAIN":
            raise ReaderCorpusError("structured targets are restricted to TRAIN")
        if not isinstance(self.key, bytes) or len(self.key) != 32:
            raise ReaderCorpusError("reader target key must contain 256 bits")
        self.public.validate()
        self.trace.validate()
        if (
            self.public.block_count != 1
            or self.trace.output != self.public.output_blocks[0]
        ):
            raise ReaderCorpusError("reader target public output differs")
        if self.public_features.shape != (PUBLIC_FEATURE_DIMENSION,):
            raise ReaderCorpusError("public feature dimension differs")
        if self.key_labels.shape != (KEY_BITS,):
            raise ReaderCorpusError("key label dimension differs")
        if self.teacher_features.shape != (TEACHER_FEATURE_DIMENSION,):
            raise ReaderCorpusError("teacher feature dimension differs")
        if any(
            array.dtype != np.float32 or not np.all(np.isfinite(array))
            for array in (
                self.public_features,
                self.key_labels,
                self.teacher_features,
            )
        ):
            raise ReaderCorpusError("reader target arrays must be finite float32")
        if expected_trace.digest() != self.trace.digest():
            raise ReaderCorpusError("reader target key, trace and public output differ")
        if not np.array_equal(
            self.public_features,
            public_target_feature_vector(self.public).astype(np.float32, copy=False),
        ):
            raise ReaderCorpusError("reader target public features differ")
        if not np.array_equal(
            self.key_labels, key_bits(self.key).astype(np.float32, copy=False)
        ):
            raise ReaderCorpusError("reader target key labels differ")
        if not np.array_equal(self.teacher_features, teacher_trace_vector(self.trace)):
            raise ReaderCorpusError("reader target teacher features differ")

    def validate(self) -> None:
        expected_trace = chacha20_block_trace(
            self.key, self.public.counter_schedule[0], self.public.nonce
        )
        self._validate_against_trace(expected_trace)

    def public_commitment(self) -> str:
        return hashlib.sha256(
            self.target_id.encode("ascii")
            + self.public.digest().encode("ascii")
            + self.public_features.tobytes()
        ).hexdigest()

    def teacher_commitment(self) -> str:
        return hashlib.sha256(
            self.target_id.encode("ascii")
            + self.key
            + self.key_labels.tobytes()
            + self.teacher_features.tobytes()
            + self.trace.digest().encode("ascii")
        ).hexdigest()


def make_reader_target(
    *,
    seed: int,
    split: str,
    index: int,
    counter: int,
    nonce: bytes,
    structured: bool,
) -> ReaderTarget:
    if split not in {"TRAIN", "CALIBRATION", "DEVELOPMENT"}:
        raise ReaderCorpusError("split differs")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ReaderCorpusError("index must be non-negative")
    if structured and split != "TRAIN":
        raise ReaderCorpusError("structured targets are restricted to TRAIN")
    key = (
        _structured_key(seed, index) if structured else _uniform_key(seed, split, index)
    )
    trace = chacha20_block_trace(key, counter, nonce)
    public = PublicTargetView(
        counter_schedule=(counter,), nonce=nonce, output_blocks=(trace.output,)
    )
    result = ReaderTarget(
        target_id=f"{split.lower()}-{index:06d}",
        split=split,
        distribution="STRUCTURED" if structured else "UNIFORM",
        key=key,
        public=public,
        trace=trace,
        public_features=public_target_feature_vector(public).astype(
            np.float32, copy=False
        ),
        key_labels=key_bits(key).astype(np.float32, copy=False),
        teacher_features=teacher_trace_vector(trace),
    )
    # The factory has just computed the exact trace; validate all couplings
    # against that object without performing the cipher a second time.
    result._validate_against_trace(trace)
    return result


def candidate_feature_vector(
    target: PublicTargetView, candidate_key: bytes
) -> np.ndarray:
    """Encode one attacker-generated key from the public target view alone."""

    if not isinstance(target, PublicTargetView):
        raise ReaderCorpusError("candidate encoder accepts only PublicTargetView")
    target.validate()
    if not isinstance(candidate_key, bytes) or len(candidate_key) != 32:
        raise ReaderCorpusError("candidate key must contain 256 bits")
    if target.block_count != 1:
        raise ReaderCorpusError("candidate encoder currently requires one public block")
    counter = target.counter_schedule[0]
    trace = chacha20_block_trace(candidate_key, counter, target.nonce)
    target_bits = np.unpackbits(
        np.frombuffer(target.output_blocks[0], dtype=np.uint8), bitorder="little"
    ).astype(np.float32)
    candidate_bits = np.unpackbits(
        np.frombuffer(trace.output, dtype=np.uint8), bitorder="little"
    ).astype(np.float32)
    residual = np.not_equal(target_bits, candidate_bits).astype(np.float32)
    candidate_key_bits = key_bits(candidate_key).astype(np.float32)
    public_payload = target.nonce + struct.pack("<I", counter)
    public_bits = np.unpackbits(
        np.frombuffer(public_payload, dtype=np.uint8), bitorder="little"
    ).astype(np.float32)
    result = np.concatenate(
        (
            target_bits,
            candidate_bits,
            residual,
            candidate_key_bits,
            public_bits,
            teacher_trace_vector(trace),
        )
    ).astype(np.float32, copy=False)
    if result.shape != (CANDIDATE_FEATURE_DIMENSION,):
        raise AssertionError("candidate feature dimension differs")
    return result


def training_candidate_key(
    target: ReaderTarget, *, seed: int, example_index: int
) -> tuple[ContrastFamily, bytes]:
    """Create a privileged TRAIN-only teacher contrast around the known key."""

    target.validate()
    if target.split != "TRAIN":
        raise ReaderCorpusError("privileged training candidates are TRAIN-only")
    families = tuple(ContrastFamily)
    family = families[(example_index + int(target.target_id[-6:])) % len(families)]
    probabilities: Sequence[float] | None = (
        np.full(KEY_BITS, 0.5, dtype=np.float64)
        if family is ContrastFamily.POSTERIOR_SAMPLE
        else None
    )
    candidate = propose_contrast_key(
        target.key,
        family,
        seed=seed + int(target.target_id[-6:]),
        step=example_index,
        posterior_probabilities=probabilities,
    )
    if candidate == target.key:
        candidate = propose_contrast_key(
            target.key,
            ContrastFamily.UNIFORM_RANDOM,
            seed=seed + 17,
            step=example_index + 1,
        )
    return family, candidate


def attacker_candidate_keys(
    target: PublicTargetView,
    direct_probabilities: Sequence[float],
    *,
    count: int,
    seed: int,
) -> tuple[bytes, ...]:
    """Create a target-secret-independent deployment proposal portfolio."""

    target.validate()
    probabilities = np.asarray(direct_probabilities, dtype=np.float64)
    if probabilities.shape != (KEY_BITS,) or not np.all(np.isfinite(probabilities)):
        raise ReaderCorpusError("direct probabilities must contain 256 finite values")
    if np.any((probabilities <= 0.0) | (probabilities >= 1.0)):
        raise ReaderCorpusError("direct probabilities must be in (0, 1)")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 64:
        raise ReaderCorpusError("attacker proposal count must be in [1, 64]")
    if (
        not isinstance(seed, int)
        or isinstance(seed, bool)
        or not -(1 << 63) <= seed < (1 << 63)
    ):
        raise ReaderCorpusError("attacker proposal seed must be signed int64")
    public_seed = int.from_bytes(
        hashlib.sha256(
            target.digest().encode("ascii") + seed.to_bytes(8, "big", signed=True)
        ).digest(),
        "big",
    )
    mode = np.packbits(
        (probabilities >= 0.5).astype(np.uint8), bitorder="little"
    ).tobytes()
    fixed = [
        bytes(32),
        bytes([0xFF]) * 32,
        bytes([0xAA]) * 32,
        bytes([0x55]) * 32,
        bytes(range(32)),
        bytes(reversed(range(32))),
        mode,
    ]
    proposals: list[bytes] = []

    def retain(candidate: bytes) -> None:
        if candidate not in proposals:
            proposals.append(candidate)

    for candidate in fixed:
        retain(candidate)
        if len(proposals) == count:
            return tuple(proposals)

    step = 0
    while len(proposals) < count:
        family = (
            ContrastFamily.POSTERIOR_SAMPLE
            if step % 3 == 0
            else (
                ContrastFamily.GRAY_WINDOW
                if step % 3 == 1
                else ContrastFamily.UNIFORM_RANDOM
            )
        )
        candidate = propose_contrast_key(
            mode,
            family,
            seed=public_seed,
            step=step,
            posterior_probabilities=(
                probabilities if family is ContrastFamily.POSTERIOR_SAMPLE else None
            ),
        )
        retain(candidate)
        step += 1
        if step > 1024:
            raise AssertionError("could not construct unique attacker proposals")
    return tuple(proposals)
