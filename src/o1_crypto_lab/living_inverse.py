"""Full-256 public-output Living Inverse data and measurement primitives."""

from __future__ import annotations

import hashlib
import json
import math
import random
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence

import numpy as np

from .chacha_trace import (
    CHACHA20_ROUNDS,
    UINT32_MASK,
    ChaChaBlockTrace,
    chacha20_block_trace,
)


KEY_BYTES = 32
KEY_BITS = 256
NONCE_BYTES = 12
BLOCK_BYTES = 64


class LivingInverseError(ValueError):
    """Raised when an attacker view, contrast or posterior is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise LivingInverseError("value is not canonical finite ASCII JSON") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _key(value: object, field: str = "key") -> bytes:
    if not isinstance(value, bytes) or len(value) != KEY_BYTES:
        raise LivingInverseError(f"{field} must be exactly 32 bytes")
    return value


def _nonce(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != NONCE_BYTES:
        raise LivingInverseError("nonce must be exactly 12 bytes")
    return value


def _counter(value: object, field: str = "counter") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LivingInverseError(f"{field} must be an integer")
    if not 0 <= value <= UINT32_MASK:
        raise LivingInverseError(f"{field} must be uint32")
    return value


def key_bits(key: bytes) -> np.ndarray:
    """Return key coordinates 0..255 in RFC little-bit-within-byte order."""

    return np.unpackbits(
        np.frombuffer(_key(key), dtype=np.uint8), bitorder="little"
    ).astype(np.uint8, copy=False)


def bits_to_key(bits: Sequence[int] | np.ndarray) -> bytes:
    array = np.asarray(bits)
    if array.shape != (KEY_BITS,) or np.any((array != 0) & (array != 1)):
        raise LivingInverseError("key bits must contain exactly 256 binary values")
    return np.packbits(array.astype(np.uint8), bitorder="little").tobytes()


@dataclass(frozen=True)
class PublicTargetView:
    """The complete and only unknown-target input accepted by deployment."""

    counter_schedule: tuple[int, ...]
    nonce: bytes
    output_blocks: tuple[bytes, ...]
    rounds: int = CHACHA20_ROUNDS

    def validate(self) -> None:
        if self.rounds != CHACHA20_ROUNDS:
            raise LivingInverseError("target must use exactly twenty rounds")
        if not isinstance(self.counter_schedule, tuple) or not self.counter_schedule:
            raise LivingInverseError("counter_schedule must be a non-empty tuple")
        counters = tuple(
            _counter(value, f"counter_schedule[{index}]")
            for index, value in enumerate(self.counter_schedule)
        )
        if counters != tuple(range(counters[0], counters[0] + len(counters))):
            raise LivingInverseError("counter schedule must be contiguous without wrap")
        _nonce(self.nonce)
        if (
            not isinstance(self.output_blocks, tuple)
            or len(self.output_blocks) != len(counters)
            or any(
                not isinstance(block, bytes) or len(block) != BLOCK_BYTES
                for block in self.output_blocks
            )
        ):
            raise LivingInverseError(
                "output_blocks must match the schedule with 64 bytes per block"
            )

    @property
    def block_count(self) -> int:
        return len(self.output_blocks)

    def describe(self) -> dict[str, object]:
        self.validate()
        return {
            "schema": "o1-256-public-target-view-v1",
            "cipher": "ChaCha20",
            "rounds": self.rounds,
            "feed_forward": True,
            "unknown_key_bits": KEY_BITS,
            "counter_schedule": list(self.counter_schedule),
            "nonce_hex": self.nonce.hex(),
            "output_blocks_hex": [block.hex() for block in self.output_blocks],
            "target_key_included": False,
            "target_trace_included": False,
        }

    def digest(self) -> str:
        return canonical_sha256(self.describe())


@dataclass(frozen=True)
class KnownTargetTeacher:
    """Build/dev-only target labels kept physically outside PublicTargetView."""

    target_key: bytes
    target_traces: tuple[ChaChaBlockTrace, ...]

    def validate_against(self, public: PublicTargetView) -> None:
        key = _key(self.target_key, "target_key")
        public.validate()
        if len(self.target_traces) != public.block_count:
            raise LivingInverseError("teacher trace count differs from public blocks")
        for index, (trace, counter, output) in enumerate(
            zip(
                self.target_traces,
                public.counter_schedule,
                public.output_blocks,
                strict=True,
            )
        ):
            trace.validate()
            expected = chacha20_block_trace(key, counter, public.nonce)
            if trace.digest() != expected.digest() or trace.output != output:
                raise LivingInverseError(f"teacher trace {index} differs")

    def describe_labels(self) -> dict[str, object]:
        return {
            "schema": "o1-256-privileged-target-teacher-v1",
            "target_key_hex": _key(self.target_key, "target_key").hex(),
            "target_trace_summaries": [
                trace.compact_summary() for trace in self.target_traces
            ],
            "deployment_input": False,
        }


@dataclass(frozen=True)
class KnownTarget:
    public: PublicTargetView
    teacher: KnownTargetTeacher

    def validate(self) -> None:
        self.teacher.validate_against(self.public)


def build_known_target(
    key: bytes,
    *,
    counter: int,
    nonce: bytes,
    block_count: int = 1,
) -> KnownTarget:
    key = _key(key)
    counter = _counter(counter)
    nonce = _nonce(nonce)
    if not isinstance(block_count, int) or isinstance(block_count, bool):
        raise LivingInverseError("block_count must be an integer")
    if not 1 <= block_count <= 16:
        raise LivingInverseError("block_count must be in [1, 16]")
    if counter + block_count - 1 > UINT32_MASK:
        raise LivingInverseError("counter schedule wraps uint32")
    counters = tuple(counter + index for index in range(block_count))
    traces = tuple(chacha20_block_trace(key, value, nonce) for value in counters)
    public = PublicTargetView(
        counter_schedule=counters,
        nonce=nonce,
        output_blocks=tuple(trace.output for trace in traces),
    )
    result = KnownTarget(
        public=public,
        teacher=KnownTargetTeacher(target_key=key, target_traces=traces),
    )
    result.validate()
    return result


class ContrastFamily(str, Enum):
    SINGLE_BIT = "single_bit"
    GRAY_WINDOW = "gray_window"
    REPEATED_WORD = "repeated_word"
    LOW_COMPLEXITY = "low_complexity"
    POSTERIOR_SAMPLE = "posterior_sample"
    UNIFORM_RANDOM = "uniform_random"


def _seeded_rng(seed: int, step: int, family: ContrastFamily) -> random.Random:
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise LivingInverseError("seed must be an integer")
    if not isinstance(step, int) or isinstance(step, bool) or step < 0:
        raise LivingInverseError("step must be a non-negative integer")
    material = canonical_json_bytes([seed, step, family.value])
    return random.Random(int.from_bytes(hashlib.sha256(material).digest(), "big"))


def propose_contrast_key(
    anchor_key: bytes,
    family: ContrastFamily,
    *,
    seed: int,
    step: int,
    posterior_probabilities: Sequence[float] | None = None,
) -> bytes:
    """Generate an attacker-computable proposal around one declared anchor."""

    anchor = bytearray(_key(anchor_key, "anchor_key"))
    if not isinstance(family, ContrastFamily):
        raise LivingInverseError("family must be ContrastFamily")
    rng = _seeded_rng(seed, step, family)

    if family is ContrastFamily.SINGLE_BIT:
        coordinate = rng.randrange(KEY_BITS)
        anchor[coordinate // 8] ^= 1 << (coordinate % 8)
        return bytes(anchor)

    if family is ContrastFamily.GRAY_WINDOW:
        start = rng.randrange(KEY_BITS)
        local = (step + 1) & ((1 << 12) - 1)
        gray = local ^ (local >> 1)
        if gray == 0:
            gray = 1
        for offset in range(12):
            if (gray >> offset) & 1:
                coordinate = (start + offset) % KEY_BITS
                anchor[coordinate // 8] ^= 1 << (coordinate % 8)
        return bytes(anchor)

    if family is ContrastFamily.REPEATED_WORD:
        word = rng.getrandbits(32).to_bytes(4, "little")
        return word * 8

    if family is ContrastFamily.LOW_COMPLEXITY:
        patterns = (
            bytes(KEY_BYTES),
            bytes([0xFF]) * KEY_BYTES,
            bytes([0xAA]) * KEY_BYTES,
            bytes([0x55]) * KEY_BYTES,
            bytes(range(KEY_BYTES)),
            bytes(reversed(range(KEY_BYTES))),
        )
        pattern = patterns[step % len(patterns)]
        rotation = rng.randrange(KEY_BYTES)
        return pattern[rotation:] + pattern[:rotation]

    if family is ContrastFamily.POSTERIOR_SAMPLE:
        if posterior_probabilities is None:
            raise LivingInverseError("posterior_sample requires probabilities")
        probabilities = _probabilities(posterior_probabilities)
        sampled = [int(rng.random() < float(value)) for value in probabilities]
        return bits_to_key(sampled)

    if family is ContrastFamily.UNIFORM_RANDOM:
        return bytes(rng.getrandbits(8) for _ in range(KEY_BYTES))

    raise AssertionError(f"unhandled contrast family: {family}")


@dataclass(frozen=True)
class DeploymentContrast:
    """An attacker-valid event; target labels cannot be represented here."""

    target: PublicTargetView
    candidate_key: bytes
    candidate: PublicTargetView
    candidate_traces: tuple[ChaChaBlockTrace, ...]
    family: ContrastFamily
    sequence: int

    def validate(self) -> None:
        self.target.validate()
        self.candidate.validate()
        _key(self.candidate_key, "candidate_key")
        if not isinstance(self.family, ContrastFamily):
            raise LivingInverseError("family must be ContrastFamily")
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 0
        ):
            raise LivingInverseError("sequence must be a non-negative integer")
        if (
            self.target.counter_schedule != self.candidate.counter_schedule
            or self.target.nonce != self.candidate.nonce
        ):
            raise LivingInverseError("candidate must use the target public relation")
        if len(self.candidate_traces) != self.candidate.block_count:
            raise LivingInverseError("candidate trace count differs")
        for index, (trace, counter, output) in enumerate(
            zip(
                self.candidate_traces,
                self.candidate.counter_schedule,
                self.candidate.output_blocks,
                strict=True,
            )
        ):
            expected = chacha20_block_trace(
                self.candidate_key, counter, self.candidate.nonce
            )
            if trace.digest() != expected.digest() or output != trace.output:
                raise LivingInverseError(f"candidate trace {index} differs")

    def describe(self) -> dict[str, object]:
        self.validate()
        return {
            "schema": "o1-256-deployment-contrast-v1",
            "target": self.target.describe(),
            "candidate_key_hex": self.candidate_key.hex(),
            "candidate": self.candidate.describe(),
            "candidate_trace_summaries": [
                trace.compact_summary() for trace in self.candidate_traces
            ],
            "family": self.family.value,
            "sequence": self.sequence,
            "target_key_included": False,
            "target_trace_included": False,
        }


@dataclass(frozen=True)
class TrainingContrast:
    deployment: DeploymentContrast
    correction_bits: tuple[int, ...]
    privileged_target_trace_digests: tuple[str, ...]

    def validate(self, target: KnownTarget) -> None:
        target.validate()
        self.deployment.validate()
        if self.deployment.target.digest() != target.public.digest():
            raise LivingInverseError("training contrast belongs to another target")
        expected = tuple(
            int(left != right)
            for left, right in zip(
                key_bits(target.teacher.target_key),
                key_bits(self.deployment.candidate_key),
                strict=True,
            )
        )
        if self.correction_bits != expected:
            raise LivingInverseError("training correction bits differ")
        expected_digests = tuple(
            trace.digest() for trace in target.teacher.target_traces
        )
        if self.privileged_target_trace_digests != expected_digests:
            raise LivingInverseError("privileged target trace digests differ")

    def describe_labels(self) -> dict[str, object]:
        return {
            "schema": "o1-256-training-contrast-labels-v1",
            "correction_bits": list(self.correction_bits),
            "privileged_target_trace_digests": list(
                self.privileged_target_trace_digests
            ),
            "deployment_input": False,
        }


def make_deployment_contrast(
    target: PublicTargetView,
    candidate_key: bytes,
    *,
    family: ContrastFamily,
    sequence: int,
) -> DeploymentContrast:
    target.validate()
    candidate_key = _key(candidate_key, "candidate_key")
    traces = tuple(
        chacha20_block_trace(candidate_key, counter, target.nonce)
        for counter in target.counter_schedule
    )
    candidate = PublicTargetView(
        counter_schedule=target.counter_schedule,
        nonce=target.nonce,
        output_blocks=tuple(trace.output for trace in traces),
    )
    result = DeploymentContrast(
        target=target,
        candidate_key=candidate_key,
        candidate=candidate,
        candidate_traces=traces,
        family=family,
        sequence=sequence,
    )
    result.validate()
    return result


def make_training_contrast(
    target: KnownTarget,
    *,
    family: ContrastFamily,
    seed: int,
    sequence: int,
    anchor_key: bytes,
    posterior_probabilities: Sequence[float] | None = None,
) -> TrainingContrast:
    target.validate()
    anchor = _key(anchor_key, "anchor_key")
    candidate_key = propose_contrast_key(
        anchor,
        family,
        seed=seed,
        step=sequence,
        posterior_probabilities=posterior_probabilities,
    )
    deployment = make_deployment_contrast(
        target.public,
        candidate_key,
        family=family,
        sequence=sequence,
    )
    result = TrainingContrast(
        deployment=deployment,
        correction_bits=tuple(
            int(left != right)
            for left, right in zip(
                key_bits(target.teacher.target_key),
                key_bits(candidate_key),
                strict=True,
            )
        ),
        privileged_target_trace_digests=tuple(
            trace.digest() for trace in target.teacher.target_traces
        ),
    )
    result.validate(target)
    return result


def _block_bits(blocks: Iterable[bytes]) -> np.ndarray:
    payload = b"".join(blocks)
    return np.unpackbits(
        np.frombuffer(payload, dtype=np.uint8), bitorder="little"
    ).astype(np.float32, copy=False)


def public_target_feature_vector(target: PublicTargetView) -> np.ndarray:
    """Encode only the public target relation for a direct inverse reader."""

    target.validate()
    public_payload = target.nonce + b"".join(
        struct.pack("<I", counter) for counter in target.counter_schedule
    )
    public_bits = np.unpackbits(
        np.frombuffer(public_payload, dtype=np.uint8), bitorder="little"
    ).astype(np.float32, copy=False)
    result = np.concatenate((_block_bits(target.output_blocks), public_bits)).astype(
        np.float32, copy=False
    )
    if not np.all(np.isfinite(result)):
        raise LivingInverseError("public target features must be finite")
    return result


def deployment_feature_vector(contrast: DeploymentContrast) -> np.ndarray:
    """Return a fixed public/candidate feature vector with no target trace."""

    contrast.validate()
    target_bits = _block_bits(contrast.target.output_blocks)
    candidate_bits = _block_bits(contrast.candidate.output_blocks)
    residual_bits = np.not_equal(target_bits, candidate_bits).astype(np.float32)
    candidate_key_bits = key_bits(contrast.candidate_key).astype(np.float32)
    public_payload = contrast.target.nonce + b"".join(
        struct.pack("<I", counter) for counter in contrast.target.counter_schedule
    )
    public_bits = np.unpackbits(
        np.frombuffer(public_payload, dtype=np.uint8), bitorder="little"
    ).astype(np.float32, copy=False)

    trace_features: list[float] = []
    for trace in contrast.candidate_traces:
        for state in trace.round_states[1:]:
            trace_features.extend(word.bit_count() / 32.0 for word in state)
        for row in trace.round_carry_masks:
            trace_features.extend(mask.bit_count() / 32.0 for mask in row)
        trace_features.extend(
            mask.bit_count() / 32.0 for mask in trace.feedforward_carry_masks
        )

    result = np.concatenate(
        (
            target_bits,
            candidate_bits,
            residual_bits,
            candidate_key_bits,
            public_bits,
            np.asarray(trace_features, dtype=np.float32),
        )
    ).astype(np.float32, copy=False)
    if not np.all(np.isfinite(result)):
        raise LivingInverseError("deployment features must be finite")
    return result


def make_output_flip_control(target: PublicTargetView, bit_index: int) -> PublicTargetView:
    target.validate()
    total_bits = target.block_count * BLOCK_BYTES * 8
    if (
        not isinstance(bit_index, int)
        or isinstance(bit_index, bool)
        or not 0 <= bit_index < total_bits
    ):
        raise LivingInverseError("output control bit is outside public output")
    blocks = [bytearray(block) for block in target.output_blocks]
    block_index, within = divmod(bit_index, BLOCK_BYTES * 8)
    blocks[block_index][within // 8] ^= 1 << (within % 8)
    result = PublicTargetView(
        counter_schedule=target.counter_schedule,
        nonce=target.nonce,
        output_blocks=tuple(bytes(block) for block in blocks),
    )
    result.validate()
    return result


def make_wrong_nonce_control(target: PublicTargetView, bit_index: int) -> PublicTargetView:
    target.validate()
    if (
        not isinstance(bit_index, int)
        or isinstance(bit_index, bool)
        or not 0 <= bit_index < NONCE_BYTES * 8
    ):
        raise LivingInverseError("nonce control bit is outside the nonce")
    nonce = bytearray(target.nonce)
    nonce[bit_index // 8] ^= 1 << (bit_index % 8)
    result = PublicTargetView(
        counter_schedule=target.counter_schedule,
        nonce=bytes(nonce),
        output_blocks=target.output_blocks,
    )
    result.validate()
    return result


def _probabilities(values: Sequence[float] | np.ndarray) -> np.ndarray:
    probabilities = np.asarray(values, dtype=np.float64)
    if probabilities.shape != (KEY_BITS,):
        raise LivingInverseError("posterior must contain exactly 256 probabilities")
    if not np.all(np.isfinite(probabilities)) or np.any(
        (probabilities <= 0.0) | (probabilities >= 1.0)
    ):
        raise LivingInverseError("posterior probabilities must be finite in (0, 1)")
    return probabilities


def _factorized_score(bits: np.ndarray, probabilities: np.ndarray) -> np.ndarray:
    log_one = np.log(probabilities)
    log_zero = np.log1p(-probabilities)
    # ``where`` avoids multiplying exact zero bits by large log terms and also
    # avoids platform BLAS floating-status leakage observed in tiny score batches.
    return np.sum(
        np.where(bits >= 0.5, log_one, log_zero), axis=-1, dtype=np.float64
    )


def _block_rank(
    truth: np.ndarray, probabilities: np.ndarray, start: int, width: int
) -> int:
    count = 1 << width
    values = np.arange(count, dtype=np.uint32)
    positions = np.arange(width, dtype=np.uint32)
    bits = ((values[:, None] >> positions) & 1).astype(np.float64)
    local_probabilities = probabilities[start : start + width]
    scores = _factorized_score(bits, local_probabilities)
    true_value = sum(int(truth[start + offset]) << offset for offset in range(width))
    true_score = float(scores[true_value])
    tolerance = 1e-12
    greater = int(np.count_nonzero(scores > true_score + tolerance))
    tied_before = int(
        np.count_nonzero(
            (np.abs(scores[:true_value] - true_score) <= tolerance)
        )
    )
    return 1 + greater + tied_before


def factorized_decoy_rank(
    true_key: bytes,
    probabilities: Sequence[float] | np.ndarray,
    *,
    decoy_count: int,
    seed: int,
    chunk_size: int = 4096,
) -> int:
    true_key = _key(true_key, "true_key")
    probabilities_array = _probabilities(probabilities)
    if (
        not isinstance(decoy_count, int)
        or isinstance(decoy_count, bool)
        or decoy_count < 0
    ):
        raise LivingInverseError("decoy_count must be a non-negative integer")
    if (
        not isinstance(chunk_size, int)
        or isinstance(chunk_size, bool)
        or chunk_size < 1
    ):
        raise LivingInverseError("chunk_size must be positive")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise LivingInverseError("seed must be an integer")

    truth = key_bits(true_key).astype(np.float64)
    true_score = float(_factorized_score(truth[None, :], probabilities_array)[0])
    rng = np.random.default_rng(seed)
    greater = 0
    tied_before = 0
    produced = 0
    tolerance = 1e-12
    while produced < decoy_count:
        count = min(chunk_size, decoy_count - produced)
        raw = rng.integers(0, 256, size=(count, KEY_BYTES), dtype=np.uint8)
        bits = np.unpackbits(raw, axis=1, bitorder="little").astype(np.float64)
        scores = _factorized_score(bits, probabilities_array)
        greater += int(np.count_nonzero(scores > true_score + tolerance))
        tied = np.abs(scores - true_score) <= tolerance
        for row in raw[tied]:
            if row.tobytes() < true_key:
                tied_before += 1
        produced += count
    return 1 + greater + tied_before


def uncertainty_beam_metrics(
    true_key: bytes,
    probabilities: Sequence[float] | np.ndarray,
    *,
    uncertain_bits: int = 16,
    beam_size: int = 65536,
) -> dict[str, object]:
    true_key = _key(true_key, "true_key")
    probabilities_array = _probabilities(probabilities)
    if (
        not isinstance(uncertain_bits, int)
        or isinstance(uncertain_bits, bool)
        or not 0 <= uncertain_bits <= 20
    ):
        raise LivingInverseError("uncertain_bits must be in [0, 20]")
    if (
        not isinstance(beam_size, int)
        or isinstance(beam_size, bool)
        or beam_size < 1
    ):
        raise LivingInverseError("beam_size must be positive")

    truth = key_bits(true_key).astype(np.uint8)
    mode = (probabilities_array >= 0.5).astype(np.uint8)
    confidence = np.abs(probabilities_array - 0.5)
    uncertain = np.argsort(confidence, kind="stable")[:uncertain_bits]
    fixed_mask = np.ones(KEY_BITS, dtype=bool)
    fixed_mask[uncertain] = False
    fixed_errors = int(np.count_nonzero(mode[fixed_mask] != truth[fixed_mask]))

    count = 1 << uncertain_bits
    values = np.arange(count, dtype=np.uint32)
    positions = np.arange(uncertain_bits, dtype=np.uint32)
    assignments = ((values[:, None] >> positions) & 1).astype(np.float64)
    scores = _factorized_score(assignments, probabilities_array[uncertain])
    order = np.argsort(-scores, kind="stable")
    true_local_value = sum(
        int(truth[coordinate]) << offset
        for offset, coordinate in enumerate(uncertain)
    )
    local_rank = int(np.flatnonzero(order == true_local_value)[0]) + 1
    exact_possible = fixed_errors == 0
    return {
        "uncertain_bits": uncertain_bits,
        "beam_size": min(beam_size, count),
        "uncertain_coordinates": [int(value) for value in uncertain],
        "fixed_bit_errors": fixed_errors,
        "best_hamming_distance": fixed_errors,
        "true_local_rank": local_rank if exact_possible else None,
        "exact_key_in_beam": exact_possible and local_rank <= min(beam_size, count),
    }


def posterior_metrics(
    true_key: bytes,
    probabilities: Sequence[float] | np.ndarray,
    *,
    confidence_threshold: float = 0.75,
    decoy_count: int = 0,
    decoy_seed: int = 0,
    beam_uncertain_bits: int = 16,
    beam_size: int = 65536,
) -> dict[str, object]:
    """Measure progress without requiring exact 256-bit recovery."""

    true_key = _key(true_key, "true_key")
    probabilities_array = _probabilities(probabilities)
    if (
        isinstance(confidence_threshold, bool)
        or not isinstance(confidence_threshold, (int, float))
        or not math.isfinite(float(confidence_threshold))
        or not 0.5 < float(confidence_threshold) < 1.0
    ):
        raise LivingInverseError("confidence_threshold must be in (0.5, 1)")

    truth = key_bits(true_key).astype(np.uint8)
    selected = np.where(truth == 1, probabilities_array, 1.0 - probabilities_array)
    key_nll_bits = float(-np.log2(selected).sum())
    prediction = (probabilities_array >= 0.5).astype(np.uint8)
    confidence = np.maximum(probabilities_array, 1.0 - probabilities_array)
    confident = confidence >= float(confidence_threshold)
    confident_count = int(np.count_nonzero(confident))
    confident_correct = int(np.count_nonzero((prediction == truth) & confident))

    byte_ranks = [
        _block_rank(truth, probabilities_array, start, 8)
        for start in range(0, KEY_BITS, 8)
    ]
    word16_ranks = [
        _block_rank(truth, probabilities_array, start, 16)
        for start in range(0, KEY_BITS, 16)
    ]
    probability_payload = probabilities_array.astype("<f8", copy=False).tobytes()
    beam = uncertainty_beam_metrics(
        true_key,
        probabilities_array,
        uncertain_bits=beam_uncertain_bits,
        beam_size=beam_size,
    )
    result = {
        "schema": "o1-256-posterior-metrics-v1",
        "key_nll_bits": key_nll_bits,
        "random_baseline_nll_bits": float(KEY_BITS),
        "effective_compression_bits": float(KEY_BITS - key_nll_bits),
        "bit_accuracy": float(np.mean(prediction == truth)),
        "hamming_distance": int(np.count_nonzero(prediction != truth)),
        "confidence_threshold": float(confidence_threshold),
        "confident_bits": confident_count,
        "confident_correct_bits": confident_correct,
        "confident_precision": (
            float(confident_correct / confident_count) if confident_count else None
        ),
        "byte_ranks": byte_ranks,
        "byte_geometric_mean_rank": float(
            math.exp(sum(math.log(value) for value in byte_ranks) / len(byte_ranks))
        ),
        "word16_ranks": word16_ranks,
        "word16_geometric_mean_rank": float(
            math.exp(
                sum(math.log(value) for value in word16_ranks) / len(word16_ranks)
            )
        ),
        "decoy_count": decoy_count,
        "full_key_rank_among_decoys": factorized_decoy_rank(
            true_key,
            probabilities_array,
            decoy_count=decoy_count,
            seed=decoy_seed,
        ),
        "beam": beam,
        "posterior_sha256": hashlib.sha256(probability_payload).hexdigest(),
    }
    return result
