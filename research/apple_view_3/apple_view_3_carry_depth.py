#!/usr/bin/env python3
"""Global carry-depth diagnosis for one full ChaCha20 block.

For each 32-bit addition, carries c1..c_d use the real majority recurrence.
Higher carries are UNKNOWN.  A three-valued evaluator then forwards this exact
partial knowledge through all 20 rounds and the final feed-forward addition.

If a determined output bit disagrees with the public block, that complete
256-bit probe key is rigorously impossible.  An UNKNOWN/surviving probe is not
claimed SAT: the abstraction intentionally performs no backward reasoning.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import platform
import resource
import struct
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence


MASK32 = (1 << 32) - 1
KEY_BITS = 256
OUTPUT_BITS = 512
ADDITIONS_PER_BLOCK = 336
UNKNOWN = -1
ZERO = 0
ONE = 1
CONSTANT_WORDS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
DEFAULT_SEED = "apple-view-3-global-carry-depth-v1-20260719"
DEFAULT_PROBES = 32
CPU_BUDGET_SECONDS = 30.0
MEMORY_BUDGET_BYTES = 128 * 1024 * 1024
APPLE_VIEW_3_DIR = Path(__file__).resolve().parent

RFC_KEY = bytes(range(32))
RFC_NONCE = bytes.fromhex("000000090000004a00000000")
RFC_BLOCK = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)

TriBit = int
TriWord = tuple[TriBit, ...]


@dataclass(frozen=True)
class ExperimentConfig:
    seed: str = DEFAULT_SEED
    probes: int = DEFAULT_PROBES
    min_depth: int = 0
    max_depth: int = 31

    def validate(self) -> None:
        if not self.seed:
            raise ValueError("seed must not be empty")
        if not 1 <= self.probes <= 65_536:
            raise ValueError("probes must be in [1, 65536]")
        if not 0 <= self.min_depth <= self.max_depth <= 31:
            raise ValueError("carry depths must satisfy 0 <= min <= max <= 31")


@dataclass
class WorkMeter:
    abstract_block_evaluations: int = 0
    abstract_word_additions: int = 0
    abstract_carry_recurrences: int = 0
    abstract_xor_bits: int = 0
    output_bits_compared: int = 0
    concrete_block_evaluations: int = 0


@dataclass(frozen=True)
class PublicTarget:
    counter: int
    nonce: bytes
    block: bytes

    def validate(self) -> None:
        if not 0 <= self.counter <= MASK32:
            raise ValueError("counter must be uint32")
        if len(self.nonce) != 12:
            raise ValueError("nonce must be exactly 12 bytes")
        if len(self.block) != 64:
            raise ValueError("block must be exactly 64 bytes")


def _derive(seed: str, label: str, index: int, length: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(seed.encode("utf-8"))
    shake.update(b"\x00")
    shake.update(label.encode("ascii"))
    shake.update(index.to_bytes(8, "little", signed=False))
    return shake.digest(length)


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & MASK32) | (value >> (32 - distance))


def _quarter_round_concrete(
    state: list[int], a: int, b: int, c: int, d: int
) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _initial_words(key: bytes, counter: int, nonce: bytes) -> tuple[int, ...]:
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be uint32")
    if len(nonce) != 12:
        raise ValueError("nonce must be exactly 12 bytes")
    return (
        *CONSTANT_WORDS,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    )


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    initial = _initial_words(key, counter, nonce)
    state = list(initial)
    for _ in range(10):
        _quarter_round_concrete(state, 0, 4, 8, 12)
        _quarter_round_concrete(state, 1, 5, 9, 13)
        _quarter_round_concrete(state, 2, 6, 10, 14)
        _quarter_round_concrete(state, 3, 7, 11, 15)
        _quarter_round_concrete(state, 0, 5, 10, 15)
        _quarter_round_concrete(state, 1, 6, 11, 12)
        _quarter_round_concrete(state, 2, 7, 8, 13)
        _quarter_round_concrete(state, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *((word + base) & MASK32 for word, base in zip(state, initial))
    )


def generate_target(config: ExperimentConfig) -> tuple[PublicTarget, bytes]:
    """Return one fixed unsealed build target; never a fresh/sealed challenge."""

    key = _derive(config.seed, "measurement-key", 0, 32)
    nonce = _derive(config.seed, "public-nonce", 0, 12)
    counter = int.from_bytes(_derive(config.seed, "public-counter", 0, 4), "little")
    return PublicTarget(counter, nonce, chacha20_block(key, counter, nonce)), key


def generate_probe_keys(config: ExperimentConfig) -> tuple[bytes, ...]:
    """Generate a fixed complete-key probe set without target or truth input."""

    return tuple(
        _derive(config.seed, "output-independent-probe-key", index, 32)
        for index in range(config.probes)
    )


def _tribit(value: int) -> TriBit:
    if value not in (UNKNOWN, ZERO, ONE):
        raise ValueError("tri-bit must be UNKNOWN, ZERO, or ONE")
    return value


def tri_xor(left: TriBit, right: TriBit) -> TriBit:
    _tribit(left)
    _tribit(right)
    if left == UNKNOWN or right == UNKNOWN:
        return UNKNOWN
    return left ^ right


def tri_majority(a: TriBit, b: TriBit, c: TriBit) -> TriBit:
    """Exact abstract majority: known iff all concrete completions agree."""

    _tribit(a)
    _tribit(b)
    _tribit(c)
    known = [value for value in (a, b, c) if value != UNKNOWN]
    if known.count(ZERO) >= 2:
        return ZERO
    if known.count(ONE) >= 2:
        return ONE
    if len(known) == 3:
        raise AssertionError("three concrete majority inputs must have a majority")
    return UNKNOWN


def concrete_word(value: int) -> TriWord:
    if not 0 <= value <= MASK32:
        raise ValueError("word must be uint32")
    return tuple((value >> bit) & 1 for bit in range(32))


def tri_xor_words(
    left: TriWord, right: TriWord, meter: WorkMeter | None = None
) -> TriWord:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("tri-words must contain exactly 32 bits")
    if meter is not None:
        meter.abstract_xor_bits += 32
    return tuple(tri_xor(a, b) for a, b in zip(left, right, strict=True))


def tri_rotl_word(word: TriWord, distance: int) -> TriWord:
    if len(word) != 32 or not 0 < distance < 32:
        raise ValueError("invalid abstract word rotation")
    return word[-distance:] + word[:-distance]


def tri_add_words(
    left: TriWord,
    right: TriWord,
    carry_depth: int,
    meter: WorkMeter | None = None,
) -> TriWord:
    """Add with c1..c_depth exact and all subsequent carries unknown."""

    if len(left) != 32 or len(right) != 32:
        raise ValueError("tri-words must contain exactly 32 bits")
    if not 0 <= carry_depth <= 31:
        raise ValueError("carry_depth must be in [0,31]")
    if meter is not None:
        meter.abstract_word_additions += 1
    carry = ZERO
    output: list[TriBit] = []
    for bit, (a, b) in enumerate(zip(left, right, strict=True)):
        output.append(tri_xor(tri_xor(a, b), carry))
        if bit == 31:
            continue
        if bit < carry_depth:
            carry = tri_majority(a, b, carry)
            if meter is not None:
                meter.abstract_carry_recurrences += 1
        else:
            carry = UNKNOWN
    return tuple(output)


def _quarter_round_abstract(
    state: list[TriWord],
    a: int,
    b: int,
    c: int,
    d: int,
    carry_depth: int,
    meter: WorkMeter | None,
) -> None:
    state[a] = tri_add_words(state[a], state[b], carry_depth, meter)
    state[d] = tri_rotl_word(tri_xor_words(state[d], state[a], meter), 16)
    state[c] = tri_add_words(state[c], state[d], carry_depth, meter)
    state[b] = tri_rotl_word(tri_xor_words(state[b], state[c], meter), 12)
    state[a] = tri_add_words(state[a], state[b], carry_depth, meter)
    state[d] = tri_rotl_word(tri_xor_words(state[d], state[a], meter), 8)
    state[c] = tri_add_words(state[c], state[d], carry_depth, meter)
    state[b] = tri_rotl_word(tri_xor_words(state[b], state[c], meter), 7)


def _known_state_bits(state: Sequence[TriWord]) -> int:
    return sum(bit != UNKNOWN for word in state for bit in word)


def _abstract_chacha20_evaluate(
    key: bytes,
    counter: int,
    nonce: bytes,
    carry_depth: int,
    meter: WorkMeter | None = None,
) -> tuple[tuple[TriBit, ...], tuple[int, ...], tuple[int, ...]]:
    """Return abstract output plus known-state counts after each double round."""

    initial_words = _initial_words(key, counter, nonce)
    initial = [concrete_word(word) for word in initial_words]
    state = list(initial)
    known_profile = [_known_state_bits(state)]
    first_double_round_quarter_profile: list[int] = []
    additions_before = meter.abstract_word_additions if meter is not None else 0
    quarter_schedule = (
        (0, 4, 8, 12),
        (1, 5, 9, 13),
        (2, 6, 10, 14),
        (3, 7, 11, 15),
        (0, 5, 10, 15),
        (1, 6, 11, 12),
        (2, 7, 8, 13),
        (3, 4, 9, 14),
    )
    for double_round in range(10):
        for a, b, c, d in quarter_schedule:
            _quarter_round_abstract(state, a, b, c, d, carry_depth, meter)
            if double_round == 0:
                first_double_round_quarter_profile.append(_known_state_bits(state))
        known_profile.append(_known_state_bits(state))
    output_words = [
        tri_add_words(word, base, carry_depth, meter)
        for word, base in zip(state, initial, strict=True)
    ]
    if meter is not None:
        if meter.abstract_word_additions - additions_before != ADDITIONS_PER_BLOCK:
            raise AssertionError("full abstract block must execute 336 additions")
        meter.abstract_block_evaluations += 1
    output = tuple(bit for word in output_words for bit in word)
    known_profile.append(sum(bit != UNKNOWN for bit in output))
    return (
        output,
        tuple(known_profile),
        tuple(first_double_round_quarter_profile),
    )


def abstract_chacha20_block(
    key: bytes,
    counter: int,
    nonce: bytes,
    carry_depth: int,
    meter: WorkMeter | None = None,
) -> tuple[TriBit, ...]:
    """Forward the globally restored carry depth through all 20 rounds."""

    output, _, _ = _abstract_chacha20_evaluate(
        key, counter, nonce, carry_depth, meter
    )
    return output


def _block_bits(block: bytes) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("block must be exactly 64 bytes")
    return tuple((byte >> bit) & 1 for byte in block for bit in range(8))


def _score_abstract_output(
    abstract: Sequence[TriBit], target: PublicTarget, meter: WorkMeter | None
) -> dict[str, object]:
    if len(abstract) != OUTPUT_BITS:
        raise ValueError("abstract block must contain exactly 512 bits")
    observed = _block_bits(target.block)
    determined_indices = [
        index for index, value in enumerate(abstract) if value != UNKNOWN
    ]
    mismatched_indices = [
        index
        for index in determined_indices
        if abstract[index] != observed[index]
    ]
    if meter is not None:
        meter.output_bits_compared += len(determined_indices)
    return {
        "determined_output_bits": len(determined_indices),
        "mismatched_determined_output_bits": len(mismatched_indices),
        "rejected_exactly": bool(mismatched_indices),
        "first_mismatched_output_bit": (
            mismatched_indices[0] if mismatched_indices else None
        ),
    }


def score_probe(
    target: PublicTarget,
    candidate_key: bytes,
    carry_depth: int,
    meter: WorkMeter | None = None,
) -> dict[str, object]:
    """Return a sound one-sided rejection using public data and a probe key."""

    target.validate()
    abstract = abstract_chacha20_block(
        candidate_key, target.counter, target.nonce, carry_depth, meter
    )
    return _score_abstract_output(abstract, target, meter)


def validate_abstract_adder(seed: str, checks_per_depth: int = 64) -> int:
    """Exhaust deterministic concrete additions against every abstract depth."""

    checks = 0
    for depth in range(32):
        for index in range(checks_per_depth):
            material = _derive(
                seed,
                "abstract-adder-check",
                depth * checks_per_depth + index,
                8,
            )
            left, right = struct.unpack("<2I", material)
            abstract = tri_add_words(concrete_word(left), concrete_word(right), depth)
            concrete = (left + right) & MASK32
            for bit, value in enumerate(abstract):
                if value != UNKNOWN and value != ((concrete >> bit) & 1):
                    raise AssertionError("abstract addition emitted an unsound bit")
            expected_known = 32 if depth == 31 else depth + 1
            if sum(value != UNKNOWN for value in abstract) != expected_known:
                raise AssertionError("concrete-input abstract adder has wrong known prefix")
            checks += 1
    return checks


def _max_rss_bytes(raw_value: int) -> int:
    return raw_value if sys.platform == "darwin" else raw_value * 1024


def run_experiment(config: ExperimentConfig = ExperimentConfig()) -> dict[str, object]:
    config.validate()
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    tracemalloc.start()
    meter = WorkMeter()

    if chacha20_block(RFC_KEY, 1, RFC_NONCE) != RFC_BLOCK:
        raise AssertionError("local implementation does not reproduce RFC 8439")
    meter.concrete_block_evaluations += 1
    adder_checks = validate_abstract_adder(config.seed)
    target, truth = generate_target(config)
    meter.concrete_block_evaluations += 1
    probes = generate_probe_keys(config)
    if truth in probes:
        raise AssertionError("fixed probe set unexpectedly contains measurement key")

    depth_rows: list[dict[str, object]] = []
    probe_first_rejection: list[int | None] = [None] * len(probes)
    for depth in range(config.min_depth, config.max_depth + 1):
        truth_abstract, truth_profile, truth_first_double_round_profile = (
            _abstract_chacha20_evaluate(
                truth, target.counter, target.nonce, depth, meter
            )
        )
        truth_score = _score_abstract_output(truth_abstract, target, meter)
        if truth_score["rejected_exactly"]:
            raise AssertionError("sound abstraction rejected the true key")
        probe_scores = [score_probe(target, key, depth, meter) for key in probes]
        rejected = sum(bool(row["rejected_exactly"]) for row in probe_scores)
        for index, row in enumerate(probe_scores):
            if row["rejected_exactly"] and probe_first_rejection[index] is None:
                probe_first_rejection[index] = depth
        determined = [int(row["determined_output_bits"]) for row in probe_scores]
        mismatches = [
            int(row["mismatched_determined_output_bits"]) for row in probe_scores
        ]
        depth_rows.append(
            {
                "carry_depth": depth,
                "exact_carry_recurrences_per_block": ADDITIONS_PER_BLOCK * depth,
                "independent_carries_remaining_per_block": (
                    ADDITIONS_PER_BLOCK * (31 - depth)
                ),
                "truth_determined_output_bits": int(
                    truth_score["determined_output_bits"]
                ),
                "truth_mismatched_determined_output_bits": 0,
                "truth_known_state_bits_initial": truth_profile[0],
                "truth_known_state_bits_during_first_double_round": list(
                    truth_first_double_round_profile
                ),
                "truth_known_state_bits_after_each_double_round": list(
                    truth_profile[1:11]
                ),
                "truth_known_output_bits_after_feed_forward": truth_profile[11],
                "probe_keys": len(probes),
                "probe_keys_rejected_exactly": rejected,
                "probe_keys_not_rejected": len(probes) - rejected,
                "probe_rejection_fraction": rejected / len(probes),
                "determined_output_bits_min": min(determined),
                "determined_output_bits_max": max(determined),
                "determined_output_bits_mean": sum(determined) / len(determined),
                "mismatched_determined_output_bits_total": sum(mismatches),
            }
        )

    first_any = next(
        (
            int(row["carry_depth"])
            for row in depth_rows
            if int(row["probe_keys_rejected_exactly"]) > 0
        ),
        None,
    )
    first_all = next(
        (
            int(row["carry_depth"])
            for row in depth_rows
            if int(row["probe_keys_rejected_exactly"]) == len(probes)
        ),
        None,
    )
    first_rejection_histogram = {
        str(depth): sum(value == depth for value in probe_first_rejection)
        for depth in range(config.min_depth, config.max_depth + 1)
        if any(value == depth for value in probe_first_rejection)
    }
    never_rejected = sum(value is None for value in probe_first_rejection)

    python_current, python_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    usage_after = resource.getrusage(resource.RUSAGE_SELF)
    max_rss = _max_rss_bytes(usage_after.ru_maxrss)
    budget_passed = cpu_seconds < CPU_BUDGET_SECONDS and max_rss < MEMORY_BUDGET_BYTES
    if not budget_passed:
        raise RuntimeError(
            f"resource budget exceeded: cpu={cpu_seconds:.6f}s rss={max_rss} bytes"
        )

    source_path = Path(__file__).resolve()
    test_path = source_path.with_name("apple_view_3_test_carry_depth.py")
    if not test_path.is_file():
        raise RuntimeError("reproduction test file is missing")

    result: dict[str, object] = {
        "schema": "apple-view-3-full256-global-carry-depth-v1",
        "started_at": started_at,
        "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hypothesis": (
            "globally restoring the real carry-majority recurrence from low to "
            "high bit positions makes some public output bits deterministic early "
            "enough to reject complete wrong 256-bit keys"
        ),
        "config": asdict(config),
        "attacker_boundary": {
            "primitive": "RFC 8439 ChaCha20 block, 20 rounds",
            "unknown_key_bits_in_base_problem": 256,
            "blocks_per_target": 1,
            "public_input": "constants + counter + 96-bit nonce + one 512-bit output",
            "truth_key_input_to_probe_scoring": False,
            "truth_key_input_to_probe_generation": False,
            "truth_key_role": "post-extraction soundness check only",
            "probe_keys_depend_on_public_output": False,
            "probe_keys_enumerate_search_space": False,
            "fresh_or_sealed_target": False,
            "reduced_round_result": False,
            "network_used": False,
            "gpu_or_mps_used": False,
        },
        "mechanism": {
            "sum_bit": "z_i = x_i XOR y_i XOR c_i",
            "restored_carry": (
                "c_(i+1) = majority(x_i, y_i, c_i) for i < carry_depth"
            ),
            "relaxed_carry": (
                "c_(i+1) = UNKNOWN independent abstraction for i >= carry_depth"
            ),
            "global_scope": "all 320 permutation additions plus all 16 feed-forward additions",
            "logic": (
                "strong three-valued forward evaluation; any known bit is equal "
                "for every completion of the remaining unknown carries"
            ),
            "one_sided_rule": (
                "known output mismatch proves key impossible; no mismatch does not prove SAT"
            ),
        },
        "target": {
            "source": "fixed SHAKE-256 build target, committed unsealed",
            "measurement_key_hex_unsealed": truth.hex(),
            "counter": target.counter,
            "nonce_hex": target.nonce.hex(),
            "block_hex": target.block.hex(),
            "public_target_sha256": hashlib.sha256(
                struct.pack("<I", target.counter) + target.nonce + target.block
            ).hexdigest(),
        },
        "validation": {
            "rfc8439_block_vector": True,
            "abstract_addition_checks": adder_checks,
            "depths_checked_per_abstract_addition": 32,
            "true_key_checked_at_every_depth": True,
            "true_key_rejections": 0,
            "score_probe_parameters": list(inspect.signature(score_probe).parameters),
            "exact_rejection_definition": (
                "at least one abstractly determined output bit disagrees with the public block"
            ),
        },
        "depth_results": depth_rows,
        "summary": {
            "first_depth_rejecting_any_probe": first_any,
            "first_depth_rejecting_all_probes": first_all,
            "probe_first_rejection_histogram": first_rejection_histogram,
            "probe_keys_never_rejected": never_rejected,
            "exact_full_key_recoveries": 0,
            "exact_key_bits_recovered": 0,
            "global_key_entropy_reduction_claimed_bits": 0,
        },
        "decision": (
            "carry depth is useful only from the first depth with exact probe "
            "rejections; retain that threshold as a low-cost branch filter, but "
            "do not interpret fixed-probe rejection rates as global key entropy"
        ),
        "artifact_hashes": {
            "apple_view_3_carry_depth.py": {
                "bytes": source_path.stat().st_size,
                "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            },
            "apple_view_3_test_carry_depth.py": {
                "bytes": test_path.stat().st_size,
                "sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
            },
        },
        "resources": {
            "cpu_budget_seconds": CPU_BUDGET_SECONDS,
            "memory_budget_bytes": MEMORY_BUDGET_BYTES,
            "budget_passed": budget_passed,
            "wall_seconds": wall_seconds,
            "cpu_seconds": cpu_seconds,
            "python_tracemalloc_current_bytes": python_current,
            "python_tracemalloc_peak_bytes": python_peak,
            "process_max_rss_bytes": max_rss,
            "minor_page_faults_delta": usage_after.ru_minflt - usage_before.ru_minflt,
            "major_page_faults_delta": usage_after.ru_majflt - usage_before.ru_majflt,
            **asdict(meter),
            "cpu_processes": 1,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
    }
    scientific_fields = {
        name: result[name]
        for name in (
            "schema",
            "hypothesis",
            "config",
            "attacker_boundary",
            "mechanism",
            "target",
            "validation",
            "depth_results",
            "summary",
            "decision",
        )
    }
    scientific_bytes = json.dumps(
        scientific_fields,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    result["reproducibility"] = {
        "scientific_payload_sha256": hashlib.sha256(scientific_bytes).hexdigest(),
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "dynamic_resource_fields_excluded_from_scientific_hash": True,
    }
    return result


def validated_output_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    resolved = candidate.resolve()
    if resolved.parent != APPLE_VIEW_3_DIR:
        raise ValueError("output must remain directly inside research/apple_view_3")
    if not resolved.name.startswith("apple_view_3_") or resolved.suffix != ".json":
        raise ValueError("output filename must match apple_view_3_*.json")
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the full-round global carry-depth abstraction diagnosis."
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--probes", type=int, default=DEFAULT_PROBES)
    parser.add_argument("--min-depth", type=int, default=0)
    parser.add_argument("--max-depth", type=int, default=31)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    output: Path | None = None
    if args.output is not None:
        try:
            output = validated_output_path(args.output)
        except ValueError as error:
            parser.error(str(error))
    result = run_experiment(
        ExperimentConfig(args.seed, args.probes, args.min_depth, args.max_depth)
    )
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
