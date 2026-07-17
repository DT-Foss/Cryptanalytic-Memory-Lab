"""Deterministic full-256 ChaCha20 CNF compiler and public-instance builder.

The template represents the complete RFC 8439 twenty-round block relation.  All
256 key bits, the public counter/nonce bits, and the 512 output bits have stable
interface variables; only a derived instance adds public unit clauses.  Internal
round values are compiler wires, never attacker inputs.

The compiler deliberately uses symmetric XOR and full-adder encodings.  They are
slightly larger than propagation-biased encodings, but make later paired-assumption
and proof-ancestry telemetry comparable between the two polarities of a key bit.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator, Protocol

from .chacha_trace import CHACHA20_ROUNDS, UINT32_MASK
from .living_inverse import canonical_json_bytes, canonical_sha256


KEY_FIRST_VARIABLE = 1
KEY_LAST_VARIABLE = 256
COUNTER_FIRST_VARIABLE = 257
COUNTER_LAST_VARIABLE = 288
NONCE_FIRST_VARIABLE = 289
NONCE_LAST_VARIABLE = 384
OUTPUT_FIRST_VARIABLE = 385
OUTPUT_LAST_VARIABLE = 896
INTERNAL_FIRST_VARIABLE = 897
PUBLIC_UNIT_CLAUSES = 32 + 96 + 512
TEMPLATE_SCHEMA = "o1-256-chacha20-cnf-template-v1"
INSTANCE_SCHEMA = "o1-256-chacha20-cnf-instance-v1"
GENERATOR_ID = "o1-full256-symmetric-ripple-v1"

Signal = bool | int
Clause = tuple[int, ...]


class Full256CNFError(ValueError):
    """Raised when a formula, sidecar, or attacker-visible instance differs."""


class ClauseSink(Protocol):
    clause_count: int
    max_variable: int
    length_histogram: Counter[int]

    def add(self, clause: Clause) -> None: ...


class _Digest(Protocol):
    def update(self, value: bytes) -> None: ...

    def hexdigest(self) -> str: ...


class CountingClauseSink:
    """Count a formula without retaining its clauses."""

    def __init__(self) -> None:
        self.clause_count = 0
        self.max_variable = 0
        self.length_histogram: Counter[int] = Counter()

    def add(self, clause: Clause) -> None:
        self.clause_count += 1
        self.length_histogram[len(clause)] += 1
        if clause:
            self.max_variable = max(
                self.max_variable, max(abs(literal) for literal in clause)
            )


class ClauseCollector(CountingClauseSink):
    """Small in-memory sink intended for exhaustive gate tests."""

    def __init__(self) -> None:
        super().__init__()
        self.clauses: list[Clause] = []

    def add(self, clause: Clause) -> None:
        super().add(clause)
        self.clauses.append(clause)


class _DimacsClauseSink(CountingClauseSink):
    def __init__(self, handle: IO[bytes], digest: _Digest) -> None:
        super().__init__()
        self._handle = handle
        self._digest = digest
        self.bytes_written = 0

    def add(self, clause: Clause) -> None:
        super().add(clause)
        row = (" ".join(str(literal) for literal in clause) + " 0\n").encode(
            "ascii"
        )
        self._handle.write(row)
        self._digest.update(row)
        self.bytes_written += len(row)


@dataclass(frozen=True)
class FormulaStats:
    variable_count: int
    clause_count: int
    clause_length_histogram: dict[str, int]
    operations: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class TemplateWriteReport:
    dimacs_path: str
    map_path: str
    dimacs_sha256: str
    map_file_sha256: str
    map_sha256: str
    variable_count: int
    clause_count: int
    dimacs_bytes: int
    operation_count: int


@dataclass(frozen=True)
class InstanceWriteReport:
    schema: str
    instance_path: str
    template_sha256: str
    template_map_sha256: str
    instance_sha256: str
    instance_bytes: int
    variable_count: int
    clause_count: int
    public_unit_clause_count: int
    public_unit_clause_sha256: str
    key_unit_clause_count: int
    key_unit_clause_sha256: str | None
    assumption_unit_clause_count: int
    assumption_unit_clause_sha256: str | None
    unit_clause_sha256: str
    assumptions: tuple[tuple[int, int], ...]
    key_fixed_for_self_test: bool
    fixed_key_sha256: str | None
    counter: int
    nonce_hex: str
    output_sha256: str

    def describe(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "template_sha256": self.template_sha256,
            "template_map_sha256": self.template_map_sha256,
            "instance_sha256": self.instance_sha256,
            "instance_bytes": self.instance_bytes,
            "variable_count": self.variable_count,
            "clause_count": self.clause_count,
            "public_unit_clause_count": self.public_unit_clause_count,
            "public_unit_clause_sha256": self.public_unit_clause_sha256,
            "key_unit_clause_count": self.key_unit_clause_count,
            "key_unit_clause_sha256": self.key_unit_clause_sha256,
            "assumption_unit_clause_count": self.assumption_unit_clause_count,
            "assumption_unit_clause_sha256": self.assumption_unit_clause_sha256,
            "unit_clause_sha256": self.unit_clause_sha256,
            "assumptions": [
                {"key_bit": bit, "value": value} for bit, value in self.assumptions
            ],
            "key_fixed_for_self_test": self.key_fixed_for_self_test,
            "fixed_key_sha256": self.fixed_key_sha256,
            "counter": self.counter,
            "nonce_hex": self.nonce_hex,
            "output_sha256": self.output_sha256,
        }


@dataclass(frozen=True)
class SolverReport:
    solver: str
    status: str
    returncode: int
    wall_seconds: float
    stdout: str
    stderr: str


def _negate(signal: Signal) -> Signal:
    if isinstance(signal, bool):
        return not signal
    return -signal


def _literal_truth(literal: int, assignment: Mapping[int, bool]) -> bool:
    value = bool(assignment[abs(literal)])
    return value if literal > 0 else not value


def clauses_satisfied(
    clauses: Iterable[Clause], assignment: Mapping[int, bool]
) -> bool:
    """Evaluate clauses under a complete assignment; useful for gate self-tests."""

    return all(any(_literal_truth(literal, assignment) for literal in row) for row in clauses)


class CNFBuilder:
    """Gate-level Tseitin builder with constant and literal folding."""

    def __init__(
        self,
        sink: ClauseSink,
        *,
        first_internal_variable: int = INTERNAL_FIRST_VARIABLE,
    ) -> None:
        if first_internal_variable < 1:
            raise Full256CNFError("first internal variable must be positive")
        self.sink = sink
        self.next_variable = first_internal_variable
        self.operations: list[dict[str, object]] = []

    def new_variable(self) -> int:
        result = self.next_variable
        self.next_variable += 1
        return result

    def clause(self, *signals: Signal) -> None:
        literals: set[int] = set()
        for signal in signals:
            if isinstance(signal, bool):
                if signal:
                    return
                continue
            if signal == 0:
                raise Full256CNFError("literal zero is reserved as DIMACS terminator")
            if -signal in literals:
                return
            literals.add(signal)
        # Sorting makes every generated byte independent of set/hash ordering.
        ordered = tuple(sorted(literals, key=lambda item: (abs(item), item < 0)))
        self.sink.add(ordered)

    @staticmethod
    def _normalize_parity(signals: Iterable[Signal]) -> tuple[list[int], bool]:
        parity = False
        counts: Counter[int] = Counter()
        for signal in signals:
            if isinstance(signal, bool):
                parity ^= signal
                continue
            if signal == 0:
                raise Full256CNFError("literal zero is not a signal")
            if signal < 0:
                parity = not parity
            counts[abs(signal)] += 1
        variables = sorted(variable for variable, count in counts.items() if count & 1)
        return variables, parity

    def _parity_zero(self, signals: Iterable[Signal]) -> None:
        variables, constant = self._normalize_parity(signals)
        if not variables:
            if constant:
                self.clause()
            return
        if len(variables) == 1:
            self.clause(variables[0] if constant else -variables[0])
            return
        for values in itertools.product((False, True), repeat=len(variables)):
            if (sum(values) & 1) == int(constant):
                continue
            forbidden = tuple(
                -variable if value else variable
                for variable, value in zip(variables, values, strict=True)
            )
            self.clause(*forbidden)

    def xor_many(
        self, inputs: Sequence[Signal], *, output: int | None = None
    ) -> Signal:
        variables, constant = self._normalize_parity(inputs)
        if output is None and not variables:
            return constant
        if output is None and len(variables) == 1:
            return -variables[0] if constant else variables[0]
        result = self.new_variable() if output is None else output
        if result == 0:
            raise Full256CNFError("XOR output must be a nonzero literal")
        normalized_inputs: list[Signal] = list(variables)
        if constant:
            normalized_inputs.append(True)
        self._parity_zero([*normalized_inputs, result])
        return result

    def equate(self, output: int, signal: Signal) -> int:
        if output == 0:
            raise Full256CNFError("equality output must be a nonzero literal")
        self._parity_zero((output, signal))
        return output

    def and2(
        self, left: Signal, right: Signal, *, output: int | None = None
    ) -> Signal:
        simplified: Signal | None = None
        if isinstance(left, bool):
            simplified = right if left else False
        elif isinstance(right, bool):
            simplified = left if right else False
        elif left == right:
            simplified = left
        elif left == -right:
            simplified = False
        if simplified is not None:
            return simplified if output is None else self.equate(output, simplified)
        result = self.new_variable() if output is None else output
        self.clause(-left, -right, result)
        self.clause(left, -result)
        self.clause(right, -result)
        return result

    def or2(
        self, left: Signal, right: Signal, *, output: int | None = None
    ) -> Signal:
        simplified: Signal | None = None
        if isinstance(left, bool):
            simplified = True if left else right
        elif isinstance(right, bool):
            simplified = True if right else left
        elif left == right:
            simplified = left
        elif left == -right:
            simplified = True
        if simplified is not None:
            return simplified if output is None else self.equate(output, simplified)
        result = self.new_variable() if output is None else output
        self.clause(left, right, -result)
        self.clause(-left, result)
        self.clause(-right, result)
        return result

    def majority3(
        self,
        left: Signal,
        middle: Signal,
        right: Signal,
        *,
        output: int | None = None,
    ) -> Signal:
        signals = [left, middle, right]
        true_count = sum(signal is True for signal in signals)
        false_count = sum(signal is False for signal in signals)
        nonconstants = [signal for signal in signals if not isinstance(signal, bool)]
        if true_count >= 2:
            return True if output is None else self.equate(output, True)
        if false_count >= 2:
            return False if output is None else self.equate(output, False)
        if true_count == 1 and false_count == 1:
            result = nonconstants[0]
            return result if output is None else self.equate(output, result)
        if false_count == 1:
            return self.and2(nonconstants[0], nonconstants[1], output=output)
        if true_count == 1:
            return self.or2(nonconstants[0], nonconstants[1], output=output)
        assert len(nonconstants) == 3
        a, b, c = nonconstants
        if a == b or a == c:
            return a if output is None else self.equate(output, a)
        if b == c:
            return b if output is None else self.equate(output, b)
        if a == -b:
            return c if output is None else self.equate(output, c)
        if a == -c:
            return b if output is None else self.equate(output, b)
        if b == -c:
            return a if output is None else self.equate(output, a)
        result = self.new_variable() if output is None else output
        self.clause(-a, -b, result)
        self.clause(-a, -c, result)
        self.clause(-b, -c, result)
        self.clause(a, b, -result)
        self.clause(a, c, -result)
        self.clause(b, c, -result)
        return result

    @contextmanager
    def operation(self, **metadata: object) -> Iterator[dict[str, object]]:
        first_variable = self.next_variable
        first_clause = self.sink.clause_count + 1
        details: dict[str, object] = {}
        yield details
        last_variable = self.next_variable - 1
        last_clause = self.sink.clause_count
        self.operations.append(
            {
                "operation_id": len(self.operations),
                **metadata,
                "first_internal_variable": (
                    first_variable if last_variable >= first_variable else None
                ),
                "last_internal_variable": (
                    last_variable if last_variable >= first_variable else None
                ),
                "first_clause": first_clause if last_clause >= first_clause else None,
                "last_clause": last_clause if last_clause >= first_clause else None,
                **details,
            }
        )


Word = tuple[Signal, ...]


def _word_from_variables(first: int) -> Word:
    return tuple(range(first, first + 32))


def _constant_word(value: int) -> Word:
    return tuple(bool((value >> bit) & 1) for bit in range(32))


def _rotl(word: Word, distance: int) -> Word:
    if len(word) != 32 or not 0 < distance < 32:
        raise Full256CNFError("rotation requires one 32-bit word and distance 1..31")
    return word[-distance:] + word[:-distance]


def _xor32(
    builder: CNFBuilder,
    left: Word,
    right: Word,
    *,
    bit_ranges: list[dict[str, object]] | None = None,
) -> Word:
    if len(left) != 32 or len(right) != 32:
        raise Full256CNFError("XOR operands must contain 32 bits")
    result: list[Signal] = []
    for bit, (a, b) in enumerate(zip(left, right, strict=True)):
        first_variable = builder.next_variable
        first_clause = builder.sink.clause_count + 1
        output = builder.xor_many((a, b))
        if isinstance(output, bool):
            raise AssertionError("round XOR output must remain an explicit variable")
        result.append(output)
        if bit_ranges is not None:
            bit_ranges.append(
                {
                    "bit": bit,
                    "output_variable": abs(output),
                    "first_internal_variable": first_variable,
                    "last_internal_variable": builder.next_variable - 1,
                    "first_clause": first_clause,
                    "last_clause": builder.sink.clause_count,
                }
            )
    return tuple(result)


def _add32(
    builder: CNFBuilder,
    left: Word,
    right: Word,
    *,
    output: Word | None = None,
    bit_ranges: list[dict[str, object]] | None = None,
) -> Word:
    if len(left) != 32 or len(right) != 32:
        raise Full256CNFError("addition operands must contain 32 bits")
    if output is not None and len(output) != 32:
        raise Full256CNFError("addition output must contain 32 bits")
    carry: Signal = False
    result: list[Signal] = []
    for bit, (a, b) in enumerate(zip(left, right, strict=True)):
        first_variable = builder.next_variable
        first_clause = builder.sink.clause_count + 1
        sum_output = builder.new_variable() if output is None else output[bit]
        if isinstance(sum_output, bool):
            raise Full256CNFError("fixed addition outputs must be DIMACS literals")
        result.append(builder.xor_many((a, b, carry), output=sum_output))
        # Retain even bit 31's carry variable: it is valuable telemetry and keeps
        # every full-adder bit structurally symmetric despite modulo-2^32 output.
        carry_output = builder.new_variable()
        carry = builder.majority3(a, b, carry, output=carry_output)
        if bit_ranges is not None:
            bit_ranges.append(
                {
                    "bit": bit,
                    "sum_variable": abs(sum_output),
                    "sum_variable_role": (
                        "internal" if output is None else "output_interface"
                    ),
                    "carry_variable": abs(carry_output),
                    "first_internal_variable": first_variable,
                    "last_internal_variable": builder.next_variable - 1,
                    "first_clause": first_clause,
                    "last_clause": builder.sink.clause_count,
                }
            )
    return tuple(result)


def _interface_words(first: int, count: int) -> list[Word]:
    return [_word_from_variables(first + 32 * index) for index in range(count)]


def _quarter_round(
    builder: CNFBuilder,
    state: list[Word],
    *,
    round_number: int,
    round_kind: str,
    quarter_index: int,
    lanes: tuple[int, int, int, int],
) -> None:
    a, b, c, d = lanes
    steps: tuple[tuple[str, int, int, int | None], ...] = (
        ("a_plus_b", a, b, None),
        ("d_xor_a_rotl16", d, a, 16),
        ("c_plus_d", c, d, None),
        ("b_xor_c_rotl12", b, c, 12),
        ("a_plus_b_second", a, b, None),
        ("d_xor_a_rotl8", d, a, 8),
        ("c_plus_d_second", c, d, None),
        ("b_xor_c_rotl7", b, c, 7),
    )
    for step_index, (step, destination, source, rotation) in enumerate(steps):
        kind = "add32" if rotation is None else "xor32"
        bit_ranges: list[dict[str, object]] = []
        with builder.operation(
            phase="round",
            kind=kind,
            round=round_number,
            round_kind=round_kind,
            quarter=quarter_index,
            lanes=list(lanes),
            step_index=step_index,
            step=step,
            destination_lane=destination,
            source_lane=source,
            rotation=rotation,
            wire_layout=(
                "lsb32-interleaved-sum-carry"
                if rotation is None
                else "lsb32-xor-output"
            ),
        ) as operation:
            if rotation is None:
                state[destination] = _add32(
                    builder,
                    state[destination],
                    state[source],
                    bit_ranges=bit_ranges,
                )
            else:
                state[destination] = _rotl(
                    _xor32(
                        builder,
                        state[destination],
                        state[source],
                        bit_ranges=bit_ranges,
                    ),
                    rotation,
                )
            operation["bit_ranges"] = bit_ranges


def build_full256_formula(sink: ClauseSink) -> FormulaStats:
    """Stream one full ChaCha20 block relation into ``sink``."""

    builder = CNFBuilder(sink)
    constants = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    key_words = _interface_words(KEY_FIRST_VARIABLE, 8)
    counter_word = _word_from_variables(COUNTER_FIRST_VARIABLE)
    nonce_words = _interface_words(NONCE_FIRST_VARIABLE, 3)
    output_words = _interface_words(OUTPUT_FIRST_VARIABLE, 16)
    initial: list[Word] = [
        *(_constant_word(value) for value in constants),
        *key_words,
        counter_word,
        *nonce_words,
    ]
    if len(initial) != 16:
        raise AssertionError("ChaCha20 initial state must contain sixteen words")
    state = list(initial)
    columns = (
        (0, 4, 8, 12),
        (1, 5, 9, 13),
        (2, 6, 10, 14),
        (3, 7, 11, 15),
    )
    diagonals = (
        (0, 5, 10, 15),
        (1, 6, 11, 12),
        (2, 7, 8, 13),
        (3, 4, 9, 14),
    )
    for double_round in range(10):
        for quarter, lanes in enumerate(columns):
            _quarter_round(
                builder,
                state,
                round_number=2 * double_round + 1,
                round_kind="column",
                quarter_index=quarter,
                lanes=lanes,
            )
        for quarter, lanes in enumerate(diagonals):
            _quarter_round(
                builder,
                state,
                round_number=2 * double_round + 2,
                round_kind="diagonal",
                quarter_index=quarter,
                lanes=lanes,
            )

    for lane, (final_word, initial_word, output_word) in enumerate(
        zip(state, initial, output_words, strict=True)
    ):
        bit_ranges = []
        with builder.operation(
            phase="feed_forward",
            kind="add32",
            round=None,
            round_kind=None,
            quarter=None,
            lanes=[lane],
            step_index=0,
            step="final_plus_initial",
            destination_lane=lane,
            source_lane=lane,
            rotation=None,
            wire_layout="lsb32-output-interface-sum-plus-internal-carry",
        ) as operation:
            constrained = _add32(
                builder,
                final_word,
                initial_word,
                output=output_word,
                bit_ranges=bit_ranges,
            )
            operation["bit_ranges"] = bit_ranges
        if constrained != output_word:
            raise AssertionError("feed-forward output interface was not retained")

    variable_count = builder.next_variable - 1
    if sink.max_variable > variable_count:
        raise AssertionError("formula references an unallocated variable")
    return FormulaStats(
        variable_count=variable_count,
        clause_count=sink.clause_count,
        clause_length_histogram={
            str(length): count for length, count in sorted(sink.length_histogram.items())
        },
        operations=tuple(builder.operations),
    )


def _interface_map() -> dict[str, object]:
    return {
        "bit_order": "little-endian-within-byte; little-endian-32-bit-words",
        "key": {
            "first_variable": KEY_FIRST_VARIABLE,
            "last_variable": KEY_LAST_VARIABLE,
            "bit_count": 256,
            "attacker_known": False,
        },
        "counter": {
            "first_variable": COUNTER_FIRST_VARIABLE,
            "last_variable": COUNTER_LAST_VARIABLE,
            "bit_count": 32,
            "attacker_known": True,
        },
        "nonce": {
            "first_variable": NONCE_FIRST_VARIABLE,
            "last_variable": NONCE_LAST_VARIABLE,
            "bit_count": 96,
            "attacker_known": True,
        },
        "output": {
            "first_variable": OUTPUT_FIRST_VARIABLE,
            "last_variable": OUTPUT_LAST_VARIABLE,
            "bit_count": 512,
            "attacker_known": True,
        },
    }


def _wire_semantics() -> dict[str, object]:
    return {
        "range_semantics": "one-based inclusive",
        "bit_range_order": "bit 0 through bit 31, LSB first",
        "round_add32": "two internal variables per bit: sum then carry",
        "round_xor32": "one internal output variable per bit before rotation",
        "feed_forward_add32": (
            "sum is the stable public output-interface variable; "
            "one internal carry variable per bit"
        ),
        "final_overflow_carry": "explicitly constrained and retained",
    }


def _write_fsync(handle: IO[bytes], value: bytes) -> None:
    handle.write(value)
    handle.flush()
    os.fsync(handle.fileno())


def _temporary_output(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    return descriptor, Path(raw)


def _publish_temporary(temporary: Path, destination: Path) -> tuple[int, int]:
    """Atomically link a completed file into place without ever clobbering."""

    metadata = temporary.stat()
    identity = (metadata.st_dev, metadata.st_ino)
    linked = False
    try:
        os.link(temporary, destination, follow_symlinks=False)
        linked = True
        temporary.unlink()
        parent_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        if linked:
            _remove_if_owned(destination, identity)
        raise
    return identity


def _remove_if_present(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _remove_if_owned(path: Path, identity: tuple[int, int]) -> None:
    """Rollback only a file whose inode was published by this invocation."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) != identity:
        return
    path.unlink()
    parent_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def write_full256_template(
    dimacs_path: str | Path, map_path: str | Path
) -> TemplateWriteReport:
    """Compile and atomically publish a deterministic template plus semantic map."""

    dimacs = Path(dimacs_path).resolve()
    sidecar = Path(map_path).resolve()
    if dimacs == sidecar:
        raise Full256CNFError("DIMACS and map paths must differ")
    if dimacs.exists() or sidecar.exists():
        raise FileExistsError("template outputs are immutable and must not exist")

    counting = CountingClauseSink()
    expected = build_full256_formula(counting)
    dimacs_fd, dimacs_temporary = _temporary_output(dimacs)
    sidecar_temporary: Path | None = None
    published: dict[Path, tuple[int, int]] = {}
    try:
        digest = hashlib.sha256()
        with os.fdopen(dimacs_fd, "wb") as handle:
            header = (
                f"p cnf {expected.variable_count} {expected.clause_count}\n"
            ).encode("ascii")
            handle.write(header)
            digest.update(header)
            streaming = _DimacsClauseSink(handle, digest)
            actual = build_full256_formula(streaming)
            handle.flush()
            os.fsync(handle.fileno())
        if actual != expected:
            raise AssertionError("counting and streaming compiler passes differ")
        dimacs_bytes = dimacs_temporary.stat().st_size
        unsigned_map: dict[str, object] = {
            "schema": TEMPLATE_SCHEMA,
            "cipher": {
                "name": "ChaCha20",
                "rounds": CHACHA20_ROUNDS,
                "feed_forward": True,
                "block_bytes": 64,
            },
            "generator": GENERATOR_ID,
            "interface": _interface_map(),
            "wire_semantics": _wire_semantics(),
            "internal_variables": {
                "first_variable": INTERNAL_FIRST_VARIABLE,
                "last_variable": expected.variable_count,
                "count": expected.variable_count - INTERNAL_FIRST_VARIABLE + 1,
            },
            "variable_count": expected.variable_count,
            "clause_count": expected.clause_count,
            "clause_length_histogram": expected.clause_length_histogram,
            "operation_count": len(expected.operations),
            "operations": list(expected.operations),
            "public_unit_clause_count": PUBLIC_UNIT_CLAUSES,
            "target_key_included": False,
            "target_internal_trace_included": False,
            "dimacs_sha256": digest.hexdigest(),
            "dimacs_bytes": dimacs_bytes,
        }
        document = {**unsigned_map, "map_sha256": canonical_sha256(unsigned_map)}
        map_bytes = canonical_json_bytes(document) + b"\n"
        sidecar_fd, sidecar_temporary = _temporary_output(sidecar)
        with os.fdopen(sidecar_fd, "wb") as handle:
            _write_fsync(handle, map_bytes)
        published[dimacs] = _publish_temporary(dimacs_temporary, dimacs)
        published[sidecar] = _publish_temporary(sidecar_temporary, sidecar)
        sidecar_temporary = None
        return TemplateWriteReport(
            dimacs_path=str(dimacs),
            map_path=str(sidecar),
            dimacs_sha256=digest.hexdigest(),
            map_file_sha256=hashlib.sha256(map_bytes).hexdigest(),
            map_sha256=str(document["map_sha256"]),
            variable_count=expected.variable_count,
            clause_count=expected.clause_count,
            dimacs_bytes=dimacs_bytes,
            operation_count=len(expected.operations),
        )
    except Exception:
        _remove_if_present(dimacs_temporary)
        if sidecar_temporary is not None:
            _remove_if_present(sidecar_temporary)
        for path, identity in published.items():
            _remove_if_owned(path, identity)
        raise


def _load_json_exact(path: Path) -> dict[str, object]:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise Full256CNFError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Full256CNFError("template map is not valid JSON") from exc
    if not isinstance(value, dict):
        raise Full256CNFError("template map must be a JSON object")
    if raw != canonical_json_bytes(value) + b"\n":
        raise Full256CNFError("template map is not canonical JSON")
    return value


def load_full256_template_map(path: str | Path) -> dict[str, object]:
    document = _load_json_exact(Path(path).resolve())
    expected_fields = {
        "schema",
        "cipher",
        "generator",
        "interface",
        "wire_semantics",
        "internal_variables",
        "variable_count",
        "clause_count",
        "clause_length_histogram",
        "operation_count",
        "operations",
        "public_unit_clause_count",
        "target_key_included",
        "target_internal_trace_included",
        "dimacs_sha256",
        "dimacs_bytes",
        "map_sha256",
    }
    if set(document) != expected_fields:
        raise Full256CNFError("template map fields differ")
    if document.get("schema") != TEMPLATE_SCHEMA:
        raise Full256CNFError("template map schema differs")
    map_sha = document.get("map_sha256")
    if (
        not isinstance(map_sha, str)
        or len(map_sha) != 64
        or any(character not in "0123456789abcdef" for character in map_sha)
    ):
        raise Full256CNFError("template map SHA-256 is invalid")
    unsigned = {key: value for key, value in document.items() if key != "map_sha256"}
    if canonical_sha256(unsigned) != map_sha:
        raise Full256CNFError("template map SHA-256 differs")
    if document.get("generator") != GENERATOR_ID:
        raise Full256CNFError("template generator differs")
    if document.get("cipher") != {
        "name": "ChaCha20",
        "rounds": CHACHA20_ROUNDS,
        "feed_forward": True,
        "block_bytes": 64,
    }:
        raise Full256CNFError("template cipher contract differs")
    if document.get("interface") != _interface_map():
        raise Full256CNFError("template interface differs")
    if document.get("wire_semantics") != _wire_semantics():
        raise Full256CNFError("template wire semantics differ")
    if (
        document.get("target_key_included") is not False
        or document.get("target_internal_trace_included") is not False
    ):
        raise Full256CNFError("template must exclude target key and internal trace")
    if document.get("public_unit_clause_count") != PUBLIC_UNIT_CLAUSES:
        raise Full256CNFError("public unit-clause count differs")
    for field in ("variable_count", "clause_count", "dimacs_bytes"):
        value = document.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise Full256CNFError(f"template {field} is invalid")
    dimacs_sha = document.get("dimacs_sha256")
    if (
        not isinstance(dimacs_sha, str)
        or len(dimacs_sha) != 64
        or any(character not in "0123456789abcdef" for character in dimacs_sha)
    ):
        raise Full256CNFError("template DIMACS SHA-256 is invalid")

    expected_sink = CountingClauseSink()
    expected = build_full256_formula(expected_sink)
    if (
        document.get("variable_count") != expected.variable_count
        or document.get("clause_count") != expected.clause_count
        or document.get("clause_length_histogram")
        != expected.clause_length_histogram
        or document.get("operation_count") != len(expected.operations)
        or document.get("operations") != list(expected.operations)
        or document.get("internal_variables")
        != {
            "first_variable": INTERNAL_FIRST_VARIABLE,
            "last_variable": expected.variable_count,
            "count": expected.variable_count - INTERNAL_FIRST_VARIABLE + 1,
        }
    ):
        raise Full256CNFError("template semantic map differs from full ChaCha20")
    return document


def verify_full256_template(
    dimacs_path: str | Path, map_path: str | Path
) -> dict[str, object]:
    """Recount and hash a template without materializing its clauses."""

    dimacs = Path(dimacs_path).resolve()
    document = load_full256_template_map(map_path)
    digest = hashlib.sha256()
    clause_count = 0
    max_variable = 0
    histogram: Counter[int] = Counter()
    with dimacs.open("rb") as handle:
        header_raw = handle.readline()
        digest.update(header_raw)
        try:
            header = header_raw.decode("ascii").strip().split()
        except UnicodeDecodeError as exc:
            raise Full256CNFError("DIMACS header is not ASCII") from exc
        if len(header) != 4 or header[:2] != ["p", "cnf"]:
            raise Full256CNFError("DIMACS header differs")
        try:
            declared_variables, declared_clauses = map(int, header[2:])
        except ValueError as exc:
            raise Full256CNFError("DIMACS header counts are invalid") from exc
        for line_number, raw in enumerate(handle, start=2):
            digest.update(raw)
            try:
                fields = raw.decode("ascii").strip().split()
                values = [int(field) for field in fields]
            except (UnicodeDecodeError, ValueError) as exc:
                raise Full256CNFError(
                    f"DIMACS clause line {line_number} is invalid"
                ) from exc
            if not values or values[-1] != 0 or 0 in values[:-1]:
                raise Full256CNFError(
                    f"DIMACS clause line {line_number} lacks one terminator"
                )
            literals = values[:-1]
            if len(set(literals)) != len(literals) or any(
                -literal in literals for literal in literals
            ):
                raise Full256CNFError(
                    f"DIMACS clause line {line_number} is not simplified"
                )
            clause_count += 1
            histogram[len(literals)] += 1
            if literals:
                max_variable = max(max_variable, max(abs(item) for item in literals))
    if declared_variables != document["variable_count"]:
        raise Full256CNFError("DIMACS variable count differs from map")
    if declared_clauses != document["clause_count"] or clause_count != declared_clauses:
        raise Full256CNFError("DIMACS clause count differs from map")
    expected_histogram = {
        str(length): count for length, count in sorted(histogram.items())
    }
    if expected_histogram != document.get("clause_length_histogram"):
        raise Full256CNFError("DIMACS clause histogram differs from map")
    if max_variable > declared_variables:
        raise Full256CNFError("DIMACS references an undeclared variable")
    if dimacs.stat().st_size != document["dimacs_bytes"]:
        raise Full256CNFError("DIMACS byte count differs from map")
    if digest.hexdigest() != document.get("dimacs_sha256"):
        raise Full256CNFError("DIMACS SHA-256 differs from map")
    return {
        "schema": "o1-256-chacha20-cnf-verification-v1",
        "ok": True,
        "variable_count": declared_variables,
        "clause_count": clause_count,
        "max_referenced_variable": max_variable,
        "clause_length_histogram": expected_histogram,
        "dimacs_sha256": digest.hexdigest(),
        "map_sha256": document["map_sha256"],
    }


def _uint32_bits(value: int, field: str) -> list[int]:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MASK:
        raise Full256CNFError(f"{field} must be uint32")
    return [(value >> bit) & 1 for bit in range(32)]


def _byte_bits(value: bytes, *, length: int, field: str) -> list[int]:
    if not isinstance(value, bytes) or len(value) != length:
        raise Full256CNFError(f"{field} must contain exactly {length} bytes")
    return [(byte >> bit) & 1 for byte in value for bit in range(8)]


def _unit_literal(variable: int, value: int) -> int:
    return variable if value else -variable


def _validated_assumptions(
    assumptions: Sequence[tuple[int, int]], *, key: bytes | None
) -> list[tuple[int, int]]:
    if isinstance(assumptions, (str, bytes)):
        raise Full256CNFError("assumptions must be (key_bit, value) pairs")
    seen: set[int] = set()
    result: list[tuple[int, int]] = []
    key_values = None if key is None else _byte_bits(key, length=32, field="key")
    if key_values is not None and assumptions:
        raise Full256CNFError(
            "paired assumptions require a free key, not a fixed self-test key"
        )
    for row in assumptions:
        if not isinstance(row, tuple) or len(row) != 2:
            raise Full256CNFError("each assumption must be one (key_bit, value) tuple")
        bit, value = row
        if (
            isinstance(bit, bool)
            or not isinstance(bit, int)
            or not 0 <= bit < 256
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value not in (0, 1)
        ):
            raise Full256CNFError("key assumptions require bit 0..255 and value 0/1")
        if bit in seen:
            raise Full256CNFError("duplicate key-bit assumption")
        if key_values is not None and key_values[bit] != value:
            raise Full256CNFError("key-bit assumption conflicts with fixed self-test key")
        seen.add(bit)
        result.append((bit, value))
    return sorted(result)


def _copy_template_body(
    source: IO[bytes],
    destination: IO[bytes],
    instance_digest: _Digest,
    source_digest: _Digest,
) -> tuple[int, bytes]:
    source_header = source.readline()
    source_digest.update(source_header)
    copied = 0
    while chunk := source.read(1 << 20):
        destination.write(chunk)
        instance_digest.update(chunk)
        source_digest.update(chunk)
        copied += len(chunk)
    return copied, source_header


def _unit_clause_bytes(units: Sequence[int]) -> bytes:
    return b"".join(f"{literal} 0\n".encode("ascii") for literal in units)


def write_full256_instance(
    template_path: str | Path,
    map_path: str | Path,
    destination_path: str | Path,
    *,
    counter: int,
    nonce: bytes,
    output: bytes,
    assumptions: Sequence[tuple[int, int]] = (),
    key_for_self_test: bytes | None = None,
    report_path: str | Path | None = None,
    verify_template: bool = True,
) -> InstanceWriteReport:
    """Instantiate one public block relation while leaving all key bits free.

    ``key_for_self_test`` exists only for compiler validation.  Production attack
    instances omit it and therefore contain exactly 640 public unit clauses plus
    any explicitly requested paired-assumption probe.
    """

    template = Path(template_path).resolve()
    sidecar = Path(map_path).resolve()
    destination = Path(destination_path).resolve()
    report_destination = None if report_path is None else Path(report_path).resolve()
    if verify_template:
        verify_full256_template(template, sidecar)
    document = load_full256_template_map(sidecar)
    counter_values = _uint32_bits(counter, "counter")
    nonce_values = _byte_bits(nonce, length=12, field="nonce")
    output_values = _byte_bits(output, length=64, field="output")
    if key_for_self_test is not None:
        key_values = _byte_bits(key_for_self_test, length=32, field="key_for_self_test")
    else:
        key_values = []
    assumption_values = _validated_assumptions(
        assumptions, key=key_for_self_test
    )
    units: list[int] = []
    units.extend(
        _unit_literal(COUNTER_FIRST_VARIABLE + index, value)
        for index, value in enumerate(counter_values)
    )
    units.extend(
        _unit_literal(NONCE_FIRST_VARIABLE + index, value)
        for index, value in enumerate(nonce_values)
    )
    units.extend(
        _unit_literal(OUTPUT_FIRST_VARIABLE + index, value)
        for index, value in enumerate(output_values)
    )
    public_count = len(units)
    if public_count != PUBLIC_UNIT_CLAUSES:
        raise AssertionError("public interface must produce exactly 640 units")
    units.extend(
        _unit_literal(KEY_FIRST_VARIABLE + index, value)
        for index, value in enumerate(key_values)
    )
    units.extend(
        _unit_literal(KEY_FIRST_VARIABLE + bit, value)
        for bit, value in assumption_values
    )
    total_clauses = int(document["clause_count"]) + len(units)
    destination_fd, temporary = _temporary_output(destination)
    report_temporary: Path | None = None
    published: dict[Path, tuple[int, int]] = {}
    try:
        digest = hashlib.sha256()
        copied_source_digest = hashlib.sha256()
        with os.fdopen(destination_fd, "wb") as target, template.open("rb") as source:
            header = f"p cnf {document['variable_count']} {total_clauses}\n".encode(
                "ascii"
            )
            target.write(header)
            digest.update(header)
            copied_bytes, source_header = _copy_template_body(
                source, target, digest, copied_source_digest
            )
            unit_bytes = _unit_clause_bytes(units)
            target.write(unit_bytes)
            digest.update(unit_bytes)
            target.flush()
            os.fsync(target.fileno())
        expected_source_header = (
            f"p cnf {document['variable_count']} {document['clause_count']}\n"
        ).encode("ascii")
        if (
            source_header != expected_source_header
            or copied_bytes + len(source_header) != document["dimacs_bytes"]
            or copied_source_digest.hexdigest() != document["dimacs_sha256"]
        ):
            raise Full256CNFError(
                "the exact template stream changed while building the instance"
            )
        public_unit_bytes = _unit_clause_bytes(units[:public_count])
        key_count = len(key_values)
        key_unit_bytes = _unit_clause_bytes(
            units[public_count : public_count + key_count]
        )
        assumption_unit_bytes = _unit_clause_bytes(
            units[public_count + key_count :]
        )
        result = InstanceWriteReport(
            schema=INSTANCE_SCHEMA,
            instance_path=str(destination),
            template_sha256=str(document["dimacs_sha256"]),
            template_map_sha256=str(document["map_sha256"]),
            instance_sha256=digest.hexdigest(),
            instance_bytes=temporary.stat().st_size,
            variable_count=int(document["variable_count"]),
            clause_count=total_clauses,
            public_unit_clause_count=public_count,
            public_unit_clause_sha256=hashlib.sha256(public_unit_bytes).hexdigest(),
            key_unit_clause_count=key_count,
            key_unit_clause_sha256=(
                hashlib.sha256(key_unit_bytes).hexdigest() if key_count else None
            ),
            assumption_unit_clause_count=len(assumption_values),
            assumption_unit_clause_sha256=(
                hashlib.sha256(assumption_unit_bytes).hexdigest()
                if assumption_values
                else None
            ),
            unit_clause_sha256=hashlib.sha256(unit_bytes).hexdigest(),
            assumptions=tuple(assumption_values),
            key_fixed_for_self_test=key_for_self_test is not None,
            fixed_key_sha256=(
                hashlib.sha256(key_for_self_test).hexdigest()
                if key_for_self_test is not None
                else None
            ),
            counter=counter,
            nonce_hex=nonce.hex(),
            output_sha256=hashlib.sha256(output).hexdigest(),
        )
        report_bytes = canonical_json_bytes(result.describe()) + b"\n"
        if report_destination is not None:
            if report_destination in (destination, template, sidecar):
                raise Full256CNFError("instance report path collides with another artifact")
            report_fd, report_temporary = _temporary_output(report_destination)
            with os.fdopen(report_fd, "wb") as handle:
                _write_fsync(handle, report_bytes)
        published[destination] = _publish_temporary(temporary, destination)
        if report_destination is not None and report_temporary is not None:
            published[report_destination] = _publish_temporary(
                report_temporary, report_destination
            )
            report_temporary = None
        return result
    except Exception:
        _remove_if_present(temporary)
        if report_temporary is not None:
            _remove_if_present(report_temporary)
        for path, identity in published.items():
            _remove_if_owned(path, identity)
        raise


def _report_mapping(
    report: InstanceWriteReport | Mapping[str, object] | str | Path,
) -> dict[str, object]:
    if isinstance(report, InstanceWriteReport):
        return report.describe()
    if isinstance(report, (str, Path)):
        return _load_json_exact(Path(report).resolve())
    if not isinstance(report, Mapping):
        raise Full256CNFError("instance report must be an object or canonical JSON")
    return dict(report)


def _bits_from_units(units: Sequence[int], first_variable: int) -> list[int]:
    expected = list(range(first_variable, first_variable + len(units)))
    if [abs(literal) for literal in units] != expected:
        raise Full256CNFError("instance unit variables are not canonical")
    return [int(literal > 0) for literal in units]


def _bits_to_bytes(bits: Sequence[int]) -> bytes:
    if len(bits) % 8:
        raise Full256CNFError("unit bit count is not byte-aligned")
    return bytes(
        sum(bits[offset + bit] << bit for bit in range(8))
        for offset in range(0, len(bits), 8)
    )


def verify_full256_instance(
    instance_path: str | Path,
    template_path: str | Path,
    map_path: str | Path,
    report: InstanceWriteReport | Mapping[str, object] | str | Path,
) -> dict[str, object]:
    """Verify the exact template body, public units, key units, and assumptions."""

    instance = Path(instance_path).resolve()
    template = Path(template_path).resolve()
    document = load_full256_template_map(map_path)
    verify_full256_template(template, map_path)
    expected_report = _report_mapping(report)
    expected_report_fields = {
        "schema",
        "template_sha256",
        "template_map_sha256",
        "instance_sha256",
        "instance_bytes",
        "variable_count",
        "clause_count",
        "public_unit_clause_count",
        "public_unit_clause_sha256",
        "key_unit_clause_count",
        "key_unit_clause_sha256",
        "assumption_unit_clause_count",
        "assumption_unit_clause_sha256",
        "unit_clause_sha256",
        "assumptions",
        "key_fixed_for_self_test",
        "fixed_key_sha256",
        "counter",
        "nonce_hex",
        "output_sha256",
    }
    if set(expected_report) != expected_report_fields:
        raise Full256CNFError("instance report fields differ")
    if (
        expected_report.get("schema") != INSTANCE_SCHEMA
        or expected_report.get("template_sha256") != document["dimacs_sha256"]
        or expected_report.get("template_map_sha256") != document["map_sha256"]
        or expected_report.get("variable_count") != document["variable_count"]
        or expected_report.get("public_unit_clause_count") != PUBLIC_UNIT_CLAUSES
    ):
        raise Full256CNFError("instance report template binding differs")

    key_count = expected_report.get("key_unit_clause_count")
    assumption_count = expected_report.get("assumption_unit_clause_count")
    if key_count not in (0, 256):
        raise Full256CNFError("instance key-unit count must be zero or 256")
    if (
        isinstance(assumption_count, bool)
        or not isinstance(assumption_count, int)
        or not 0 <= assumption_count <= 256
    ):
        raise Full256CNFError("instance assumption-unit count differs")
    total_units = PUBLIC_UNIT_CLAUSES + key_count + assumption_count
    expected_clauses = int(document["clause_count"]) + total_units
    if expected_report.get("clause_count") != expected_clauses:
        raise Full256CNFError("instance report clause count differs")

    digest = hashlib.sha256()
    with template.open("rb") as source, instance.open("rb") as target:
        template_header = source.readline()
        target_header = target.readline()
        digest.update(target_header)
        expected_template_header = (
            f"p cnf {document['variable_count']} {document['clause_count']}\n"
        ).encode("ascii")
        expected_target_header = (
            f"p cnf {document['variable_count']} {expected_clauses}\n"
        ).encode("ascii")
        if template_header != expected_template_header or target_header != expected_target_header:
            raise Full256CNFError("instance or template header differs")
        body_bytes = int(document["dimacs_bytes"]) - len(template_header)
        remaining = body_bytes
        while remaining:
            size = min(1 << 20, remaining)
            source_chunk = source.read(size)
            target_chunk = target.read(size)
            if (
                len(source_chunk) != size
                or len(target_chunk) != size
                or source_chunk != target_chunk
            ):
                raise Full256CNFError("instance body differs from exact template")
            digest.update(target_chunk)
            remaining -= size
        if source.read(1):
            raise Full256CNFError("template contains unaccounted bytes")
        unit_bytes = target.read()
        digest.update(unit_bytes)

    try:
        rows = unit_bytes.decode("ascii").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise Full256CNFError("instance unit clauses are not ASCII") from exc
    if len(rows) != total_units or any(not row.endswith("\n") for row in rows):
        raise Full256CNFError("instance unit-clause byte count differs")
    units: list[int] = []
    for row in rows:
        fields = row.strip().split()
        if len(fields) != 2 or fields[1] != "0":
            raise Full256CNFError("instance suffix contains a non-unit clause")
        try:
            literal = int(fields[0])
        except ValueError as exc:
            raise Full256CNFError("instance unit literal is invalid") from exc
        if literal == 0:
            raise Full256CNFError("instance unit literal cannot be zero")
        units.append(literal)
    if unit_bytes != _unit_clause_bytes(units):
        raise Full256CNFError("instance unit clauses are not canonical")

    public_units = units[:PUBLIC_UNIT_CLAUSES]
    key_units = units[PUBLIC_UNIT_CLAUSES : PUBLIC_UNIT_CLAUSES + key_count]
    assumption_units = units[PUBLIC_UNIT_CLAUSES + key_count :]
    public_bits = _bits_from_units(public_units, COUNTER_FIRST_VARIABLE)
    counter_bits = public_bits[:32]
    nonce_bits = public_bits[32:128]
    output_bits = public_bits[128:]
    counter = sum(bit << index for index, bit in enumerate(counter_bits))
    nonce = _bits_to_bytes(nonce_bits)
    output = _bits_to_bytes(output_bits)
    if (
        expected_report.get("counter") != counter
        or expected_report.get("nonce_hex") != nonce.hex()
        or expected_report.get("output_sha256")
        != hashlib.sha256(output).hexdigest()
    ):
        raise Full256CNFError("instance public unit values differ from report")

    fixed_key_sha: str | None = None
    if key_count:
        key = _bits_to_bytes(_bits_from_units(key_units, KEY_FIRST_VARIABLE))
        fixed_key_sha = hashlib.sha256(key).hexdigest()
    if (
        expected_report.get("key_fixed_for_self_test") is not bool(key_count)
        or expected_report.get("fixed_key_sha256") != fixed_key_sha
    ):
        raise Full256CNFError("instance fixed-key binding differs")

    assumptions_value = expected_report.get("assumptions")
    if not isinstance(assumptions_value, list) or len(assumptions_value) != assumption_count:
        raise Full256CNFError("instance assumption inventory differs")
    expected_assumption_literals: list[int] = []
    prior_bit = -1
    for row in assumptions_value:
        if not isinstance(row, dict) or set(row) != {"key_bit", "value"}:
            raise Full256CNFError("instance assumption row differs")
        bit = row["key_bit"]
        value = row["value"]
        if (
            isinstance(bit, bool)
            or not isinstance(bit, int)
            or not 0 <= bit < 256
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value not in (0, 1)
            or bit <= prior_bit
        ):
            raise Full256CNFError("instance assumption value differs")
        prior_bit = bit
        literal = KEY_FIRST_VARIABLE + bit
        expected_assumption_literals.append(literal if value else -literal)
    if assumption_units != expected_assumption_literals:
        raise Full256CNFError("instance assumption literals differ from report")

    public_bytes = _unit_clause_bytes(public_units)
    key_bytes = _unit_clause_bytes(key_units)
    assumption_bytes = _unit_clause_bytes(assumption_units)
    actual_sha = digest.hexdigest()
    if (
        expected_report.get("instance_sha256") != actual_sha
        or expected_report.get("instance_bytes") != instance.stat().st_size
        or expected_report.get("public_unit_clause_sha256")
        != hashlib.sha256(public_bytes).hexdigest()
        or expected_report.get("key_unit_clause_sha256")
        != (hashlib.sha256(key_bytes).hexdigest() if key_count else None)
        or expected_report.get("assumption_unit_clause_sha256")
        != (
            hashlib.sha256(assumption_bytes).hexdigest()
            if assumption_count
            else None
        )
        or expected_report.get("unit_clause_sha256")
        != hashlib.sha256(unit_bytes).hexdigest()
    ):
        raise Full256CNFError("instance artifact hash binding differs")
    return {
        "schema": "o1-256-chacha20-cnf-instance-verification-v1",
        "ok": True,
        "instance_sha256": actual_sha,
        "template_sha256": document["dimacs_sha256"],
        "template_map_sha256": document["map_sha256"],
        "variable_count": document["variable_count"],
        "clause_count": expected_clauses,
        "public_unit_clause_count": PUBLIC_UNIT_CLAUSES,
        "key_unit_clause_count": key_count,
        "assumption_unit_clause_count": assumption_count,
    }


def _timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_cadical(
    instance_path: str | Path,
    *,
    executable: str | None = None,
    timeout_seconds: float = 30.0,
) -> SolverReport:
    """Run a bounded, quiet CaDiCaL validation and normalize its SAT status."""

    if timeout_seconds <= 0:
        raise Full256CNFError("solver timeout must be positive")
    solver = executable or shutil.which("cadical")
    if solver is None:
        raise FileNotFoundError("cadical")
    instance = Path(instance_path).resolve()
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [solver, "-q", "-n", str(instance)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        return SolverReport(
            solver=solver,
            status="TIMEOUT",
            returncode=-1,
            wall_seconds=elapsed,
            stdout=_timeout_output(exc.stdout),
            stderr=_timeout_output(exc.stderr),
        )
    elapsed = time.monotonic() - started
    status = {10: "SAT", 20: "UNSAT"}.get(completed.returncode, "ERROR")
    return SolverReport(
        solver=solver,
        status=status,
        returncode=completed.returncode,
        wall_seconds=elapsed,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
