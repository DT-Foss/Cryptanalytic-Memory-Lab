"""Bounded-state memory arms and a streaming bit-evidence accumulator."""

from __future__ import annotations

import hashlib
import math
from typing import Iterable, Sequence


Address = bytes | str | int


def _address_bytes(address: Address) -> bytes:
    if isinstance(address, bytes):
        return b"B" + address
    if isinstance(address, str):
        return b"S" + address.encode("utf-8")
    if isinstance(address, int):
        if isinstance(address, bool):
            raise TypeError("boolean addresses are not supported")
        if address < 0:
            return b"I-" + (-address).to_bytes(
                max(1, ((-address).bit_length() + 7) // 8), "big"
            )
        return b"I+" + address.to_bytes(max(1, (address.bit_length() + 7) // 8), "big")
    raise TypeError("addresses must be bytes, str or int")


def _hash_u64(address: Address, *, seed: int, channel: int = 0) -> int:
    digest = hashlib.blake2b(
        _address_bytes(address),
        digest_size=8,
        person=b"o1crypt1",
        salt=(seed & ((1 << 64) - 1)).to_bytes(8, "big"),
        key=(channel & ((1 << 64) - 1)).to_bytes(8, "big"),
    ).digest()
    return int.from_bytes(digest, "big")


class DirectBitVault:
    """One explicit register per fixed semantic bit position.

    This is the honest ceiling for the position-indexed MQAR-256 instrument. It is
    bounded in stream length but scales linearly with the declared key width.
    """

    def __init__(self, n_bits: int) -> None:
        if not isinstance(n_bits, int) or isinstance(n_bits, bool) or n_bits < 1:
            raise ValueError("n_bits must be positive")
        self.n_bits = n_bits
        self._values: list[int | None] = [None] * n_bits

    @property
    def state_scalars(self) -> int:
        return self.n_bits

    @property
    def state_precision_bits(self) -> int:
        return 1

    @property
    def serialized_state_bytes(self) -> int:
        # One value bit plus one validity bit per fixed register.
        return (2 * self.n_bits + 7) // 8

    @property
    def state_dtype(self) -> str:
        return "bit+validity"

    def write(self, address: int, bit: int) -> None:
        if not isinstance(address, int) or isinstance(address, bool):
            raise TypeError("address must be an integer")
        if not 0 <= address < self.n_bits:
            raise IndexError(
                f"address {address} outside fixed vault width {self.n_bits}"
            )
        if not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1):
            raise ValueError("bit must be 0 or 1")
        self._values[address] = bit

    def read(self, address: int) -> int:
        if not isinstance(address, int) or isinstance(address, bool):
            raise TypeError("address must be an integer")
        if not 0 <= address < self.n_bits:
            raise IndexError(
                f"address {address} outside fixed vault width {self.n_bits}"
            )
        value = self._values[address]
        if value is None:
            raise KeyError(f"address {address} has not been written")
        return value

    def observe_haystack(self, _token: int) -> None:
        """Ideal closed relevance gate: keep the register frozen."""

    def state_digest(self) -> str:
        payload = bytes(2 if value is None else value for value in self._values)
        return hashlib.sha256(payload).hexdigest()


class FullContextAttentionCeiling:
    """An explicitly unbounded full-context validity ceiling.

    It stores every binding and every haystack token and scans them at query time. This
    is deliberately invalid as a bounded-state solution and deliberately useful as
    a harness ceiling: if it is not exact, the benchmark itself is broken.
    """

    def __init__(self) -> None:
        self._tokens: list[tuple[int, int, int]] = []

    @property
    def state_scalars(self) -> int:
        return 3 * len(self._tokens)

    @property
    def state_precision_bits(self) -> int:
        return 64

    @property
    def serialized_state_bytes(self) -> int:
        # Canonical logical encoding: kind u8, address u64, value u8.
        return 10 * len(self._tokens)

    @property
    def state_dtype(self) -> str:
        return "full-context u8/u64/u8"

    def write(self, address: int, bit: int) -> None:
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address < (1 << 64)
        ):
            raise IndexError(address)
        if not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1):
            raise ValueError("bit must be 0 or 1")
        self._tokens.append((1, address, bit))

    def read(self, address: int) -> int:
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address < (1 << 64)
        ):
            raise IndexError(address)
        # Hard content attention over the retained context. No retrieval dictionary
        # is allowed in this ceiling; query cost and state both grow with context.
        for kind, stored_address, bit in reversed(self._tokens):
            if kind == 1 and stored_address == address:
                return bit
        raise KeyError(f"address {address} has not been written")

    def observe_haystack(self, token: int) -> None:
        if (
            not isinstance(token, int)
            or isinstance(token, bool)
            or not 0 <= token < (1 << 64)
        ):
            raise ValueError("haystack token must fit unsigned 64-bit storage")
        self._tokens.append((0, token, 0))

    def state_digest(self) -> str:
        digest = hashlib.sha256()
        for kind, address, value in self._tokens:
            digest.update(kind.to_bytes(1, "big"))
            digest.update(address.to_bytes(8, "big"))
            digest.update(value.to_bytes(1, "big"))
        return digest.hexdigest()


class CountSketchBitMemory:
    """An undersized fixed carrier bank used as a collision/capacity control."""

    def __init__(self, n_slots: int, *, seed: int = 0) -> None:
        if not isinstance(n_slots, int) or isinstance(n_slots, bool) or n_slots < 1:
            raise ValueError("n_slots must be positive")
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise TypeError("seed must be an integer")
        self.n_slots = n_slots
        self.seed = seed
        self._state = [0.0] * n_slots

    @property
    def state_scalars(self) -> int:
        return self.n_slots

    @property
    def state_precision_bits(self) -> int:
        return 64

    @property
    def serialized_state_bytes(self) -> int:
        return 8 * self.n_slots

    @property
    def state_dtype(self) -> str:
        return "float64"

    def _location(self, address: Address) -> tuple[int, float]:
        hashed = _hash_u64(address, seed=self.seed)
        slot = hashed % self.n_slots
        sign = 1.0 if (hashed >> 63) == 0 else -1.0
        return slot, sign

    def write(self, address: Address, bit: int) -> None:
        if not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1):
            raise ValueError("bit must be 0 or 1")
        slot, sign = self._location(address)
        value = 1.0 if bit else -1.0
        self._state[slot] += sign * value

    def score(self, address: Address) -> float:
        slot, sign = self._location(address)
        return sign * self._state[slot]

    def read(self, address: Address) -> int:
        return int(self.score(address) >= 0.0)

    def observe_haystack(self, _token: int) -> None:
        pass

    def state_digest(self) -> str:
        payload = ",".join(f"{value:.17g}" for value in self._state).encode("ascii")
        return hashlib.sha256(payload).hexdigest()


class HolographicBitMemory:
    """Fixed multi-channel complex superposition with address-conditioned phase.

    A deterministic random phase code is generated from `(address, channel, seed)`.
    Writes superpose signed code vectors; reads de-rotate and average across channels.
    With `channels=128`, the state contains 256 real scalars, matching a 256-wide
    direct vault while supporting addresses from a much larger space.
    """

    def __init__(self, channels: int, *, seed: int = 0) -> None:
        if not isinstance(channels, int) or isinstance(channels, bool) or channels < 1:
            raise ValueError("channels must be positive")
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise TypeError("seed must be an integer")
        self.channels = channels
        self.seed = seed
        self._state = [0.0j] * channels

    @property
    def state_scalars(self) -> int:
        return 2 * self.channels

    @property
    def state_precision_bits(self) -> int:
        return 64

    @property
    def serialized_state_bytes(self) -> int:
        return 16 * self.channels

    @property
    def state_dtype(self) -> str:
        return "complex128"

    def _code(self, address: Address, channel: int) -> complex:
        raw = _hash_u64(address, seed=self.seed, channel=channel)
        angle = math.tau * (raw / float(1 << 64))
        return complex(math.cos(angle), math.sin(angle))

    def write(self, address: Address, bit: int) -> None:
        if not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1):
            raise ValueError("bit must be 0 or 1")
        value = 1.0 if bit else -1.0
        for channel in range(self.channels):
            self._state[channel] += value * self._code(address, channel)

    def score(self, address: Address) -> float:
        total = 0.0
        for channel, state in enumerate(self._state):
            total += (state * self._code(address, channel).conjugate()).real
        return total / self.channels

    def read(self, address: Address) -> int:
        return int(self.score(address) >= 0.0)

    def observe_haystack(self, _token: int) -> None:
        pass

    def state_digest(self) -> str:
        payload = ";".join(
            f"{value.real:.17g},{value.imag:.17g}" for value in self._state
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()


class StreamingEvidenceAccumulator:
    """A fixed-width bank of online bit log-odds.

    The state is constant in the number of relations. It is intentionally explicit
    in bit position: this tests evidence integration, not address compression.
    """

    def __init__(self, n_bits: int, *, decay: float = 1.0, clip: float = 80.0) -> None:
        if not isinstance(n_bits, int) or isinstance(n_bits, bool) or n_bits < 1:
            raise ValueError("n_bits must be positive")
        if (
            isinstance(decay, bool)
            or not isinstance(decay, (int, float))
            or not math.isfinite(decay)
            or not 0.0 < decay <= 1.0
        ):
            raise ValueError("decay must be in (0, 1]")
        if (
            isinstance(clip, bool)
            or not isinstance(clip, (int, float))
            or not math.isfinite(clip)
            or clip <= 0.0
        ):
            raise ValueError("clip must be positive")
        self.n_bits = n_bits
        self.decay = decay
        self.clip = clip
        self._log_odds = [0.0] * n_bits

    @property
    def state_scalars(self) -> int:
        return self.n_bits

    @property
    def state_precision_bits(self) -> int:
        return 64

    @property
    def serialized_state_bytes(self) -> int:
        return 8 * self.n_bits

    @property
    def state_dtype(self) -> str:
        return "float64"

    def update(self, evidence: Sequence[float]) -> None:
        if len(evidence) != self.n_bits:
            raise ValueError(
                f"expected {self.n_bits} evidence values, got {len(evidence)}"
            )
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in evidence
        ):
            raise TypeError("evidence must contain numeric scalars")
        values = [float(value) for value in evidence]
        if any(not math.isfinite(value) for value in values):
            raise ValueError("evidence must be finite")
        updated_state = []
        for index, value in enumerate(values):
            updated = self.decay * self._log_odds[index] + float(value)
            updated_state.append(max(-self.clip, min(self.clip, updated)))
        self._log_odds = updated_state

    def update_sparse(self, evidence: Iterable[tuple[int, float]]) -> None:
        raw_entries = list(evidence)
        if any(
            not isinstance(index, int)
            or isinstance(index, bool)
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            for index, value in raw_entries
        ):
            raise TypeError(
                "sparse evidence must contain integer indices and numeric values"
            )
        entries = [(index, float(value)) for index, value in raw_entries]
        for index, value in entries:
            if not 0 <= index < self.n_bits:
                raise IndexError(index)
            if not math.isfinite(value):
                raise ValueError("evidence must be finite")
        updated_state = [self.decay * value for value in self._log_odds]
        for index, value in entries:
            updated = updated_state[index] + value
            updated_state[index] = max(-self.clip, min(self.clip, updated))
        self._log_odds = updated_state

    def score(self, index: int) -> float:
        if not 0 <= index < self.n_bits:
            raise IndexError(index)
        return self._log_odds[index]

    def probability(self, index: int) -> float:
        value = self.score(index)
        if value >= 0.0:
            return 1.0 / (1.0 + math.exp(-value))
        exp_value = math.exp(value)
        return exp_value / (1.0 + exp_value)

    def predict(self) -> list[int]:
        return [int(value >= 0.0) for value in self._log_odds]

    def probabilities(self) -> list[float]:
        return [self.probability(index) for index in range(self.n_bits)]

    def state_digest(self) -> str:
        payload = ",".join(f"{value:.17g}" for value in self._log_odds).encode("ascii")
        return hashlib.sha256(payload).hexdigest()
