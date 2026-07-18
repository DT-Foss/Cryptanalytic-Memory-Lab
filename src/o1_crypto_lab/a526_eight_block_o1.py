"""Eight-block public-output O1 reader for A526's 204 fixed key bits.

The model consumes only public RFC8439 words in one bounded O1 state, then
queries coordinates 52..255 through the existing holographic read path.  Its
output is already in the exact coordinate system required by
``a526_completion_frontier``; no replacement residual engine is introduced.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from .a526_completion_frontier import (
    A526_FIXED_COORDINATES,
    A526_FIXED_WIDTH,
    A526_RESIDUAL_WIDTH,
)
from .chacha_trace import UINT32_MASK, chacha20_blocks
from .living_inverse import KEY_BITS, PublicTargetView, canonical_json_bytes, key_bits
from .o1_streaming_core import (
    O1FastState,
    O1StreamingCoreConfig,
    StreamingO1KeyReader,
    torch,
)


EIGHT_BLOCK_COUNT = 8
PUBLIC_WORD_TOKENS = 4 + EIGHT_BLOCK_COUNT * 16
EVENT_DIMENSION = 36
ADDRESS_DIMENSION = 12
_MASK32 = (1 << 32) - 1


class A526EightBlockO1Error(ValueError):
    """The public stream, reader configuration, or training row differs."""


@dataclass(frozen=True)
class A526EightBlockExample:
    public: PublicTargetView
    teacher_key: bytes
    example_id: str

    def validate(self) -> None:
        self.public.validate()
        if (
            self.public.block_count != EIGHT_BLOCK_COUNT
            or not isinstance(self.teacher_key, bytes)
            or len(self.teacher_key) != 32
            or not isinstance(self.example_id, str)
            or not self.example_id
        ):
            raise A526EightBlockO1Error("eight-block example differs")


@dataclass(frozen=True)
class A526EightBlockTrainingConfig:
    training_targets: int = 1024
    epochs: int = 6
    batch_size: int = 32
    learning_rate: float = 2e-3
    weight_decay: float = 1e-4
    cpu_threads: int = 2
    corpus_seed: int = 526036
    model_seed: int = 526204
    model_dimension: int = 32
    heads: int = 4
    head_dimension: int = 8
    holographic_slots: int = 4
    feedforward_dimension: int = 64

    def validate(self) -> None:
        for field, value, minimum, maximum in (
            ("training_targets", self.training_targets, 2, 1_000_000),
            ("epochs", self.epochs, 1, 10_000),
            ("batch_size", self.batch_size, 1, 4096),
            ("cpu_threads", self.cpu_threads, 1, 8),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise A526EightBlockO1Error(
                    f"{field} must be an integer in [{minimum},{maximum}]"
                )
        if self.batch_size > self.training_targets:
            raise A526EightBlockO1Error("batch_size exceeds training_targets")
        for field, value, allow_zero in (
            ("learning_rate", self.learning_rate, False),
            ("weight_decay", self.weight_decay, True),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0.0
                or (not allow_zero and float(value) == 0.0)
            ):
                raise A526EightBlockO1Error(f"{field} differs")
        O1StreamingCoreConfig(
            event_dimension=EVENT_DIMENSION,
            address_dimension=ADDRESS_DIMENSION,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            seed=self.model_seed,
        )

    @property
    def core_config(self) -> O1StreamingCoreConfig:
        self.validate()
        return O1StreamingCoreConfig(
            event_dimension=EVENT_DIMENSION,
            address_dimension=ADDRESS_DIMENSION,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            seed=self.model_seed,
        )

    def describe(self) -> dict[str, object]:
        self.validate()
        return {
            "training_targets": self.training_targets,
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "learning_rate": self.learning_rate,
            "weight_decay": self.weight_decay,
            "cpu_threads": self.cpu_threads,
            "corpus_seed": self.corpus_seed,
            "model_seed": self.model_seed,
            "core": self.core_config.describe(),
        }


def _word_bits(word: int) -> np.ndarray:
    return np.asarray(
        [1.0 if word & (1 << bit) else -1.0 for bit in range(32)],
        dtype=np.float32,
    )


def _address(
    kind: int,
    *,
    position: int,
    position_maximum: int,
    group: int,
    group_maximum: int,
    local: int,
    local_maximum: int,
    phase_index: int,
    phase_period: int,
) -> np.ndarray:
    value = np.zeros(ADDRESS_DIMENSION, dtype=np.float32)
    value[kind] = 1.0

    def normalized(item: int, maximum: int) -> float:
        return 0.0 if maximum == 0 else 2.0 * item / maximum - 1.0

    angle = 2.0 * math.pi * phase_index / phase_period
    value[4:] = (
        normalized(position, position_maximum),
        normalized(group, group_maximum),
        normalized(local, local_maximum),
        math.sin(angle),
        math.cos(angle),
        math.sin(3.0 * angle),
        math.cos(3.0 * angle),
        1.0,
    )
    return value


def encode_public_streams(
    public_views: Sequence[PublicTargetView],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Encode counter, nonce, and eight outputs without accepting a key label."""

    if not public_views:
        raise A526EightBlockO1Error("at least one public view is required")
    events = np.zeros(
        (len(public_views), PUBLIC_WORD_TOKENS, EVENT_DIMENSION),
        dtype=np.float32,
    )
    addresses = np.zeros(
        (len(public_views), PUBLIC_WORD_TOKENS, ADDRESS_DIMENSION),
        dtype=np.float32,
    )
    for batch, public in enumerate(public_views):
        if not isinstance(public, PublicTargetView):
            raise A526EightBlockO1Error("encoder accepts PublicTargetView only")
        public.validate()
        if public.block_count != EIGHT_BLOCK_COUNT:
            raise A526EightBlockO1Error("encoder requires exactly eight blocks")
        nonce_words = struct.unpack("<3I", public.nonce)
        header_words = (public.counter_schedule[0], *nonce_words)
        cursor = 0
        for header_index, word in enumerate(header_words):
            kind = 0 if header_index == 0 else 1
            events[batch, cursor, :32] = _word_bits(word)
            events[batch, cursor, 32 + kind] = 1.0
            addresses[batch, cursor] = _address(
                kind,
                position=header_index,
                position_maximum=3,
                group=header_index,
                group_maximum=3,
                local=0,
                local_maximum=0,
                phase_index=header_index,
                phase_period=4,
            )
            cursor += 1
        for block_index, block in enumerate(public.output_blocks):
            for lane, word in enumerate(struct.unpack("<16I", block)):
                output_index = block_index * 16 + lane
                events[batch, cursor, :32] = _word_bits(word)
                events[batch, cursor, 34] = 1.0
                addresses[batch, cursor] = _address(
                    2,
                    position=output_index,
                    position_maximum=127,
                    group=block_index,
                    group_maximum=7,
                    local=lane,
                    local_maximum=15,
                    phase_index=output_index,
                    phase_period=128,
                )
                cursor += 1
        if cursor != PUBLIC_WORD_TOKENS:
            raise AssertionError("public word stream length differs")
    update_mask = np.ones(
        (len(public_views), PUBLIC_WORD_TOKENS), dtype=np.bool_
    )
    return events, addresses, update_mask


def _query_arrays() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    events = np.zeros((A526_FIXED_WIDTH, 1, EVENT_DIMENSION), dtype=np.float32)
    addresses = np.zeros(
        (A526_FIXED_WIDTH, 1, ADDRESS_DIMENSION), dtype=np.float32
    )
    events[:, 0, 35] = 1.0
    for local, coordinate in enumerate(A526_FIXED_COORDINATES):
        addresses[local, 0] = _address(
            3,
            position=coordinate,
            position_maximum=KEY_BITS - 1,
            group=coordinate // 32,
            group_maximum=7,
            local=coordinate % 32,
            local_maximum=31,
            phase_index=coordinate,
            phase_period=KEY_BITS,
        )
    return events, addresses, np.zeros((A526_FIXED_WIDTH, 1), dtype=np.bool_)


if torch is not None:

    class A526EightBlockO1Reader(torch.nn.Module):
        """Existing O1 core plus an address-conditioned 204-bit query surface."""

        def __init__(self, config: O1StreamingCoreConfig) -> None:
            super().__init__()
            self.config = config
            self.reader = StreamingO1KeyReader(config)
            query_events, query_addresses, query_mask = _query_arrays()
            self.register_buffer(
                "query_events", torch.from_numpy(query_events), persistent=False
            )
            self.register_buffer(
                "query_addresses", torch.from_numpy(query_addresses), persistent=False
            )
            self.register_buffer(
                "query_mask", torch.from_numpy(query_mask), persistent=False
            )

        def forward(self, events, addresses, update_mask):
            _encoded, state = self.reader.core(events, addresses, update_mask)
            batch = int(events.shape[0])
            repeated = O1FastState(
                state.gssm_z.repeat_interleave(A526_FIXED_WIDTH, dim=0),
                state.holographic_real.repeat_interleave(A526_FIXED_WIDTH, dim=0),
                state.holographic_imaginary.repeat_interleave(
                    A526_FIXED_WIDTH, dim=0
                ),
            )
            logits, _held = self.reader(
                self.query_events.repeat(batch, 1, 1),
                self.query_addresses.repeat(batch, 1, 1),
                self.query_mask.repeat(batch, 1),
                repeated,
            )
            return logits[:, 0].reshape(batch, A526_FIXED_WIDTH)

else:  # pragma: no cover

    class A526EightBlockO1Reader:  # type: ignore[no-redef]
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise A526EightBlockO1Error("eight-block O1 training requires torch")


@dataclass(frozen=True)
class TrainedA526EightBlockReader:
    model: A526EightBlockO1Reader
    config: A526EightBlockTrainingConfig
    epoch_losses: tuple[float, ...]
    parameter_count: int
    model_sha256: str

    def predict_fixed_logits(
        self, public_views: Sequence[PublicTargetView], *, batch_size: int = 32
    ) -> np.ndarray:
        if torch is None:  # pragma: no cover
            raise A526EightBlockO1Error("eight-block O1 inference requires torch")
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or batch_size < 1
        ):
            raise A526EightBlockO1Error("prediction batch_size must be positive")
        rows: list[np.ndarray] = []
        self.model.eval()
        with torch.no_grad():
            for start in range(0, len(public_views), batch_size):
                batch = public_views[start : start + batch_size]
                events, addresses, mask = encode_public_streams(batch)
                logits = self.model(
                    torch.from_numpy(events),
                    torch.from_numpy(addresses),
                    torch.from_numpy(mask),
                )
                rows.append(logits.cpu().numpy().astype(np.float64))
        if not rows:
            raise A526EightBlockO1Error("at least one public view is required")
        return np.concatenate(rows, axis=0)

    def predict_full_logits(
        self, public_views: Sequence[PublicTargetView], *, batch_size: int = 32
    ) -> np.ndarray:
        fixed = self.predict_fixed_logits(public_views, batch_size=batch_size)
        result = np.zeros((fixed.shape[0], KEY_BITS), dtype=np.float64)
        result[:, A526_RESIDUAL_WIDTH:] = fixed
        return result


def _model_sha256(model: A526EightBlockO1Reader) -> str:
    if torch is None:  # pragma: no cover
        raise A526EightBlockO1Error("model hashing requires torch")
    digest = hashlib.sha256()
    for name, tensor in sorted(model.state_dict().items()):
        encoded = name.encode("utf-8")
        payload = (
            tensor.detach()
            .cpu()
            .contiguous()
            .numpy()
            .astype("<f4", copy=False)
            .tobytes()
        )
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack(">Q", len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def generate_uniform_eight_block_examples(
    *, count: int, seed: int
) -> tuple[A526EightBlockExample, ...]:
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or isinstance(seed, bool)
        or not isinstance(seed, int)
    ):
        raise A526EightBlockO1Error("uniform corpus count or seed differs")
    rows = []
    for index in range(count):
        material = hashlib.shake_256(
            canonical_json_bytes(["a526-eight-block-uniform", seed, index])
        ).digest(48)
        key = material[:32]
        counter = int.from_bytes(material[32:36], "little") % (
            UINT32_MASK - EIGHT_BLOCK_COUNT + 2
        )
        nonce = material[36:]
        public = PublicTargetView(
            counter_schedule=tuple(counter + offset for offset in range(8)),
            nonce=nonce,
            output_blocks=chacha20_blocks(key, counter, nonce, EIGHT_BLOCK_COUNT),
        )
        rows.append(
            A526EightBlockExample(
                public=public,
                teacher_key=key,
                example_id=f"uniform-{seed}-{index:06d}",
            )
        )
    return tuple(rows)


def train_a526_eight_block_reader(
    examples: Sequence[A526EightBlockExample],
    config: A526EightBlockTrainingConfig,
) -> TrainedA526EightBlockReader:
    """Fit the existing O1 bounded-state core against fixed bits 52..255."""

    if torch is None:  # pragma: no cover
        raise A526EightBlockO1Error("eight-block O1 training requires torch")
    config.validate()
    if len(examples) != config.training_targets:
        raise A526EightBlockO1Error("training example count differs from config")
    for example in examples:
        example.validate()
    torch.set_num_threads(config.cpu_threads)
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(config.model_seed)
    model = A526EightBlockO1Reader(config.core_config)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=config.learning_rate,
        weight_decay=config.weight_decay,
    )
    loss_function = torch.nn.BCEWithLogitsLoss()
    generator = torch.Generator(device="cpu").manual_seed(
        config.model_seed ^ 0xA526036
    )
    losses: list[float] = []
    for _epoch in range(config.epochs):
        model.train()
        permutation = torch.randperm(len(examples), generator=generator).tolist()
        total = 0.0
        consumed = 0
        for start in range(0, len(permutation), config.batch_size):
            indexes = permutation[start : start + config.batch_size]
            batch = [examples[index] for index in indexes]
            events, addresses, mask = encode_public_streams(
                [example.public for example in batch]
            )
            labels = np.stack(
                [
                    key_bits(example.teacher_key)[A526_RESIDUAL_WIDTH:]
                    for example in batch
                ]
            ).astype(np.float32, copy=False)
            optimizer.zero_grad(set_to_none=True)
            logits = model(
                torch.from_numpy(events),
                torch.from_numpy(addresses),
                torch.from_numpy(mask),
            )
            loss = loss_function(logits, torch.from_numpy(labels))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            count = len(batch)
            total += float(loss.detach()) * count
            consumed += count
        losses.append(total / consumed)
    parameters = sum(parameter.numel() for parameter in model.parameters())
    return TrainedA526EightBlockReader(
        model=model,
        config=config,
        epoch_losses=tuple(losses),
        parameter_count=parameters,
        model_sha256=_model_sha256(model),
    )


__all__ = [
    "A526EightBlockExample",
    "A526EightBlockO1Error",
    "A526EightBlockO1Reader",
    "A526EightBlockTrainingConfig",
    "ADDRESS_DIMENSION",
    "EIGHT_BLOCK_COUNT",
    "EVENT_DIMENSION",
    "PUBLIC_WORD_TOKENS",
    "TrainedA526EightBlockReader",
    "encode_public_streams",
    "generate_uniform_eight_block_examples",
    "train_a526_eight_block_reader",
]
