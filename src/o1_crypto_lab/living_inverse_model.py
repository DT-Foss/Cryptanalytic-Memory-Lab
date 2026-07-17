"""Deterministic CPU readers for the full-256 Living Inverse."""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Sequence

import numpy as np

try:  # The base harness remains NumPy-only; training is an explicit optional extra.
    import torch
    from torch import nn
except ImportError:  # pragma: no cover - exercised on minimal installations.
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


KEY_BITS = 256
MODEL_MAGIC = b"O1LIR1\x00"


class LivingInverseModelError(ValueError):
    """Raised when a reader, training array or frozen model differs."""


def require_torch() -> None:
    if torch is None or nn is None:
        raise LivingInverseModelError(
            "Living Inverse training requires the optional 'train' dependency"
        )


@dataclass(frozen=True)
class ReaderTrainingConfig:
    hidden_dimension: int = 128
    epochs: int = 4
    batch_size: int = 128
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    auxiliary_weight: float = 0.2
    cpu_threads: int = 1
    seed: int = 1
    shrinkage_grid: tuple[float, ...] = (
        0.0,
        1.0 / 64.0,
        1.0 / 32.0,
        1.0 / 16.0,
        1.0 / 8.0,
        1.0 / 4.0,
        1.0 / 2.0,
        1.0,
    )

    def validate(self) -> None:
        for name, value, minimum, maximum in (
            ("hidden_dimension", self.hidden_dimension, 8, 2048),
            ("epochs", self.epochs, 1, 10000),
            ("batch_size", self.batch_size, 1, 65536),
            ("cpu_threads", self.cpu_threads, 1, 8),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise LivingInverseModelError(
                    f"{name} must be an integer in [{minimum}, {maximum}]"
                )
        if not isinstance(self.seed, int) or isinstance(self.seed, bool):
            raise LivingInverseModelError("seed must be an integer")
        for name, value, allow_zero in (
            ("learning_rate", self.learning_rate, False),
            ("weight_decay", self.weight_decay, True),
            ("auxiliary_weight", self.auxiliary_weight, True),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0.0
                or (not allow_zero and float(value) == 0.0)
            ):
                comparator = ">= 0" if allow_zero else "> 0"
                raise LivingInverseModelError(f"{name} must be finite {comparator}")
        if (
            not isinstance(self.shrinkage_grid, tuple)
            or not self.shrinkage_grid
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= 1.0
                for value in self.shrinkage_grid
            )
            or tuple(sorted(set(self.shrinkage_grid))) != self.shrinkage_grid
            or self.shrinkage_grid[0] != 0.0
        ):
            raise LivingInverseModelError(
                "shrinkage_grid must be sorted unique finite values in [0,1] starting at 0"
            )

    def describe(self) -> dict[str, object]:
        self.validate()
        return {
            "hidden_dimension": self.hidden_dimension,
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "learning_rate": self.learning_rate,
            "weight_decay": self.weight_decay,
            "auxiliary_weight": self.auxiliary_weight,
            "cpu_threads": self.cpu_threads,
            "seed": self.seed,
            "shrinkage_grid": list(self.shrinkage_grid),
        }


if nn is not None:

    class KeyReaderMLP(nn.Module):
        def __init__(
            self, input_dimension: int, hidden_dimension: int, auxiliary_dimension: int
        ) -> None:
            super().__init__()
            self.input_dimension = input_dimension
            self.hidden_dimension = hidden_dimension
            self.auxiliary_dimension = auxiliary_dimension
            self.encoder = nn.Sequential(
                nn.Linear(input_dimension, hidden_dimension),
                nn.GELU(),
                nn.Linear(hidden_dimension, hidden_dimension),
                nn.GELU(),
            )
            self.key_head = nn.Linear(hidden_dimension, KEY_BITS)
            self.auxiliary_head = (
                nn.Linear(hidden_dimension, auxiliary_dimension)
                if auxiliary_dimension > 0
                else None
            )

        def forward(self, inputs):
            hidden = self.encoder(inputs)
            key_logits = self.key_head(hidden)
            auxiliary = (
                self.auxiliary_head(hidden) if self.auxiliary_head is not None else None
            )
            return key_logits, auxiliary

else:  # pragma: no cover

    class KeyReaderMLP:  # type: ignore[no-redef]
        pass


def _finite_array(
    value: np.ndarray | Sequence[Sequence[float]],
    field: str,
    *,
    columns: int | None = None,
) -> np.ndarray:
    result = np.asarray(value, dtype=np.float32)
    if result.ndim != 2 or result.shape[0] < 1:
        raise LivingInverseModelError(f"{field} must be a non-empty matrix")
    if columns is not None and result.shape[1] != columns:
        raise LivingInverseModelError(f"{field} must contain {columns} columns")
    if not np.all(np.isfinite(result)):
        raise LivingInverseModelError(f"{field} must be finite")
    return np.ascontiguousarray(result)


def _binary_labels(
    value: np.ndarray | Sequence[Sequence[float]], rows: int
) -> np.ndarray:
    result = _finite_array(value, "key labels", columns=KEY_BITS)
    if result.shape[0] != rows or np.any((result != 0.0) & (result != 1.0)):
        raise LivingInverseModelError("key labels must be a matched binary matrix")
    return result


def _configure_torch(config: ReaderTrainingConfig) -> None:
    require_torch()
    config.validate()
    torch.set_num_threads(config.cpu_threads)
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        # PyTorch permits this only before parallel work begins; the established
        # value is process-global and remains one in the experiment runner.
        pass
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(config.seed)


@dataclass
class TrainedReader:
    model: KeyReaderMLP
    config: ReaderTrainingConfig
    input_dimension: int
    auxiliary_dimension: int
    epoch_losses: tuple[float, ...]
    parameter_count: int
    model_sha256: str

    def predict_logits(
        self, features: np.ndarray, *, batch_size: int = 1024
    ) -> np.ndarray:
        require_torch()
        matrix = _finite_array(
            features, "prediction features", columns=self.input_dimension
        )
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or batch_size < 1
        ):
            raise LivingInverseModelError("prediction batch_size must be positive")
        self.model.eval()
        rows: list[np.ndarray] = []
        with torch.no_grad():
            for start in range(0, matrix.shape[0], batch_size):
                batch = torch.from_numpy(matrix[start : start + batch_size])
                logits, _auxiliary = self.model(batch)
                rows.append(logits.cpu().numpy().astype(np.float64))
        return np.concatenate(rows, axis=0)

    def frozen_bytes(self) -> bytes:
        return serialize_reader(self.model)


def train_reader(
    features: np.ndarray,
    key_labels: np.ndarray,
    config: ReaderTrainingConfig,
    *,
    auxiliary_labels: np.ndarray | None = None,
) -> TrainedReader:
    require_torch()
    _configure_torch(config)
    inputs = _finite_array(features, "training features")
    labels = _binary_labels(key_labels, inputs.shape[0])
    auxiliary = None
    auxiliary_dimension = 0
    if auxiliary_labels is not None:
        auxiliary = _finite_array(auxiliary_labels, "auxiliary labels")
        if auxiliary.shape[0] != inputs.shape[0]:
            raise LivingInverseModelError("auxiliary labels must match training rows")
        auxiliary_dimension = int(auxiliary.shape[1])

    model = KeyReaderMLP(
        int(inputs.shape[1]), config.hidden_dimension, auxiliary_dimension
    )
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=config.learning_rate,
        weight_decay=config.weight_decay,
    )
    binary_loss = nn.BCEWithLogitsLoss()
    auxiliary_loss = nn.SmoothL1Loss()
    generator = torch.Generator(device="cpu")
    generator.manual_seed(config.seed ^ 0x4F315256)
    input_tensor = torch.from_numpy(inputs)
    label_tensor = torch.from_numpy(labels)
    auxiliary_tensor = torch.from_numpy(auxiliary) if auxiliary is not None else None
    epoch_losses: list[float] = []

    for _epoch in range(config.epochs):
        model.train()
        permutation = torch.randperm(inputs.shape[0], generator=generator)
        total = 0.0
        consumed = 0
        for start in range(0, inputs.shape[0], config.batch_size):
            indexes = permutation[start : start + config.batch_size]
            batch_inputs = input_tensor[indexes]
            batch_labels = label_tensor[indexes]
            optimizer.zero_grad(set_to_none=True)
            logits, predicted_auxiliary = model(batch_inputs)
            loss = binary_loss(logits, batch_labels)
            if auxiliary_tensor is not None:
                if predicted_auxiliary is None:
                    raise AssertionError("auxiliary model head is absent")
                loss = loss + config.auxiliary_weight * auxiliary_loss(
                    predicted_auxiliary, auxiliary_tensor[indexes]
                )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            count = int(indexes.numel())
            total += float(loss.detach()) * count
            consumed += count
        epoch_losses.append(total / consumed)

    frozen = serialize_reader(model)
    return TrainedReader(
        model=model,
        config=config,
        input_dimension=int(inputs.shape[1]),
        auxiliary_dimension=auxiliary_dimension,
        epoch_losses=tuple(epoch_losses),
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        model_sha256=hashlib.sha256(frozen).hexdigest(),
    )


def serialize_reader(model: KeyReaderMLP) -> bytes:
    require_torch()
    if not isinstance(model, KeyReaderMLP):
        raise LivingInverseModelError("model must be KeyReaderMLP")
    tensors = []
    payloads = []
    offset = 0
    for name, tensor in sorted(model.state_dict().items()):
        array = np.ascontiguousarray(tensor.detach().cpu().numpy().astype("<f4"))
        payload = array.tobytes()
        tensors.append(
            {
                "name": name,
                "shape": list(array.shape),
                "dtype": "float32-le",
                "offset": offset,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        payloads.append(payload)
        offset += len(payload)
    header = {
        "schema": "o1-256-key-reader-v1",
        "input_dimension": model.input_dimension,
        "hidden_dimension": model.hidden_dimension,
        "auxiliary_dimension": model.auxiliary_dimension,
        "tensors": tensors,
        "payload_bytes": offset,
    }
    header_bytes = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return (
        MODEL_MAGIC
        + struct.pack(">Q", len(header_bytes))
        + header_bytes
        + b"".join(payloads)
    )


def deserialize_reader(value: bytes) -> KeyReaderMLP:
    require_torch()
    if not isinstance(value, bytes) or not value.startswith(MODEL_MAGIC):
        raise LivingInverseModelError("frozen reader magic differs")
    cursor = len(MODEL_MAGIC)
    if len(value) < cursor + 8:
        raise LivingInverseModelError("frozen reader header is truncated")
    header_length = struct.unpack(">Q", value[cursor : cursor + 8])[0]
    cursor += 8
    try:
        header = json.loads(value[cursor : cursor + header_length].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LivingInverseModelError("frozen reader header is invalid") from exc
    cursor += header_length
    if not isinstance(header, dict) or header.get("schema") != "o1-256-key-reader-v1":
        raise LivingInverseModelError("frozen reader schema differs")
    model = KeyReaderMLP(
        int(header["input_dimension"]),
        int(header["hidden_dimension"]),
        int(header["auxiliary_dimension"]),
    )
    state = model.state_dict()
    tensors = header.get("tensors")
    if not isinstance(tensors, list):
        raise LivingInverseModelError("frozen reader tensor inventory differs")
    seen: set[str] = set()
    payload_base = cursor
    for row in tensors:
        if not isinstance(row, dict) or set(row) != {
            "name",
            "shape",
            "dtype",
            "offset",
            "bytes",
            "sha256",
        }:
            raise LivingInverseModelError("frozen reader tensor row differs")
        name = row["name"]
        if not isinstance(name, str) or name not in state or name in seen:
            raise LivingInverseModelError("frozen reader tensor name differs")
        seen.add(name)
        if row["dtype"] != "float32-le":
            raise LivingInverseModelError("frozen reader tensor dtype differs")
        start = payload_base + int(row["offset"])
        end = start + int(row["bytes"])
        payload = value[start:end]
        if (
            len(payload) != int(row["bytes"])
            or hashlib.sha256(payload).hexdigest() != row["sha256"]
        ):
            raise LivingInverseModelError("frozen reader tensor payload differs")
        shape = tuple(int(dimension) for dimension in row["shape"])
        array = np.frombuffer(payload, dtype="<f4").reshape(shape).copy()
        if tuple(state[name].shape) != shape:
            raise LivingInverseModelError("frozen reader tensor shape differs")
        state[name] = torch.from_numpy(array)
    if seen != set(state):
        raise LivingInverseModelError("frozen reader tensor set is incomplete")
    if len(value) != payload_base + int(header["payload_bytes"]):
        raise LivingInverseModelError("frozen reader has trailing or missing bytes")
    model.load_state_dict(state, strict=True)
    model.eval()
    return model


def binary_nll_bits(logits: np.ndarray, labels: np.ndarray, shrinkage: float) -> float:
    matrix = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape != truth.shape or matrix.shape[1] != KEY_BITS:
        raise LivingInverseModelError(
            "logits and labels must be matched Nx256 matrices"
        )
    if not np.all(np.isfinite(matrix)) or np.any((truth != 0.0) & (truth != 1.0)):
        raise LivingInverseModelError("logits must be finite and labels binary")
    if (
        isinstance(shrinkage, bool)
        or not isinstance(shrinkage, (int, float))
        or not math.isfinite(float(shrinkage))
        or not 0.0 <= float(shrinkage) <= 1.0
    ):
        raise LivingInverseModelError("shrinkage must be finite in [0, 1]")
    scaled = matrix * float(shrinkage)
    losses = np.logaddexp(0.0, scaled) - truth * scaled
    return float(np.mean(np.sum(losses, axis=1) / math.log(2.0)))


def select_shrinkage(
    calibration_logits: np.ndarray,
    calibration_labels: np.ndarray,
    grid: Sequence[float],
) -> tuple[float, tuple[dict[str, float], ...]]:
    candidates = tuple(float(value) for value in grid)
    if not candidates:
        raise LivingInverseModelError("shrinkage grid is empty")
    rows = tuple(
        {
            "shrinkage": value,
            "mean_key_nll_bits": binary_nll_bits(
                calibration_logits, calibration_labels, value
            ),
        }
        for value in candidates
    )
    selected = min(rows, key=lambda row: (row["mean_key_nll_bits"], row["shrinkage"]))
    return float(selected["shrinkage"]), rows


def posterior_from_logits(logits: np.ndarray, shrinkage: float) -> np.ndarray:
    matrix = np.asarray(logits, dtype=np.float64)
    if (
        matrix.ndim != 2
        or matrix.shape[1] != KEY_BITS
        or not np.all(np.isfinite(matrix))
    ):
        raise LivingInverseModelError("logits must be a finite Nx256 matrix")
    scaled = np.clip(matrix * float(shrinkage), -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-scaled))


def evaluate_posteriors(
    probabilities: np.ndarray,
    labels: np.ndarray,
    *,
    stable_accuracy: float = 0.55,
    stable_nll_gain: float = 0.002,
) -> dict[str, object]:
    values = np.asarray(probabilities, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if values.ndim != 2 or values.shape != truth.shape or values.shape[1] != KEY_BITS:
        raise LivingInverseModelError("probabilities and labels must be matched Nx256")
    if not np.all(np.isfinite(values)) or np.any((values <= 0.0) | (values >= 1.0)):
        raise LivingInverseModelError("probabilities must be finite in (0,1)")
    if np.any((truth != 0.0) & (truth != 1.0)):
        raise LivingInverseModelError("labels must be binary")
    selected = np.where(truth == 1.0, values, 1.0 - values)
    per_target_nll = -np.log2(selected).sum(axis=1)
    per_bit_nll = -np.log2(selected).mean(axis=0)
    predictions = values >= 0.5
    per_bit_accuracy = np.mean(predictions == truth, axis=0)
    stable = (per_bit_accuracy >= stable_accuracy) & (
        per_bit_nll <= 1.0 - stable_nll_gain
    )
    order = np.lexsort((np.arange(KEY_BITS), per_bit_nll))
    top = [
        {
            "bit": int(bit),
            "accuracy": float(per_bit_accuracy[bit]),
            "nll_bits": float(per_bit_nll[bit]),
            "nll_gain_bits": float(1.0 - per_bit_nll[bit]),
        }
        for bit in order[:16]
    ]
    payload = values.astype("<f8", copy=False).tobytes()
    return {
        "schema": "o1-256-reader-evaluation-v1",
        "targets": int(values.shape[0]),
        "mean_key_nll_bits": float(np.mean(per_target_nll)),
        "median_key_nll_bits": float(np.median(per_target_nll)),
        "minimum_key_nll_bits": float(np.min(per_target_nll)),
        "maximum_key_nll_bits": float(np.max(per_target_nll)),
        "mean_effective_compression_bits": float(KEY_BITS - np.mean(per_target_nll)),
        "bit_accuracy": float(np.mean(predictions == truth)),
        "stable_accuracy_threshold": stable_accuracy,
        "stable_nll_gain_threshold": stable_nll_gain,
        "stable_bits": int(np.count_nonzero(stable)),
        "stable_bit_coordinates": [int(value) for value in np.flatnonzero(stable)],
        "top_bits": top,
        "posterior_set_sha256": hashlib.sha256(payload).hexdigest(),
    }
