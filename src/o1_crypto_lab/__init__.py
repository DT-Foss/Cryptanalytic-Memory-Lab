"""Bounded-state cryptanalytic evidence-stream research harness."""

from .benchmark import BenchmarkConfig, run_benchmark
from .composer import ChainComposer, default_registry
from .memory import (
    DirectBitVault,
    FullContextAttentionCeiling,
    HolographicBitMemory,
    StreamingEvidenceAccumulator,
)
from .replay import O1OSessionReplay

__all__ = [
    "BenchmarkConfig",
    "ChainComposer",
    "DirectBitVault",
    "FullContextAttentionCeiling",
    "HolographicBitMemory",
    "O1OSessionReplay",
    "StreamingEvidenceAccumulator",
    "default_registry",
    "run_benchmark",
]

__version__ = "0.1.0"
