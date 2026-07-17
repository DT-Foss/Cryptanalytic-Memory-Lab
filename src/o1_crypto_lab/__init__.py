"""Bounded-state cryptanalytic evidence-stream research harness."""

from .benchmark import BenchmarkConfig, run_benchmark
from .composer import ChainComposer, default_registry
from .chacha_trace import ChaChaBlockTrace, chacha20_block_trace
from .full256_broker import Full256TargetBroker
from .living_inverse import ContrastFamily, PublicTargetView
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
    "ChaChaBlockTrace",
    "ContrastFamily",
    "DirectBitVault",
    "FullContextAttentionCeiling",
    "Full256TargetBroker",
    "HolographicBitMemory",
    "O1OSessionReplay",
    "PublicTargetView",
    "StreamingEvidenceAccumulator",
    "default_registry",
    "chacha20_block_trace",
    "run_benchmark",
]

__version__ = "0.1.0"
