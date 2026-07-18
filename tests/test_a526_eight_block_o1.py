from __future__ import annotations

import numpy as np
import pytest

from o1_crypto_lab.a526_eight_block_o1 import (
    ADDRESS_DIMENSION,
    EVENT_DIMENSION,
    PUBLIC_WORD_TOKENS,
    A526EightBlockTrainingConfig,
    encode_public_streams,
    generate_uniform_eight_block_examples,
    train_a526_eight_block_reader,
)
from o1_crypto_lab.o1_streaming_core import torch


def test_public_encoder_has_fixed_stream_shape_and_no_label_argument() -> None:
    rows = generate_uniform_eight_block_examples(count=2, seed=41)
    events, addresses, mask = encode_public_streams([row.public for row in rows])
    assert events.shape == (2, PUBLIC_WORD_TOKENS, EVENT_DIMENSION)
    assert addresses.shape == (2, PUBLIC_WORD_TOKENS, ADDRESS_DIMENSION)
    assert mask.shape == (2, PUBLIC_WORD_TOKENS)
    assert events.dtype == np.float32
    assert addresses.dtype == np.float32
    assert mask.dtype == np.bool_
    assert bool(mask.all())


@pytest.mark.skipif(torch is None, reason="optional torch dependency is absent")
def test_tiny_reader_trains_and_emits_native_a526_logits() -> None:
    config = A526EightBlockTrainingConfig(
        training_targets=4,
        epochs=1,
        batch_size=2,
        cpu_threads=1,
        model_dimension=8,
        heads=1,
        head_dimension=4,
        holographic_slots=1,
        feedforward_dimension=16,
    )
    rows = generate_uniform_eight_block_examples(
        count=config.training_targets, seed=config.corpus_seed
    )
    trained = train_a526_eight_block_reader(rows, config)
    logits = trained.predict_full_logits([rows[0].public])
    assert logits.shape == (1, 256)
    assert np.isfinite(logits).all()
    assert np.array_equal(logits[0, :52], np.zeros(52))
    assert len(trained.epoch_losses) == 1
    assert trained.parameter_count > 0
