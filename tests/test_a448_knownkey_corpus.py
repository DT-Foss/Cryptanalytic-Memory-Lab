from __future__ import annotations

import pytest

from o1_crypto_lab.a448_knownkey_corpus import (
    A448_TARGETS,
    default_sibling_root,
    load_a448_knownkey_corpus,
)


@pytest.mark.skipif(
    not default_sibling_root().exists(), reason="read-only sibling corpus is absent"
)
def test_complete_a448_corpus_exposes_only_public_deployment_views() -> None:
    rows = load_a448_knownkey_corpus()
    assert len(rows) == A448_TARGETS
    assert {row.block for row in rows} == set(range(8))
    assert all(row.public.block_count == 8 for row in rows)
    assert len({row.public.digest() for row in rows}) == A448_TARGETS
    assert len({row.teacher_key for row in rows}) == A448_TARGETS
    deployment = rows[0].public.describe()
    assert deployment["unknown_key_bits"] == 256
    assert deployment["target_key_included"] is False
    assert "known_zeroed_key_words" not in deployment
    assert "unknown_assignment" not in deployment
