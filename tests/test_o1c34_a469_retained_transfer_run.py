from o1_crypto_lab.o1c34_a469_retained_transfer_run import (
    BYTE_INDEX,
    PASS_MAX_RANK,
    SOURCE_FREEZE_SHA256,
)


def test_o1c34_freezes_same_byte_and_two_target_median_gate() -> None:
    assert BYTE_INDEX == 3
    assert PASS_MAX_RANK == 128
    assert len(SOURCE_FREEZE_SHA256) == 64
