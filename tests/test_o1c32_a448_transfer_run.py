from o1_crypto_lab.o1c32_a448_transfer_run import (
    BYTE_INDEX,
    EXPECTED_PUBLIC_SHA256,
    consumed_target,
)


def test_consumed_target_reconstructs_prior_public_view() -> None:
    target = consumed_target()

    assert target.target_id == "development-0000"
    assert target.public.digest() == EXPECTED_PUBLIC_SHA256
    assert target.public.describe()["unknown_key_bits"] == 256
    assert target._key[BYTE_INDEX] == 0x0F
