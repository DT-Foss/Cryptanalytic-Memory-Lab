from o1_crypto_lab.o1c33_a465_retained_transfer_run import BYTE_INDEX, TARGETS


def test_o1c33_uses_two_disjoint_consumed_public_targets() -> None:
    assert BYTE_INDEX == 3
    assert [target.target_id for target in TARGETS] == [
        "RFC8439",
        "development-0000",
    ]
    assert len({target.public_view_sha256 for target in TARGETS}) == 2
    assert len({target.raw_sha256 for target in TARGETS}) == 2
