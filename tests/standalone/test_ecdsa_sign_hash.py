"""Tests for ECDSA_SIGN_HASH (INS 0x15).

The bulk of this test suite exercises the pre-approval error paths (wrong
length, bad P1/P2). The end-to-end sign flow (finalize -> UI approval ->
signature -> secp256k1 verify) requires golden snapshots for the new
"Review hash to sign" blind-signing screen and is deferred until we sort
out the finalize timing story shared with test_pq_sign_finalize.py.
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import CLA, Errors, InsType


def _payload(path: str, hash_bytes: bytes) -> bytes:
    if len(hash_bytes) != 32:
        raise ValueError("hash must be 32 bytes")
    return pack_derivation_path(path) + hash_bytes


def test_p1p2_must_be_zero(backend: BackendInterface) -> None:
    payload = _payload("m/44'/1'/0'/0'/0'", bytes(32))
    for p1, p2 in [(1, 0), (0, 1), (0xFF, 0), (0, 0xFF)]:
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(
                cla=CLA, ins=InsType.ECDSA_SIGN_HASH, p1=p1, p2=p2, data=payload
            )
        assert e.value.status == Errors.SWO_INCORRECT_P1_P2, (
            f"P1={p1:#x} P2={p2:#x} should have been rejected"
        )


def test_empty_data_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.ECDSA_SIGN_HASH, p1=0, p2=0, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_missing_hash_rejected(backend: BackendInterface) -> None:
    # BIP32 path present but the trailing 32-byte hash is missing entirely.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.ECDSA_SIGN_HASH,
            p1=0,
            p2=0,
            data=pack_derivation_path("m/44'/1'/0'/0'/0'"),
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_truncated_hash_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.ECDSA_SIGN_HASH,
            p1=0,
            p2=0,
            data=_payload("m/44'/1'/0'/0'/0'", bytes(31) + b"\x00")[:-1],  # 31 bytes of hash
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_extra_bytes_after_hash_rejected(backend: BackendInterface) -> None:
    # 33 bytes of "hash" past the path -> reject as wrong length.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.ECDSA_SIGN_HASH,
            p1=0,
            p2=0,
            data=_payload("m/44'/1'/0'/0'/0'", bytes(32)) + b"\x00",
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH
