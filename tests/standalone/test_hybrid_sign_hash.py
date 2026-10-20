"""Pre-approval tests for HYBRID_SIGN_HASH (INS 0x16).

Mirrors test_ecdsa_sign_hash.py's error-path coverage. The end-to-end flow
(finalize -> UI approval -> ECDSA sig inline + ML-DSA pk/sig via chunk fetch)
requires golden snapshots for the new "Review hybrid signature" screen and
is deferred until we sort out the ML-DSA post-approval timing story shared
with test_pq_sign_finalize.py.
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import CLA, Errors, InsType

# Every instruction exercised here is blind signing (the review screen cannot
# represent the bytes being signed), so the whole module needs the user opt-in.
pytestmark = pytest.mark.usefixtures("blind_signing_enabled")


def _payload(path: str, hash_bytes: bytes) -> bytes:
    if len(hash_bytes) != 32:
        raise ValueError("hash must be 32 bytes")
    return pack_derivation_path(path) + hash_bytes


def test_p1_must_be_zero_and_p2_is_the_parameter_set(backend: BackendInterface) -> None:
    # P1 must be 0. P2 selects the ML-DSA parameter set: 0x00 (ML-DSA-44) and
    # 0x01 (ML-DSA-65) are valid and start a review, anything else is rejected
    # (the valid values are exercised end to end in test_mldsa65.py).
    payload = _payload("m/44'/1'/0'/0'/0'", bytes(32))
    for p1, p2 in [(1, 0), (0xFF, 0), (1, 1), (0, 2), (0, 0x80), (0, 0xFF)]:
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(
                cla=CLA, ins=InsType.HYBRID_SIGN_HASH, p1=p1, p2=p2, data=payload
            )
        assert e.value.status == Errors.SWO_INCORRECT_P1_P2, (
            f"P1={p1:#x} P2={p2:#x} should have been rejected"
        )


def test_empty_data_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.HYBRID_SIGN_HASH, p1=0, p2=0, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_missing_hash_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.HYBRID_SIGN_HASH,
            p1=0,
            p2=0,
            data=pack_derivation_path("m/44'/1'/0'/0'/0'"),
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_truncated_hash_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.HYBRID_SIGN_HASH,
            p1=0,
            p2=0,
            data=_payload("m/44'/1'/0'/0'/0'", bytes(32))[:-1],  # 31 bytes of hash
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_extra_bytes_after_hash_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.HYBRID_SIGN_HASH,
            p1=0,
            p2=0,
            data=_payload("m/44'/1'/0'/0'/0'", bytes(32)) + b"\x00",
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


# The pre-approval security property (ML-DSA seed is not derived until the
# user approves, closing the ZKNOX seed-window bug) is verified by static
# reading of validate.c: mldsa_derive_seed lives inside the `if (choice)`
# branch of validate_hybrid_sign_hash, not in handler_hybrid_sign_hash. A
# runtime test would need to pause mid-UI without deadlocking Speculos.
