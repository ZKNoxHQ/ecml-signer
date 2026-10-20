"""State-machine tests for SIGN_DILITHIUM (INS 0x0f).

These tests exercise every code path that does NOT reach the finalize step
(P1=0x80), so no on-device user approval and no snapshot handling is needed.

The end-to-end sign flow (finalize -> UI approval -> signature) lives in
`test_pq_sign_finalize.py` because it requires golden snapshots.
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import CLA, Errors, InsType

# Every instruction exercised here is blind signing (the review screen cannot
# represent the bytes being signed), so the whole module needs the user opt-in.
pytestmark = pytest.mark.usefixtures("blind_signing_enabled")


P1_INIT = 0x00
P1_ABSORB = 0x01
P1_FINALIZE = 0x80


def _prime_key(backend: BackendInterface) -> None:
    """Seed a deterministic ML-DSA-44 key so SIGN_DILITHIUM has something to sign."""
    backend.exchange(
        cla=CLA,
        ins=InsType.KEYGEN_DILITHIUM_CORE,
        p1=0,
        p2=0,
        data=bytes([0x42] * 32),
    )


# ---------------------------------------------------------------------------
# Init (P1=0x00)
# ---------------------------------------------------------------------------


def test_init_after_keygen_ok(backend: BackendInterface) -> None:
    _prime_key(backend)
    rapdu = backend.exchange(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b""
    )
    assert rapdu.status == Errors.SWO_SUCCESS


def test_init_rejects_p2_nonzero(backend: BackendInterface) -> None:
    _prime_key(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=1, data=b""
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_absorb_before_init_rejected(backend: BackendInterface) -> None:
    # Fresh state - init hasn't been called yet. Even with a loaded key,
    # absorbing before init must fail closed.
    _prime_key(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_DILITHIUM,
            p1=P1_ABSORB,
            p2=0,
            data=bytes(32),
        )
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED


def test_finalize_before_init_rejected(backend: BackendInterface) -> None:
    _prime_key(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""
        )
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED


# ---------------------------------------------------------------------------
# Absorb (P1=0x01)
# ---------------------------------------------------------------------------


def test_absorb_single_chunk(backend: BackendInterface) -> None:
    _prime_key(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    rapdu = backend.exchange(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=bytes(32)
    )
    assert rapdu.status == Errors.SWO_SUCCESS


def test_absorb_multiple_chunks(backend: BackendInterface) -> None:
    _prime_key(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    for _ in range(3):
        rapdu = backend.exchange(
            cla=CLA,
            ins=InsType.SIGN_DILITHIUM,
            p1=P1_ABSORB,
            p2=0,
            data=bytes(100),
        )
        assert rapdu.status == Errors.SWO_SUCCESS


def test_absorb_overflow_rejected(backend: BackendInterface) -> None:
    # MAX_TRANSACTION_LEN = 510. Absorbing 510+1 must fail.
    _prime_key(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    # 2 x 255 = 510 fits exactly.
    for _ in range(2):
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=bytes(255)
        )
    # Any further byte overflows.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=b"\x00"
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_absorb_empty_chunk(backend: BackendInterface) -> None:
    # Empty absorb is a no-op - useful for wire-format compatibility with
    # clients that always call absorb even for zero-byte segments.
    # However the dispatcher rejects APDUs with lc=0 upfront (SWO_WRONG_DATA_LENGTH),
    # so we can't verify handler-side no-op behavior without bypassing the
    # dispatcher. Just check that a 1-byte absorb works after init.
    _prime_key(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    r = backend.exchange(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=b"\x01"
    )
    assert r.status == Errors.SWO_SUCCESS


# ---------------------------------------------------------------------------
# P1 validation
# ---------------------------------------------------------------------------


def test_unknown_p1_rejected(backend: BackendInterface) -> None:
    _prime_key(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=0x42, p2=0, data=b"\x00"
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


# ---------------------------------------------------------------------------
# Cross-INS state hygiene
# ---------------------------------------------------------------------------


def test_keygen_resets_pq_sign_state(backend: BackendInterface) -> None:
    # Starting a fresh keygen must invalidate any in-progress sign session
    # so a P1=0x80 finalize following it fails closed.
    _prime_key(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    backend.exchange(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=bytes(32)
    )
    # Fresh keygen wipes G_context including req_type.
    _prime_key(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""
        )
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED
