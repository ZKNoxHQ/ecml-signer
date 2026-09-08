"""Tests for the ZKNOX post-quantum primitive INS codes.

Phase 1 covers:
  * DUMMY (INS 0x0a) - echo cdata
  * SAMPLE_IN_BALL (INS 0x0b) - ML-DSA SampleInBall via cx_mldsa_sample

No state, no UI, no device approval.
"""

import struct

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import CLA, Errors, InsType


# ---------------------------------------------------------------------------
# DUMMY (0x0a)
# ---------------------------------------------------------------------------


def test_dummy_echo(backend: BackendInterface) -> None:
    payload = bytes(range(64))
    rapdu = backend.exchange(cla=CLA, ins=InsType.DUMMY, p1=0, p2=0, data=payload)
    assert rapdu.status == Errors.SWO_SUCCESS
    assert rapdu.data == payload


def test_dummy_short(backend: BackendInterface) -> None:
    rapdu = backend.exchange(cla=CLA, ins=InsType.DUMMY, p1=0, p2=0, data=b"\xaa")
    assert rapdu.status == Errors.SWO_SUCCESS
    assert rapdu.data == b"\xaa"


def test_dummy_rejects_empty_data(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.DUMMY, p1=0, p2=0, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_dummy_accepts_any_p1p2(backend: BackendInterface) -> None:
    # DUMMY is a smoke test; unlike other INS it must not gate on P1/P2.
    rapdu = backend.exchange(cla=CLA, ins=InsType.DUMMY, p1=0xAB, p2=0xCD, data=b"hi")
    assert rapdu.status == Errors.SWO_SUCCESS
    assert rapdu.data == b"hi"


# ---------------------------------------------------------------------------
# SAMPLE_IN_BALL (0x0b)
# ---------------------------------------------------------------------------

# Response is 1024 bytes = 256 * int32 (raw mldsa_poly.coeffs, little-endian).
# ML-DSA-44 tau = 39: exactly 39 nonzero coefficients, each in {-1, +1}.
POLY_BYTES = 1024
POLY_N = 256
MLDSA44_TAU = 39


def _unpack_challenge(response: bytes) -> list[int]:
    assert len(response) == POLY_BYTES, f"expected {POLY_BYTES} bytes, got {len(response)}"
    return list(struct.unpack("<" + "i" * POLY_N, response))


def test_sample_in_ball_length(backend: BackendInterface) -> None:
    c_tilde = bytes(32)  # zeroes -> deterministic well-defined output
    rapdu = backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=c_tilde)
    assert rapdu.status == Errors.SWO_SUCCESS
    assert len(rapdu.data) == POLY_BYTES


def test_sample_in_ball_challenge_shape(backend: BackendInterface) -> None:
    # SampleInBall's contract: exactly TAU nonzero coefficients in {-1, +1},
    # rest are 0. In signed int32 representation, -1 = 0xFFFFFFFF but sig-extended.
    c_tilde = bytes([0x11] * 32)
    rapdu = backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=c_tilde)
    coeffs = _unpack_challenge(rapdu.data)

    nonzero = [c for c in coeffs if c != 0]
    assert len(nonzero) == MLDSA44_TAU, f"expected {MLDSA44_TAU} nonzero, got {len(nonzero)}"
    assert all(c in (-1, 1) for c in nonzero), (
        f"nonzero coefficients must be in {{-1, +1}}, got unexpected values: "
        f"{sorted({c for c in nonzero if c not in (-1, 1)})}"
    )


def test_sample_in_ball_deterministic(backend: BackendInterface) -> None:
    # Same c_tilde must produce the same polynomial (FIPS 204 requirement).
    c_tilde = b"\xde\xad\xbe\xef" * 8
    r1 = backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=c_tilde)
    r2 = backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=c_tilde)
    assert r1.data == r2.data


def test_sample_in_ball_seed_sensitivity(backend: BackendInterface) -> None:
    # A single-bit change in c_tilde must produce a different polynomial.
    seed_a = b"\x00" * 32
    seed_b = b"\x01" + b"\x00" * 31
    ra = backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=seed_a)
    rb = backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=seed_b)
    assert ra.data != rb.data


def test_sample_in_ball_rejects_empty_data(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SAMPLE_IN_BALL, p1=0, p2=0, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH
