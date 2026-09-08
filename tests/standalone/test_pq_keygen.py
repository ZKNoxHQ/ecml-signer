"""Tests for the ML-DSA keygen and chunk-fetch INS codes.

Phase 2a covers:
  * KEYGEN_DILITHIUM_CORE (INS 0x0c) - keygen from a caller-supplied 32-byte seed
  * KEYGEN_DILITHIUM      (INS 0x11) - keygen from a BIP32 path (SLIP-0010)
  * GET_PK_CHUNK          (INS 0x13) - fetch pk in <=255-byte chunks
  * GET_SIG_CHUNK         (INS 0x12) - fetch sig in <=255-byte chunks

No UI approval is required (this is the low-level primitive surface).
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import CLA, Errors, InsType

# End-to-end interop with an external FIPS 204 reference (noble-post-quantum
# and the parity with SIGN_TX_MLDSA) is covered separately by:
#   - tests/standalone/test_sign_mldsa_cmd.py (verifies sig against the exported pk)
#   - js/ smoke tests (noble round trip)
# The tests here only cover this INS family's internal contract.


PK_BYTES = 1312
SIG_BYTES = 2420
PK_CHUNK_SIZES = [255, 255, 255, 255, 255, 37]  # 5*255 + 37 = 1312
SIG_CHUNK_SIZES = [255] * 9 + [125]  # 9*255 + 125 = 2420


def _fetch(backend: BackendInterface, ins: InsType, chunk_sizes: list[int]) -> bytes:
    out = b""
    for i, size in enumerate(chunk_sizes):
        rapdu = backend.exchange(cla=CLA, ins=ins, p1=i, p2=size, data=b"")
        assert rapdu.status == Errors.SWO_SUCCESS
        assert len(rapdu.data) == size, f"chunk {i}: got {len(rapdu.data)}, expected {size}"
        out += rapdu.data
    return out


def _fetch_pk(backend: BackendInterface) -> bytes:
    return _fetch(backend, InsType.GET_PK_CHUNK, PK_CHUNK_SIZES)


def _fetch_sig(backend: BackendInterface) -> bytes:
    return _fetch(backend, InsType.GET_SIG_CHUNK, SIG_CHUNK_SIZES)


# ---------------------------------------------------------------------------
# KEYGEN_DILITHIUM_CORE (0x0c) - seed-driven keygen
# ---------------------------------------------------------------------------


def test_keygen_core_deterministic(backend: BackendInterface) -> None:
    seed = bytes([0x42] * 32)
    backend.exchange(cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=seed)
    pk1 = _fetch_pk(backend)
    backend.exchange(cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=seed)
    pk2 = _fetch_pk(backend)
    assert pk1 == pk2
    assert len(pk1) == PK_BYTES
    # ML-DSA-44 pk = rho(32) || t1_packed(1280). rho is the seed's SHAKE-derived
    # public matrix seed; changes with seed. Bytes 32..1312 are t1 - not zeroes.
    assert pk1[:32] != b"\x00" * 32
    assert pk1[32:64] != b"\x00" * 32


def test_keygen_core_seed_sensitivity(backend: BackendInterface) -> None:
    for seed_byte in (0x00, 0x01):
        seed = bytes([seed_byte] * 32)
        backend.exchange(cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=seed)
    pk_after_second = _fetch_pk(backend)
    # Now re-derive from the first seed; the pk in the device must change back.
    backend.exchange(
        cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=bytes([0x00] * 32)
    )
    pk_after_first = _fetch_pk(backend)
    assert pk_after_first != pk_after_second


def test_keygen_core_wrong_seed_length(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=bytes(31)
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_keygen_core_rejects_wrong_p1p2(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=1, p2=0, data=bytes(32)
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_keygen_core_wipes_sig_buffer(backend: BackendInterface) -> None:
    # Fetching sig chunks after a fresh keygen must return zeros (buffer is
    # scrubbed so a stale sig from a prior flow cannot leak).
    backend.exchange(
        cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=bytes(32)
    )
    sig = _fetch_sig(backend)
    assert sig == b"\x00" * SIG_BYTES


# ---------------------------------------------------------------------------
# KEYGEN_DILITHIUM (0x11) - BIP32-driven keygen
# ---------------------------------------------------------------------------


def test_keygen_from_bip32_deterministic(backend: BackendInterface) -> None:
    path_bytes = pack_derivation_path("m/44'/1'/0'/0'/0'")
    r1 = backend.exchange(
        cla=CLA, ins=InsType.KEYGEN_DILITHIUM, p1=0, p2=0, data=path_bytes
    )
    assert r1.status == Errors.SWO_SUCCESS
    pk1 = _fetch_pk(backend)

    r2 = backend.exchange(
        cla=CLA, ins=InsType.KEYGEN_DILITHIUM, p1=0, p2=0, data=path_bytes
    )
    assert r2.status == Errors.SWO_SUCCESS
    pk2 = _fetch_pk(backend)
    assert pk1 == pk2
    assert len(pk1) == PK_BYTES


def test_keygen_from_bip32_path_sensitivity(backend: BackendInterface) -> None:
    p1 = pack_derivation_path("m/44'/1'/0'/0'/0'")
    p2 = pack_derivation_path("m/44'/1'/0'/0'/1'")
    backend.exchange(cla=CLA, ins=InsType.KEYGEN_DILITHIUM, p1=0, p2=0, data=p1)
    pk1 = _fetch_pk(backend)
    backend.exchange(cla=CLA, ins=InsType.KEYGEN_DILITHIUM, p1=0, p2=0, data=p2)
    pk2 = _fetch_pk(backend)
    assert pk1 != pk2


# ---------------------------------------------------------------------------
# GET_PK_CHUNK / GET_SIG_CHUNK (0x12/0x13) - bounds check
# ---------------------------------------------------------------------------


def test_chunk_out_of_bounds_rejected(backend: BackendInterface) -> None:
    # Prime the buffers with a keygen first.
    backend.exchange(
        cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=bytes(32)
    )

    # pk is 1312 bytes; chunk (p1=5, p2=38) would read to offset 1313 -> reject.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.GET_PK_CHUNK, p1=5, p2=38, data=b""
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH

    # sig is 2420 bytes; chunk (p1=9, p2=126) would read to offset 2421 -> reject.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.GET_SIG_CHUNK, p1=9, p2=126, data=b""
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_chunk_exact_bounds_accepted(backend: BackendInterface) -> None:
    backend.exchange(
        cla=CLA, ins=InsType.KEYGEN_DILITHIUM_CORE, p1=0, p2=0, data=bytes(32)
    )
    # Last valid pk chunk: p1=5, p2=37 -> reads pk[1275..1312).
    r = backend.exchange(cla=CLA, ins=InsType.GET_PK_CHUNK, p1=5, p2=37, data=b"")
    assert r.status == Errors.SWO_SUCCESS
    assert len(r.data) == 37


def test_chunk_way_past_end(backend: BackendInterface) -> None:
    # Extreme case: p1=255 * p2=255 would be offset 65025 - well past both buffers.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.GET_PK_CHUNK, p1=255, p2=255, data=b""
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH
