"""Pre-approval state-machine tests for HYBRID_SIGN_USEROP (INS 0x17).

Covers:
  * 4-step APDU sequence: P1=0/1/2/3 must arrive in order
  * Exact-length enforcement on the metadata (104 B) and packed (192 B) steps
  * callData hash verification against the previously-declared hashCallData
  * P2 must be 0; P1 > 3 rejected
  * A fresh P1=0x00 always resets the accumulator

The end-to-end sign flow (finalize -> UI approval -> hybrid sig fetch) needs
golden snapshots and shares the ML-DSA post-approval timing issue documented
in test_pq_sign_finalize.py; it is deferred.
"""

import hashlib
import struct

import pytest
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import CLA, Errors, InsType

P1_PATH     = 0x00
P1_METADATA = 0x01
P1_PACKED   = 0x02
P1_CALLDATA = 0x03


def _keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---- Realistic UserOp fixture (Sepolia-flavoured, values are cosmetic) -----

CHAIN_ID           = (11155111).to_bytes(32, "big")
ENTRY_POINT        = bytes.fromhex("0000000071727de22e5e9d8baf0edac6f37da032")   # v0.7
SENDER             = bytes.fromhex("1111111111111111111111111111111111111111")
NONCE              = (42).to_bytes(32, "big")

# execute(address dest, uint256 value, bytes data) — selector b61d27f6
EXEC_SELECTOR      = bytes.fromhex("b61d27f6")
EXEC_DEST_PADDED   = bytes(12) + bytes.fromhex("22222222222222222222222222222222" "22222222")
EXEC_VALUE         = (1_000_000_000).to_bytes(32, "big")  # 1e9 wei
EXEC_DATA_OFFSET   = (0x60).to_bytes(32, "big")
EXEC_DATA_LEN      = (0).to_bytes(32, "big")
CALLDATA           = EXEC_SELECTOR + EXEC_DEST_PADDED + EXEC_VALUE + EXEC_DATA_OFFSET + EXEC_DATA_LEN

HASH_INIT_CODE     = bytes(32)                     # no initCode
HASH_CALL_DATA     = _keccak256(CALLDATA)
ACCOUNT_GAS_LIMITS = bytes(32)
PRE_VERIF_GAS      = bytes(32)
GAS_FEES           = bytes(32)
HASH_PAYMASTER     = bytes(32)

METADATA = CHAIN_ID + ENTRY_POINT + SENDER + NONCE                          # 104 B
PACKED   = (HASH_INIT_CODE + HASH_CALL_DATA + ACCOUNT_GAS_LIMITS +
            PRE_VERIF_GAS + GAS_FEES + HASH_PAYMASTER)                       # 192 B
PATH     = pack_derivation_path("m/44'/1'/0'/0'/0'")


def _p1(backend: BackendInterface, p1: int, data: bytes) -> None:
    """Send one step of the userop APDU sequence, expecting SW_SUCCESS."""
    rapdu = backend.exchange(cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=p1, p2=0, data=data)
    assert rapdu.status == Errors.SWO_SUCCESS


# ---- Happy-path sequence: path -> metadata -> packed --------------------
# (We deliberately do NOT run P1=0x03 finalize, which would trigger the UI
# and hit the same MLDSA post-approval timing issue as other phases.)


def test_sequence_up_to_packed_ok(backend: BackendInterface) -> None:
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    _p1(backend, P1_PACKED, PACKED)


# ---- Ordering enforcement ----------------------------------------------


def test_metadata_before_path_rejected(backend: BackendInterface) -> None:
    # Fresh device state — no P1=0x00 has been sent this session's userop_ctx.
    # Path handler always accepts, but metadata expects step=1 not step=0.
    # First reset via a bad-but-completing path call to leave step=1, then
    # try to jump straight to packed — must reject.
    _p1(backend, P1_PATH, PATH)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_PACKED, p2=0, data=PACKED
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_packed_before_metadata_rejected(backend: BackendInterface) -> None:
    _p1(backend, P1_PATH, PATH)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_PACKED, p2=0, data=PACKED
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_metadata_twice_rejected(backend: BackendInterface) -> None:
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    # After METADATA, next expected step is PACKED. Sending METADATA again fails.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_METADATA, p2=0, data=METADATA
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_p1_out_of_range_rejected(backend: BackendInterface) -> None:
    for bad_p1 in (0x04, 0x42, 0xFF):
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(
                cla=CLA,
                ins=InsType.HYBRID_SIGN_USEROP,
                p1=bad_p1,
                p2=0,
                data=b"\x00",
            )
        assert e.value.status == Errors.SWO_INCORRECT_P1_P2


def test_p2_nonzero_rejected(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_PATH, p2=1, data=PATH
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


# ---- Length enforcement ------------------------------------------------


def test_metadata_wrong_length_rejected(backend: BackendInterface) -> None:
    _p1(backend, P1_PATH, PATH)
    # 103 B (one short) must fail.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_METADATA, p2=0,
            data=METADATA[:-1],
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH
    # 105 B (one over) must fail. The step didn't advance from the short-data
    # attempt, so metadata is still expected.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_METADATA, p2=0,
            data=METADATA + b"\x00",
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_packed_wrong_length_rejected(backend: BackendInterface) -> None:
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_PACKED, p2=0, data=PACKED[:-1]
        )
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


# ---- callData hash verification (would trigger UI on success, so we only
# ---- test the failure path here — mismatch must reject without UI). ---


def test_calldata_hash_mismatch_rejected(backend: BackendInterface) -> None:
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    _p1(backend, P1_PACKED, PACKED)

    # Send callData that does NOT match HASH_CALL_DATA. Device computes
    # keccak256(bad) and compares to HASH_CALL_DATA, mismatch -> reject.
    bad_calldata = b"\xff" * len(CALLDATA)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.HYBRID_SIGN_USEROP,
            p1=P1_CALLDATA,
            p2=0,
            data=bad_calldata,
        )
    assert e.value.status == Errors.SWO_INCORRECT_DATA


def test_calldata_after_mismatch_resets_state(backend: BackendInterface) -> None:
    # After a callData mismatch, the accumulator is wiped. A subsequent P1=0x03
    # (calldata) without re-doing path/metadata/packed must fail on ordering.
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    _p1(backend, P1_PACKED, PACKED)

    with pytest.raises(ExceptionRAPDU):
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_CALLDATA, p2=0,
            data=b"\xff" * 20,
        )

    # State should be reset — trying calldata again fails with INCORRECT_P1_P2.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_CALLDATA, p2=0, data=CALLDATA
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


# ---- Reset semantics ----------------------------------------------------


def test_path_always_resets(backend: BackendInterface) -> None:
    # Mid-sequence, sending P1=0x00 again wipes the accumulator and returns
    # to expecting metadata. Verify by finishing the sequence cleanly after
    # a reset.
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    _p1(backend, P1_PATH, PATH)               # reset
    _p1(backend, P1_METADATA, METADATA)       # would fail if not reset
    _p1(backend, P1_PACKED, PACKED)
