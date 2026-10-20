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

from cryptography.hazmat.primitives.asymmetric import mldsa
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    CLA,
    BoilerplateCommandSender,
    Errors,
    InsType,
    MLDSAParam,
)
from application_client.boilerplate_response_unpacker import unpack_sign_tx_response

PUBKEY_CLS = {
    MLDSAParam.MLDSA_44: mldsa.MLDSA44PublicKey,
    MLDSAParam.MLDSA_65: mldsa.MLDSA65PublicKey,
}

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
PATH_STR = "m/44'/1'/0'/0'/0'"
PATH     = pack_derivation_path(PATH_STR)


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


def test_p2_out_of_range_rejected(backend: BackendInterface) -> None:
    # P2 carries the ML-DSA parameter set: 0x00 (ML-DSA-44) and 0x01
    # (ML-DSA-65) are valid, anything else is rejected. The 0x01 path is
    # exercised in test_mldsa65.py.
    for bad_p2 in (0x02, 0x80, 0xFF):
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(
                cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_PATH, p2=bad_p2, data=PATH
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


# ---- End to end: finalize -> clear-sign review -> hybrid signature ------
#
# These are the only tests that drive P1=0x03, so they are what actually covers
# the userOpHash construction, the callData verification and the clear-signing
# screens. No blind_signing_enabled fixture on purpose: a UserOp with its
# callData present is clear-signed and must work with the setting off.


def _userop_hash(metadata: bytes, packed: bytes) -> bytes:
    """Mirror of compute_userop_hash() in src/handler/hybrid_sign_userop.c.

    inner      = keccak256(sender || nonce || packed)   (sender left-padded)
    userOpHash = keccak256(inner || entryPoint || chainId)  (entryPoint padded)
    """
    chain_id, entry_point, sender, nonce = (
        metadata[0:32],
        metadata[32:52],
        metadata[52:72],
        metadata[72:104],
    )
    inner = _keccak256(bytes(12) + sender + nonce + packed)
    return _keccak256(inner + bytes(12) + entry_point + chain_id)


@pytest.mark.parametrize(
    "param", [MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65], ids=lambda p: p.name
)
def test_userop_clear_sign_end_to_end(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    """Approve a clear-signed UserOp and check both halves of the signature.

    The ML-DSA half must verify against the userOpHash computed here, which is
    an independent reimplementation of the device's ERC-4337 v0.7 hashing: if
    the two constructions ever diverge, verification fails.
    """
    client = BoilerplateCommandSender(backend)

    with client.hybrid_sign_userop(
        path=PATH_STR, metadata=METADATA, packed=PACKED, call_data=CALLDATA, param=param
    ):
        scenario_navigator.review_approve(test_name=f"userop_clear_sign_{param.name.lower()}")

    # ECDSA half, inline: [len][DER sig][v]
    response = client.get_async_response()
    assert response is not None
    der_sig_len, der_sig, _v = unpack_sign_tx_response(response.data)
    assert der_sig_len == len(der_sig) and 8 <= der_sig_len <= 72

    # ML-DSA half, through the chunk INS, over the device's userOpHash.
    pk = client.get_mldsa_pk(param)
    sig = client.get_mldsa_sig(param)
    assert len(pk) == param.pk_bytes
    assert len(sig) == param.sig_bytes
    PUBKEY_CLS[param].from_public_bytes(pk).verify(sig, _userop_hash(METADATA, PACKED))


def test_userop_clear_sign_rejected(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """Rejecting the review signs nothing and leaves no ML-DSA material."""
    client = BoilerplateCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.hybrid_sign_userop(
            path=PATH_STR,
            metadata=METADATA,
            packed=PACKED,
            call_data=CALLDATA,
            param=MLDSAParam.MLDSA_44,
        ):
            scenario_navigator.review_reject(test_name="userop_clear_sign_rejected")
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED
    assert client.get_mldsa_sig(MLDSAParam.MLDSA_44) == bytes(MLDSAParam.MLDSA_44.sig_bytes)


def test_userop_blind_variant_refused_without_opt_in(backend: BackendInterface) -> None:
    """Withholding callData is blind signing, so it needs the user's opt-in."""
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    _p1(backend, P1_PACKED, PACKED)

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_CALLDATA, p2=0, data=b"")
    assert e.value.status == Errors.SW_BLIND_SIGNING_DISABLED


# ---- callData the device cannot clear-sign ------------------------------
#
# Only execute(address,uint256,bytes) yields To / Value. Any other callData is
# hash-checked but leaves the review with nothing but the userOpHash, i.e. blind
# signing: refused without the opt-in, and behind the SDK warning with it.

# executeBatch(address[],uint256[],bytes[]) of the v0.7 SimpleAccount. The
# device does not decode it; any non-execute selector takes the same path.
EXECUTE_BATCH_SELECTOR = bytes.fromhex("47e1da2a")
EXECUTE_BATCH_CALLDATA = (
    EXECUTE_BATCH_SELECTOR
    + (0x60).to_bytes(32, "big")  # offset of dest[]
    + (0x80).to_bytes(32, "big")  # offset of value[]
    + (0xA0).to_bytes(32, "big")  # offset of func[]
    + (0).to_bytes(32, "big")  # dest[]  (empty)
    + (0).to_bytes(32, "big")  # value[] (empty)
    + (0).to_bytes(32, "big")  # func[]  (empty)
)
# The execute selector but too short to carry dest and value: must not be
# mistaken for something clear-signable.
EXECUTE_TRUNCATED_CALLDATA = CALLDATA[:40]

ERC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
ERC20_APPROVE_SELECTOR = bytes.fromhex("095ea7b3")
TOKEN = bytes.fromhex("4444444444444444444444444444444444444444")
RECIPIENT = bytes.fromhex("3333333333333333333333333333333333333333")
ATTACKER = bytes.fromhex("6666666666666666666666666666666666666666")
# 100 tokens with 18 decimals: above 2^64, so it exercises the full-width
# uint256 decimal formatting of the review.
AMOUNT = 100 * 10**18
UINT256_MAX = 2**256 - 1


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _address_word(address: bytes, pad: bytes = bytes(12)) -> bytes:
    return pad + address


def _execute(
    dest: bytes,
    value: int,
    inner: bytes,
    data_ptr: int = 0x60,
    dest_pad: bytes = bytes(12),
    trailing: bytes = b"",
) -> bytes:
    """execute(address dest, uint256 value, bytes inner), canonically encoded
    unless one of the knobs says otherwise."""
    padding = bytes(-len(inner) % 32)
    return (
        EXEC_SELECTOR
        + _address_word(dest, dest_pad)
        + _word(value)
        + _word(data_ptr)
        + _word(len(inner))
        + inner
        + padding
        + trailing
    )


def _erc20_transfer(to: bytes, amount: int, to_pad: bytes = bytes(12)) -> bytes:
    return ERC20_TRANSFER_SELECTOR + _address_word(to, to_pad) + _word(amount)


ERC20_TRANSFER_CALLDATA = _execute(TOKEN, 0, _erc20_transfer(RECIPIENT, AMOUNT))

UNPARSED_CALLDATA = [
    pytest.param(EXECUTE_BATCH_CALLDATA, id="executeBatch"),
    pytest.param(EXECUTE_TRUNCATED_CALLDATA, id="execute-truncated"),
    # The approval-phishing shape: execute(token, 0, approve(attacker, max)).
    pytest.param(
        _execute(TOKEN, 0, ERC20_APPROVE_SELECTOR + _address_word(ATTACKER) + _word(UINT256_MAX)),
        id="inner-approve",
    ),
    pytest.param(
        _execute(TOKEN, 1, _erc20_transfer(RECIPIENT, AMOUNT)), id="transfer-with-native-value"
    ),
    pytest.param(
        _execute(TOKEN, 0, _erc20_transfer(RECIPIENT, AMOUNT, to_pad=b"\x01" + bytes(11))),
        id="transfer-dirty-recipient",
    ),
    # transfer() with 4 extra bytes: wrong inner length, still within one APDU.
    pytest.param(
        _execute(TOKEN, 0, _erc20_transfer(RECIPIENT, AMOUNT) + bytes(4)),
        id="transfer-extra-bytes",
    ),
    pytest.param(_execute(RECIPIENT, 1, b"", dest_pad=b"\x01" + bytes(11)), id="dirty-dest"),
    pytest.param(_execute(RECIPIENT, 1, b"", data_ptr=0x80), id="non-canonical-offset"),
    pytest.param(_execute(RECIPIENT, 1, b"", trailing=bytes(32)), id="trailing-bytes"),
    # A valid ERC-20 transfer whose 28 bytes of ABI padding are not all zero.
    pytest.param(ERC20_TRANSFER_CALLDATA[:-1] + b"\x01", id="dirty-padding"),
]


def _packed_for(call_data: bytes) -> bytes:
    """The packed fields with an honest hashCallData for `call_data`."""
    return (
        HASH_INIT_CODE
        + _keccak256(call_data)
        + ACCOUNT_GAS_LIMITS
        + PRE_VERIF_GAS
        + GAS_FEES
        + HASH_PAYMASTER
    )


@pytest.mark.parametrize("call_data", UNPARSED_CALLDATA)
def test_userop_unparsed_calldata_refused_without_opt_in(
    backend: BackendInterface, call_data: bytes
) -> None:
    """Hash-valid callData that is not an execute call is blind signing."""
    _p1(backend, P1_PATH, PATH)
    _p1(backend, P1_METADATA, METADATA)
    _p1(backend, P1_PACKED, _packed_for(call_data))

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_CALLDATA, p2=0, data=call_data
        )
    assert e.value.status == Errors.SW_BLIND_SIGNING_DISABLED

    # The accumulated UserOp was wiped: the sequence must restart from the path.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=P1_CALLDATA, p2=0, data=call_data
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


@pytest.mark.usefixtures("blind_signing_enabled")
@pytest.mark.parametrize(
    "param", [MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65], ids=lambda p: p.name
)
def test_userop_unparsed_calldata_blind_signed_with_opt_in(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    """With the opt-in, the same UserOp goes through the blind-signing review
    (warning page, then the userOpHash) and both halves still verify."""
    client = BoilerplateCommandSender(backend)
    packed = _packed_for(EXECUTE_BATCH_CALLDATA)

    with client.hybrid_sign_userop(
        path=PATH_STR,
        metadata=METADATA,
        packed=packed,
        call_data=EXECUTE_BATCH_CALLDATA,
        param=param,
    ):
        scenario_navigator.review_approve_with_warning(
            test_name=f"userop_blind_sign_{param.name.lower()}"
        )

    response = client.get_async_response()
    assert response is not None
    der_sig_len, der_sig, _v = unpack_sign_tx_response(response.data)
    assert der_sig_len == len(der_sig) and 8 <= der_sig_len <= 72

    pk = client.get_mldsa_pk(param)
    sig = client.get_mldsa_sig(param)
    PUBKEY_CLS[param].from_public_bytes(pk).verify(sig, _userop_hash(METADATA, packed))


# ---- ERC-20 transfer: clear-signed from the inner call -------------------


@pytest.mark.parametrize(
    "param", [MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65], ids=lambda p: p.name
)
def test_userop_erc20_transfer_clear_sign(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    """execute(token, 0, transfer(recipient, amount)) is clear-signed without the
    opt-in: the review shows Token, the real recipient and the amount, not the
    outer "To: token, Value: 0"."""
    client = BoilerplateCommandSender(backend)
    packed = _packed_for(ERC20_TRANSFER_CALLDATA)

    with client.hybrid_sign_userop(
        path=PATH_STR,
        metadata=METADATA,
        packed=packed,
        call_data=ERC20_TRANSFER_CALLDATA,
        param=param,
    ):
        scenario_navigator.review_approve(test_name=f"userop_erc20_transfer_{param.name.lower()}")

    response = client.get_async_response()
    assert response is not None
    der_sig_len, der_sig, _v = unpack_sign_tx_response(response.data)
    assert der_sig_len == len(der_sig) and 8 <= der_sig_len <= 72

    pk = client.get_mldsa_pk(param)
    sig = client.get_mldsa_sig(param)
    PUBKEY_CLS[param].from_public_bytes(pk).verify(sig, _userop_hash(METADATA, packed))
