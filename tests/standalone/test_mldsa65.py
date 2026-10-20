"""ML-DSA-65 (FIPS 204, security category 3) on the device, and the parameter
selector that carries it.

The ML-DSA INS take the parameter set in P2 (0x00 = ML-DSA-44, the value every
pre-existing client sends; 0x01 = ML-DSA-65), so these tests run the same
flows as the ML-DSA-44 ones with P2 = 1 and check the sizes, the key material
and the signatures of the larger set.

What is checked against an external reference rather than against the device
itself:
  * KEYGEN_DILITHIUM_CORE reproduces the NIST ACVP ML-DSA keyGen vectors
    (tests/kat/acvp_mldsa_keygen.json, seed -> pk of FIPS 204 Alg. 6), for
    both parameter sets;
  * every signature is verified with `cryptography` (OpenSSL's FIPS 204
    implementation) against the public key the device exported;
  * the hybrid signatures are the pure ML-DSA signature of the 32-byte hash
    with an empty context, i.e. of M' = 0x00 || 0x00 || hash: the input of
    ZKNOX_dilithium65.verify(pk, bytes32 hash, sig) in ETHDILITHIUM, so the
    device output verifies on-chain as is.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa
from Crypto.Hash import keccak
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    CLA,
    BoilerplateCommandSender,
    Errors,
    InsType,
    MLDSAParam,
)
from application_client.boilerplate_response_unpacker import (
    unpack_sign_tx_mldsa_response,
    unpack_sign_tx_response,
)
from application_client.boilerplate_transaction import Transaction

PATH = "m/44'/1'/0'/0'/0'"


def _is_nanox(backend: BackendInterface) -> bool:
    """Nano X is the device where SIGN_TX_MLDSA has no I/O buffer."""
    return str(getattr(backend.device, "name", backend.device)).lower().startswith("nanox")

KAT_FILE = Path(__file__).parent.parent / "kat" / "acvp_mldsa_keygen.json"
KAT = json.loads(KAT_FILE.read_text())
PARAM_OF_NAME = {"ML-DSA-44": MLDSAParam.MLDSA_44, "ML-DSA-65": MLDSAParam.MLDSA_65}
PUBKEY_CLS = {
    MLDSAParam.MLDSA_44: mldsa.MLDSA44PublicKey,
    MLDSAParam.MLDSA_65: mldsa.MLDSA65PublicKey,
}


def _verify(param: MLDSAParam, pk_bytes: bytes, sig: bytes, message: bytes) -> None:
    """FIPS 204 verification with an empty context; raises on an invalid signature."""
    PUBKEY_CLS[param].from_public_bytes(pk_bytes).verify(sig, message)


# ---------------------------------------------------------------------------
# NIST ACVP keyGen vectors, on the device
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", KAT["vectors"], ids=lambda v: f"{v['parameterSet']}-{v['tcId']}")
def test_keygen_matches_nist_acvp(backend: BackendInterface, vector: dict) -> None:
    client = BoilerplateCommandSender(backend)
    param = PARAM_OF_NAME[vector["parameterSet"]]
    expected_pk = bytes.fromhex(vector["pk"])

    rapdu = client.keygen_mldsa_seed(bytes.fromhex(vector["seed"]), param)
    assert rapdu.status == Errors.SWO_SUCCESS

    pk = client.get_mldsa_pk(param)
    assert len(pk) == param.pk_bytes
    assert pk == expected_pk, f"{vector['parameterSet']} tcId {vector['tcId']}: pk mismatch"


# ---------------------------------------------------------------------------
# Sizes and parameter-set isolation
# ---------------------------------------------------------------------------


def test_pk_size_follows_parameter_set(backend: BackendInterface) -> None:
    client = BoilerplateCommandSender(backend)
    seed = bytes([0x42] * 32)

    client.keygen_mldsa_seed(seed, MLDSAParam.MLDSA_65)
    pk65 = client.get_mldsa_pk(MLDSAParam.MLDSA_65)
    # The pk of ML-DSA-65 is 1952 bytes: the chunk right past 1312 (the
    # ML-DSA-44 size) must exist and not be zero padding.
    assert len(pk65) == 1952
    assert pk65[1312:] != bytes(640)

    client.keygen_mldsa_seed(seed, MLDSAParam.MLDSA_44)
    pk44 = client.get_mldsa_pk(MLDSAParam.MLDSA_44)
    assert len(pk44) == 1312
    # Same seed, different parameter set: unrelated keys (and different rho).
    assert pk44 != pk65[:1312]


def test_chunk_bounds_follow_parameter_set(backend: BackendInterface) -> None:
    client = BoilerplateCommandSender(backend)

    # ML-DSA-65: pk 1952 bytes -> last valid chunk is (p1=7, p2=167).
    client.keygen_mldsa_seed(bytes(32), MLDSAParam.MLDSA_65)
    r = backend.exchange(cla=CLA, ins=InsType.GET_PK_CHUNK, p1=7, p2=167, data=b"")
    assert r.status == Errors.SWO_SUCCESS and len(r.data) == 167
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.GET_PK_CHUNK, p1=7, p2=168, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH

    # sig 3309 bytes -> last valid chunk is (p1=12, p2=249).
    r = backend.exchange(cla=CLA, ins=InsType.GET_SIG_CHUNK, p1=12, p2=249, data=b"")
    assert r.status == Errors.SWO_SUCCESS and len(r.data) == 249
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.GET_SIG_CHUNK, p1=12, p2=250, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH

    # After keygen, the sig buffer is scrubbed over the whole 65 length.
    assert client.get_mldsa_sig(MLDSAParam.MLDSA_65) == bytes(3309)

    # An ML-DSA-44 key must not expose the tail of the (larger) buffers: the
    # bound drops back to 1312 / 2420.
    client.keygen_mldsa_seed(bytes(32), MLDSAParam.MLDSA_44)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.GET_PK_CHUNK, p1=5, p2=38, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.GET_SIG_CHUNK, p1=9, p2=126, data=b"")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_bip32_keygen_65_deterministic_and_separated(backend: BackendInterface) -> None:
    client = BoilerplateCommandSender(backend)

    assert client.keygen_mldsa_path(PATH, MLDSAParam.MLDSA_65).status == Errors.SWO_SUCCESS
    pk1 = client.get_mldsa_pk(MLDSAParam.MLDSA_65)
    assert client.keygen_mldsa_path(PATH, MLDSAParam.MLDSA_65).status == Errors.SWO_SUCCESS
    pk2 = client.get_mldsa_pk(MLDSAParam.MLDSA_65)
    assert pk1 == pk2, "ML-DSA-65 keygen must be deterministic for a path"

    # Another path gives another key.
    client.keygen_mldsa_path("m/44'/1'/0'/0'/1'", MLDSAParam.MLDSA_65)
    assert client.get_mldsa_pk(MLDSAParam.MLDSA_65) != pk1

    # Same path, ML-DSA-44: the SLIP-0010 personalization differs
    # ("ML-DSA-44 seed" vs "ML-DSA-65 seed"), so the two key trees are
    # independent — the 44 pk is not a prefix of the 65 one.
    client.keygen_mldsa_path(PATH, MLDSAParam.MLDSA_44)
    pk44 = client.get_mldsa_pk(MLDSAParam.MLDSA_44)
    assert pk44 != pk1[:1312]
    assert pk44[:32] != pk1[:32], "rho must differ between the two parameter sets"


@pytest.mark.usefixtures("blind_signing_enabled")
def test_invalid_parameter_selector_rejected(backend: BackendInterface) -> None:
    for ins, data in (
        (InsType.KEYGEN_DILITHIUM_CORE, bytes(32)),
        (InsType.KEYGEN_DILITHIUM, pack_derivation_path(PATH)),
        (InsType.SAMPLE_IN_BALL, bytes(32)),
        (InsType.HYBRID_SIGN_HASH, pack_derivation_path(PATH) + bytes(32)),
        (InsType.HYBRID_SIGN_USEROP, pack_derivation_path(PATH)),
    ):
        for bad_p2 in (0x02, 0x7F, 0xFF):
            with pytest.raises(ExceptionRAPDU) as e:
                backend.exchange(cla=CLA, ins=ins, p1=0, p2=bad_p2, data=data)
            assert e.value.status == Errors.SWO_INCORRECT_P1_P2, (
                f"INS {ins:#x} P2={bad_p2:#x} should have been rejected"
            )


def test_userop_parameter_set_fixed_by_first_apdu(backend: BackendInterface) -> None:
    # The sequence is started with ML-DSA-65; a later step claiming ML-DSA-44
    # is a client bug and must be rejected.
    backend.exchange(
        cla=CLA,
        ins=InsType.HYBRID_SIGN_USEROP,
        p1=0x00,
        p2=MLDSAParam.MLDSA_65,
        data=pack_derivation_path(PATH),
    )
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA,
            ins=InsType.HYBRID_SIGN_USEROP,
            p1=0x01,
            p2=MLDSAParam.MLDSA_44,
            data=bytes(104),
        )
    assert e.value.status == Errors.SWO_INCORRECT_P1_P2


# ---------------------------------------------------------------------------
# SAMPLE_IN_BALL with tau = 49
# ---------------------------------------------------------------------------


def test_sample_in_ball_tau_follows_parameter_set(backend: BackendInterface) -> None:
    import struct

    client = BoilerplateCommandSender(backend)
    # ML-DSA-65 uses a 48-byte c~.
    c_tilde = bytes([0x11] * 48)

    for param in (MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65):
        rapdu = client.sample_in_ball(c_tilde, param)
        assert rapdu.status == Errors.SWO_SUCCESS
        coeffs = struct.unpack("<" + "i" * 256, rapdu.data)
        nonzero = [c for c in coeffs if c != 0]
        assert len(nonzero) == param.tau, f"{param.name}: expected tau={param.tau} nonzero"
        assert all(c in (-1, 1) for c in nonzero)


# ---------------------------------------------------------------------------
# End-to-end signing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("param", [MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65], ids=lambda p: p.name)
def test_sign_tx_mldsa(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    """SIGN_TX_MLDSA with the parameter set in the low bits of P2: the response
    carries the pk and the signature of that set, and the signature verifies.

    This INS answers pk + signature in ONE APDU, so it needs an I/O buffer of
    5265 bytes for ML-DSA-65. On Nano X (28 KB of SRAM) that buffer would
    starve the stack, which the review + signing path needs ~14.2 KB of
    (measured; tests/standalone/test_stack_watermark.py), so the INS is
    unavailable there and clients use the chunk-fetched flows instead —
    test_sign_tx_mldsa_unavailable_on_nanox covers that, and
    test_hybrid_sign_hash covers the flows, on every device.
    """
    if _is_nanox(backend):
        pytest.skip("SIGN_TX_MLDSA is unavailable on Nano X (no I/O buffer for its single response)")
    client = BoilerplateCommandSender(backend)
    transaction = Transaction(
        nonce=1,
        to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        value=666,
        memo=param.name.lower(),
    ).serialize()

    with client.sign_tx_mldsa(path=PATH, transaction=transaction, param=param):
        scenario_navigator.review_approve(test_name=f"sign_tx_{param.name.lower()}")

    pk, sig = unpack_sign_tx_mldsa_response(client.get_async_response().data)
    assert len(pk) == param.pk_bytes
    assert len(sig) == param.sig_bytes

    # The device Keccak-256s the raw tx and signs the digest (empty context).
    k = keccak.new(digest_bits=256)
    k.update(transaction)
    _verify(param, pk, sig, k.digest())


@pytest.mark.parametrize("param", [MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65], ids=lambda p: p.name)
@pytest.mark.usefixtures("blind_signing_enabled")
def test_hybrid_sign_hash(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    """HYBRID_SIGN_HASH end to end: the ECDSA half comes back inline, the
    ML-DSA half through the chunk INS, and both verify over the same hash."""
    client = BoilerplateCommandSender(backend)
    m_hash = keccak.new(digest_bits=256, data=b"ECML-Signer hybrid test").digest()

    with client.hybrid_sign_hash(path=PATH, m_hash=m_hash, param=param):
        scenario_navigator.review_approve_with_warning(
            test_name=f"hybrid_sign_hash_{param.name.lower()}"
        )

    # ECDSA half, inline: [len][DER sig][v]
    der_sig_len, der_sig, _v = unpack_sign_tx_response(client.get_async_response().data)
    assert der_sig_len == len(der_sig) and 8 <= der_sig_len <= 72

    # ML-DSA half, through GET_PK_CHUNK / GET_SIG_CHUNK.
    pk = client.get_mldsa_pk(param)
    sig = client.get_mldsa_sig(param)
    assert len(pk) == param.pk_bytes
    assert len(sig) == param.sig_bytes

    # Pure ML-DSA over the 32-byte hash with an empty context: exactly what
    # ZKNOX_dilithium / ZKNOX_dilithium65 verify(pk, bytes32 hash, sig) checks.
    _verify(param, pk, sig, m_hash)

    # The ML-DSA key is the one of the BIP32 path (same as KEYGEN_DILITHIUM).
    client.keygen_mldsa_path(PATH, param)
    assert client.get_mldsa_pk(param) == pk



def test_sign_tx_mldsa_unavailable_on_nanox(backend: BackendInterface) -> None:
    """Where the single-response INS has no I/O buffer it must refuse cleanly,
    before doing any work, rather than answer a truncated response."""
    if not _is_nanox(backend):
        pytest.skip("only Nano X lacks the I/O buffer for SIGN_TX_MLDSA")
    for param in (MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65):
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(
                cla=CLA,
                ins=InsType.SIGN_TX_MLDSA,
                p1=0,
                p2=0x80 | param,
                data=pack_derivation_path(PATH),
            )
        assert e.value.status == Errors.SWO_INVALID_INS


@pytest.mark.usefixtures("blind_signing_enabled")
def test_hybrid_sign_hash_65_rejected(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """Rejecting the review leaves no ML-DSA-65 material behind."""
    client = BoilerplateCommandSender(backend)
    m_hash = bytes(range(32))

    with pytest.raises(ExceptionRAPDU) as e:
        with client.hybrid_sign_hash(path=PATH, m_hash=m_hash, param=MLDSAParam.MLDSA_65):
            scenario_navigator.review_reject_with_warning(test_name="hybrid_sign_hash_65_rejected")
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED
    assert client.get_mldsa_sig(MLDSAParam.MLDSA_65) == bytes(3309)
