"""End-to-end SIGN_DILITHIUM finalize + UI approval + sig fetch, for both
ML-DSA parameter sets.

SIGN_DILITHIUM has no parameter-set selector of its own: it signs with the key
the last keygen loaded. So every test here loads a key of the parameter set
under test first, and the review must show that set on its "Signer" line.

The review screen is a blind-signing flow (`nbgl_useCaseReviewBlindSigning` in
src/ui/nbgl_display_pq_sign.c), so navigation must go through the
`*_with_warning` scenarios — the plain `review_approve` / `review_reject`
scenarios do not account for the warning page.

Handler behavior is covered by test_pq_sign.py (state machine, error paths,
cross-INS hygiene); what this file adds is the review-screen golden snapshots
and the round-trip signature assertions, verified with OpenSSL's FIPS 204
implementation against the public key the device exported.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    CLA,
    BoilerplateCommandSender,
    Errors,
    InsType,
    MLDSAParam,
)

# SIGN_DILITHIUM signs an opaque payload shown only as a hex preview.
pytestmark = pytest.mark.usefixtures("blind_signing_enabled")

PARAMS = pytest.mark.parametrize(
    "param", [MLDSAParam.MLDSA_44, MLDSAParam.MLDSA_65], ids=lambda p: p.name
)

P1_INIT = 0x00
P1_ABSORB = 0x01
P1_FINALIZE = 0x80

PATH = "m/44'/1'/0'/0'/0'"

PUBKEY_CLS = {
    MLDSAParam.MLDSA_44: mldsa.MLDSA44PublicKey,
    MLDSAParam.MLDSA_65: mldsa.MLDSA65PublicKey,
}


def _load_payload(backend: BackendInterface, payload: bytes) -> None:
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    for i in range(0, len(payload), 255):
        chunk = payload[i : i + 255]
        backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=chunk)


def _sign_and_verify(
    backend: BackendInterface,
    scenario_navigator: NavigateWithScenario,
    param: MLDSAParam,
    payload: bytes,
    test_name: str,
) -> None:
    """Load a key of `param`, approve the review, and verify the signature."""
    client = BoilerplateCommandSender(backend)
    client.keygen_mldsa_path(PATH, param)
    _load_payload(backend, payload)

    with backend.exchange_async(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""):
        scenario_navigator.review_approve_with_warning(test_name=test_name)
    rapdu = backend.last_async_response
    assert rapdu is not None and rapdu.status == Errors.SWO_SUCCESS

    pk = client.get_mldsa_pk(param)
    sig = client.get_mldsa_sig(param)
    assert len(pk) == param.pk_bytes
    assert len(sig) == param.sig_bytes
    # Pure FIPS 204 signature of the payload with an empty context; raises if
    # the device signed with the wrong key, the wrong set, or the wrong bytes.
    PUBKEY_CLS[param].from_public_bytes(pk).verify(sig, payload)


@PARAMS
def test_sign_dilithium_short_payload(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    _sign_and_verify(
        backend,
        scenario_navigator,
        param,
        bytes.fromhex("0123456789abcdef" * 4),  # 32 bytes -> classic hash-sized payload
        f"test_sign_dilithium_short_payload_{param.name.lower()}",
    )


@PARAMS
def test_sign_dilithium_long_payload(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    # Multi-chunk absorb over a >32-byte payload exercises the "..." truncation
    # branch of the payload preview in the UI.
    _sign_and_verify(
        backend,
        scenario_navigator,
        param,
        bytes(range(200)),
        f"test_sign_dilithium_long_payload_{param.name.lower()}",
    )


@PARAMS
def test_sign_dilithium_rejected_by_user(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, param: MLDSAParam
) -> None:
    client = BoilerplateCommandSender(backend)
    client.keygen_mldsa_path(PATH, param)
    _load_payload(backend, bytes(32))

    # A rejection answers 0x6985, which the backend surfaces as an exception
    # rather than a status on last_async_response.
    with pytest.raises(ExceptionRAPDU) as e:
        with backend.exchange_async(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""):
            scenario_navigator.review_reject_with_warning(
                test_name=f"test_sign_dilithium_rejected_by_user_{param.name.lower()}"
            )
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED

    # After rejection the signature buffer must be wiped, over the full size of
    # the loaded set.
    assert client.get_mldsa_sig(param) == bytes(param.sig_bytes)
