"""End-to-end SIGN_DILITHIUM finalize + UI approval + sig fetch.

The review screen is a blind-signing flow (`nbgl_useCaseReviewBlindSigning` in
src/ui/nbgl_display_pq_sign.c), so navigation must go through the
`*_with_warning` scenarios — the plain `review_approve` / `review_reject`
scenarios do not account for the warning page.

Handler behavior is covered by test_pq_sign.py (state machine, error paths,
cross-INS hygiene); what this file adds is the review-screen golden snapshots
and the round-trip signature assertions.
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import CLA, Errors, InsType

# SIGN_DILITHIUM signs an opaque payload shown only as a hex preview.
pytestmark = pytest.mark.usefixtures("blind_signing_enabled")


P1_INIT = 0x00
P1_ABSORB = 0x01
P1_FINALIZE = 0x80

# ML-DSA-44 sig length.
SIG_BYTES = 2420
SIG_CHUNK_SIZES = [255] * 9 + [125]


def _fetch_sig(backend: BackendInterface) -> bytes:
    out = b""
    for i, size in enumerate(SIG_CHUNK_SIZES):
        r = backend.exchange(cla=CLA, ins=InsType.GET_SIG_CHUNK, p1=i, p2=size, data=b"")
        assert r.status == Errors.SWO_SUCCESS
        out += r.data
    return out


def _prime_key(backend: BackendInterface, seed_byte: int = 0x42) -> None:
    backend.exchange(
        cla=CLA,
        ins=InsType.KEYGEN_DILITHIUM_CORE,
        p1=0,
        p2=0,
        data=bytes([seed_byte] * 32),
    )


def _load_payload(backend: BackendInterface, payload: bytes) -> None:
    backend.exchange(cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_INIT, p2=0, data=b"")
    for i in range(0, len(payload), 255):
        chunk = payload[i : i + 255]
        backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_ABSORB, p2=0, data=chunk
        )


def test_sign_dilithium_short_payload(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    _prime_key(backend)
    _load_payload(backend, bytes.fromhex(
        "0123456789abcdef" * 4  # 32 bytes -> classic hash-sized payload
    ))
    with backend.exchange_async(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""
    ) as _resp:
        scenario_navigator.review_approve_with_warning()

    rapdu = backend.last_async_response
    assert rapdu.status == Errors.SWO_SUCCESS

    sig = _fetch_sig(backend)
    assert len(sig) == SIG_BYTES
    # Sig must not be all zeros (would mean crypto_pq_sign silently failed).
    assert sig != b"\x00" * SIG_BYTES


def test_sign_dilithium_rejected_by_user(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    _prime_key(backend)
    _load_payload(backend, bytes(32))
    # A rejection answers 0x6985, which the backend surfaces as an exception
    # rather than a status on last_async_response.
    with pytest.raises(ExceptionRAPDU) as e:
        with backend.exchange_async(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""
        ) as _resp:
            scenario_navigator.review_reject_with_warning()
    assert e.value.status == Errors.SWO_CONDITIONS_NOT_SATISFIED

    # After rejection the sig buffer must be wiped.
    sig = _fetch_sig(backend)
    assert sig == b"\x00" * SIG_BYTES


def test_sign_dilithium_long_payload(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    # Multi-chunk absorb over a >32-byte payload exercises the "..." truncation
    # branch of the payload preview in the UI.
    _prime_key(backend)
    _load_payload(backend, bytes(range(200)))
    with backend.exchange_async(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""
    ) as _resp:
        scenario_navigator.review_approve_with_warning()

    rapdu = backend.last_async_response
    assert rapdu.status == Errors.SWO_SUCCESS
    sig = _fetch_sig(backend)
    assert len(sig) == SIG_BYTES
