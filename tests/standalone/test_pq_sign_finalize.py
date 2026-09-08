"""End-to-end SIGN_DILITHIUM finalize + UI approval + sig fetch.

Currently skipped: ML-DSA-44 signing takes ~30-60 seconds on Nano-class
devices in Speculos, which exceeds ragger's default 10 s `wait_for_screen_change`
timeout. A proper fix needs either:
  * an async signing pattern in the app (post-approval spinner + os_ux pump),
    so a screen change happens before the slow sign starts blocking; or
  * a global ragger fixture that raises the wait_for_screen_change ceiling
    (a naive monkey-patch on SpeculosBackend didn't take; needs investigation).

Handler behavior is fully covered by test_pq_sign.py (state machine, error
paths, cross-INS hygiene). What's missing here is only the review-screen
golden snapshots and the round-trip sig assertion, both easy to add once
the timing story is sorted.
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import CLA, Errors, InsType

pytestmark = pytest.mark.skip(
    reason="MLDSA_sign wall time exceeds ragger's default screen-change timeout; "
    "needs app-side async signing or ragger fixture upgrade. See file docstring."
)


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
        scenario_navigator.review_approve()

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
    with backend.exchange_async(
        cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=P1_FINALIZE, p2=0, data=b""
    ) as _resp:
        scenario_navigator.review_reject()

    rapdu = backend.last_async_response
    assert rapdu.status == Errors.SWO_CONDITIONS_NOT_SATISFIED
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
        scenario_navigator.review_approve()

    rapdu = backend.last_async_response
    assert rapdu.status == Errors.SWO_SUCCESS
    sig = _fetch_sig(backend)
    assert len(sig) == SIG_BYTES
