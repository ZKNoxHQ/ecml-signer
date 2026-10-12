"""The blind-signing opt-in: default state, enforcement, and the Settings UI.

Blind signing covers every flow where the review screen cannot represent the
bytes being signed. It is OFF on a fresh install and the device must refuse
those flows with SW_BLIND_SIGNING_DISABLED rather than silently showing a
degraded review (EMBEDDED.instructions.md: fail closed, never downgrade).

The other modules reach the signing flows through the `blind_signing_enabled`
fixture, which writes the setting over SET_SETTING. This module deliberately
does not: it asserts the default, the refusals, and that the user-facing
Settings switch — a different code path in src/ui/menu_nbgl.c — really flips it.
"""

import pytest
from ledgered.devices import Device, DeviceType
from ragger.backend.interface import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavIns, NavInsID, Navigator

from application_client.boilerplate_command_sender import (
    CLA,
    BoilerplateCommandSender,
    Errors,
    InsType,
    MLDSAParam,
    SettingId,
)

PATH = "m/44'/1'/0'/0'/0'"
M_HASH = bytes(range(32))


def _hash_payload(path: str, hash_bytes: bytes) -> bytes:
    """Payload of the hash-signing instructions: BIP32 path then the digest."""
    return pack_derivation_path(path) + hash_bytes


# Each gated instruction with a payload that is otherwise well-formed, so a
# refusal can only be the blind-signing policy and not input validation.
GATED = [
    ("ECDSA_SIGN_HASH", InsType.ECDSA_SIGN_HASH, 0x00, 0x00, _hash_payload(PATH, M_HASH)),
    (
        "HYBRID_SIGN_HASH-44",
        InsType.HYBRID_SIGN_HASH,
        0x00,
        MLDSAParam.MLDSA_44,
        _hash_payload(PATH, M_HASH),
    ),
    (
        "HYBRID_SIGN_HASH-65",
        InsType.HYBRID_SIGN_HASH,
        0x00,
        MLDSAParam.MLDSA_65,
        _hash_payload(PATH, M_HASH),
    ),
    ("SIGN_DILITHIUM-init", InsType.SIGN_DILITHIUM, 0x00, 0x00, b""),
]


@pytest.mark.parametrize("name,ins,p1,p2,data", GATED, ids=[g[0] for g in GATED])
def test_gated_instruction_refused_by_default(
    backend: BackendInterface, name: str, ins: InsType, p1: int, p2: int, data: bytes
) -> None:
    """Fresh NVM: every blind-signing instruction is refused, before any work.

    The accepted-once-enabled direction is covered end to end by the per-INS
    modules (test_ecdsa_sign_hash, test_hybrid_sign_hash, test_pq_sign*), which
    all run under the blind_signing_enabled fixture.
    """
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=ins, p1=p1, p2=p2, data=data)
    assert e.value.status == Errors.SW_BLIND_SIGNING_DISABLED


def test_setting_round_trips(backend: BackendInterface) -> None:
    """Enabling then disabling returns the device to refusing."""
    client = BoilerplateCommandSender(backend)

    client.set_setting(SettingId.BLIND_SIGNING, True)
    client.set_setting(SettingId.BLIND_SIGNING, False)

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.ECDSA_SIGN_HASH, p1=0, p2=0, data=_hash_payload(PATH, M_HASH)
        )
    assert e.value.status == Errors.SW_BLIND_SIGNING_DISABLED


def test_set_setting_rejects_bad_parameters(backend: BackendInterface) -> None:
    """SET_SETTING validates P1/P2 and takes no data."""
    for p1, p2, data in [
        (0xFF, 0x01, b""),  # unknown setting id
        (0x00, 0x02, b""),  # value outside {0, 1}
    ]:
        with pytest.raises(ExceptionRAPDU) as e:
            backend.exchange(cla=CLA, ins=InsType.SET_SETTING, p1=p1, p2=p2, data=data)
        assert e.value.status == Errors.SWO_INCORRECT_P1_P2

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.SET_SETTING, p1=0x00, p2=0x01, data=b"\x00")
    assert e.value.status == Errors.SWO_WRONG_DATA_LENGTH


def test_userop_clear_signing_needs_no_opt_in(backend: BackendInterface) -> None:
    """HYBRID_SIGN_USEROP stays available with blind signing off.

    Only the callData-withheld variant is blind, so the clear-signed path must
    not be caught by the gate. Stops before the finalize step, which would
    trigger the review.
    """
    chain_id = (11155111).to_bytes(32, "big")
    entry_point = bytes.fromhex("0000000071727de22e5e9d8baf0edac6f37da032")
    sender = bytes.fromhex("1111111111111111111111111111111111111111")
    nonce = (42).to_bytes(32, "big")

    for p1, data in [
        (0x00, pack_derivation_path(PATH)),
        (0x01, chain_id + entry_point + sender + nonce),
        (0x02, bytes(6 * 32)),
    ]:
        rapdu = backend.exchange(
            cla=CLA, ins=InsType.HYBRID_SIGN_USEROP, p1=p1, p2=MLDSAParam.MLDSA_44, data=data
        )
        assert rapdu.status == Errors.SWO_SUCCESS


def test_settings_ui_toggles_blind_signing(
    backend: BackendInterface, device: Device, navigator: Navigator
) -> None:
    """The Settings switch is what a real user has; it must flip the NVM flag.

    Covers the code path SET_SETTING bypasses: the switch plus its confirmation
    screen in src/ui/menu_nbgl.c. Verified by behaviour — an instruction that
    was refused before the navigation is accepted after it.
    """
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.ECDSA_SIGN_HASH, p1=0, p2=0, data=_hash_payload(PATH, M_HASH)
        )
    assert e.value.status == Errors.SW_BLIND_SIGNING_DISABLED

    if device.is_nano:
        instructions = [
            NavInsID.RIGHT_CLICK,  # home -> App settings
            NavInsID.BOTH_CLICK,  # enter settings, on "Blind signing"
            NavInsID.BOTH_CLICK,  # toggle -> warning choice
            NavInsID.RIGHT_CLICK,  # warning page 1/2
            NavInsID.RIGHT_CLICK,  # warning page 2/2
            NavInsID.RIGHT_CLICK,  # "I understand, confirm"
            NavInsID.BOTH_CLICK,  # confirm
        ]
    elif device.type is DeviceType.APEX_P:
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (243, 90)),
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        ]
    else:  # STAX, FLEX
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        ]

    navigator.navigate(instructions, screen_change_before_first_instruction=False)

    # The flag flipped: the same gated instruction that was refused above is now
    # let through. SIGN_DILITHIUM's init step answers synchronously, so this
    # checks the policy without opening a review that would need approving.
    # (It answers 0x6985 with no key loaded; any status but the blind-signing
    # refusal proves the gate opened.)
    try:
        status = backend.exchange(
            cla=CLA, ins=InsType.SIGN_DILITHIUM, p1=0x00, p2=0x00, data=b""
        ).status
    except ExceptionRAPDU as e:
        status = e.status
    assert status != Errors.SW_BLIND_SIGNING_DISABLED, (
        "Settings switch did not enable blind signing"
    )

    # Toggling back off takes no confirmation. Both switch states render the
    # same text, so the navigator cannot wait on a screen change here; assert
    # on the behaviour instead.
    toggle_off = [NavInsID.BOTH_CLICK] if device.is_nano else [
        NavIns(NavInsID.TOUCH, (243, 90) if device.type is DeviceType.APEX_P else (200, 113))
    ]
    navigator.navigate(
        toggle_off,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False,
    )

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(
            cla=CLA, ins=InsType.ECDSA_SIGN_HASH, p1=0, p2=0, data=_hash_payload(PATH, M_HASH)
        )
    assert e.value.status == Errors.SW_BLIND_SIGNING_DISABLED
