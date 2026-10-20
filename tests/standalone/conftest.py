###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)

import pytest
from ragger.backend.interface import BackendInterface

from application_client.boilerplate_command_sender import BoilerplateCommandSender, SettingId


@pytest.fixture
def blind_signing_enabled(backend: BackendInterface):
    """Turn the blind-signing setting on for the duration of a test.

    Blind signing defaults to OFF, so every instruction that signs bytes the
    review screen cannot represent (ECDSA_SIGN_HASH, HYBRID_SIGN_HASH,
    SIGN_DILITHIUM, HYBRID_SIGN_USEROP without callData) answers
    SW_BLIND_SIGNING_DISABLED until the user opts in. Tests that exercise those
    flows request this fixture; tests asserting the refusal must not.

    Uses SET_SETTING, which exists only on TEST_INS=1 / DEBUG=1 builds, so the
    whole standalone suite requires such a build.
    """
    client = BoilerplateCommandSender(backend)
    client.set_setting(SettingId.BLIND_SIGNING, True)
    yield
    # Speculos starts each test from a clean NVM, so restoring is belt and
    # braces. It is best-effort: after a flow that ends on a review status
    # screen the device may not accept another APDU, and that must not turn a
    # passing test into a teardown error.
    try:
        client.set_setting(SettingId.BLIND_SIGNING, False)
    except Exception:
        pass
