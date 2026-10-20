from ledgered.devices import Device, DeviceType
from ragger.navigator import Navigator, NavIns, NavInsID


# In this test we check the behavior of the device main menu
def test_app_mainmenu(device: Device, navigator: Navigator, test_name: str, default_screenshot_path: str) -> None:
    # Navigate in the main menu
    # The settings list holds a single switch, "Blind signing". Enabling it goes
    # through a confirmation screen. The walk below turns it on, confirms, and
    # leaves the settings.
    #
    # Turning it back off is deliberately not part of the walk: the switch's two
    # states render the same text, so the navigator's screen-change wait times
    # out on it. That branch is covered behaviourally in test_blind_signing.py.
    instructions = []
    if device.is_nano:
        instructions += [
            NavInsID.RIGHT_CLICK,  # home -> App settings
            NavInsID.BOTH_CLICK,  # enter settings, on "Blind signing"
            NavInsID.BOTH_CLICK,  # toggle on -> warning choice
            NavInsID.RIGHT_CLICK,  # warning page 1/2
            NavInsID.RIGHT_CLICK,  # warning page 2/2
            NavInsID.RIGHT_CLICK,  # "I understand, confirm"
            NavInsID.BOTH_CLICK,  # confirm
            NavInsID.RIGHT_CLICK,  # -> "Back"
            NavInsID.BOTH_CLICK,  # leave settings
        ]
    elif device.type is DeviceType.STAX:
        instructions += [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),  # the switch
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ]
    elif device.type is DeviceType.FLEX:
        instructions += [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (200, 113)),
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ]
    elif device.type is DeviceType.APEX_P:
        instructions += [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (243, 90)),
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ]

    assert len(instructions) > 0
    navigator.navigate_and_compare(
        default_screenshot_path,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
    )
