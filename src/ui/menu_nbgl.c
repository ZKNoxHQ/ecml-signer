
/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"

#include "globals.h"
#include "menu.h"
#include "display.h"

//  -----------------------------------------------------------
//  ----------------------- HOME PAGE -------------------------
//  -----------------------------------------------------------

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

//  -----------------------------------------------------------
//  --------------------- SETTINGS MENU -----------------------
//  -----------------------------------------------------------
#define SETTING_INFO_NB 2
static const char *const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer"};
static const char *const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, "Ledger"};

// settings switches definitions
enum { BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN };
enum { BLIND_SIGNING_ID = 0, SETTINGS_SWITCHES_NB };

static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

static uint8_t initSettingPage;
static void review_warning_choice(bool confirm);
static void controls_callback(int token, uint8_t index, int page);

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB,
     .content.switchesList.switches = switches,
     .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

// callback for setting warning choice
static void review_warning_choice(bool confirm) {
    uint8_t switch_value;
    if (confirm) {
        // Only ever reached when turning blind signing ON (turning it OFF needs
        // no confirmation), so this always enables it.
        switch_value = 0x01;
        switches[BLIND_SIGNING_ID].initState = (nbgl_state_t) switch_value;
        // store the new setting value in NVM
        nvm_write((void *) &N_storage.blind_signing_allowed, &switch_value, 1);
    }

    // Reset setting menu to the right page
    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_APP_HOME,
                                NULL,
                                initSettingPage,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
}

static void controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);

    initSettingPage = page;

    uint8_t switch_value;
    if (token == BLIND_SIGNING_TOKEN) {
        if (!N_storage.blind_signing_allowed) {
            // Enabling is the dangerous direction: warn and require an
            // explicit confirmation before writing it to NVM.
            nbgl_useCaseChoice(&ICON_APP_WARNING,
                               "Blind signing",
                               "Allow signing data\nthat cannot be\ndisplayed? Only "
                               "enable if you\ntrust the application.",
                               "I understand, confirm",
                               "Cancel",
                               review_warning_choice);
        } else {
            // Disabling is always safe — no confirmation needed.
            switch_value = 0x00;
            switches[BLIND_SIGNING_ID].initState = (nbgl_state_t) switch_value;
            nvm_write((void *) &N_storage.blind_signing_allowed, &switch_value, 1);
        }
    }
}

// home page definition
void ui_menu_main(void) {
    // Initialize switches data
    switches[BLIND_SIGNING_ID].initState = (nbgl_state_t) N_storage.blind_signing_allowed;
    switches[BLIND_SIGNING_ID].text = "Blind signing";
    switches[BLIND_SIGNING_ID].subText = "Allow signing data\nthat cannot be displayed";
    switches[BLIND_SIGNING_ID].token = BLIND_SIGNING_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    switches[BLIND_SIGNING_ID].tuneId = TUNE_TAP_CASUAL;
#endif

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_APP_HOME,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
}
