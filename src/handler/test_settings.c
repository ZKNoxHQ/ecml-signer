#include "test_settings.h"

#ifdef HAVE_TEST_INS

#include <stdint.h>

#include "os.h"
#include "io.h"

#include "globals.h"
#include "sw.h"

#define SETTING_ID_BLIND_SIGNING 0x00

int handler_set_setting(uint8_t p1, uint8_t p2) {
    if (p2 > 0x01) {
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }

    switch (p1) {
        case SETTING_ID_BLIND_SIGNING: {
            uint8_t value = p2;
            nvm_write((void *) &N_storage.blind_signing_allowed, &value, 1);
            return io_send_sw(SWO_SUCCESS);
        }
        default:
            return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}

#endif  // HAVE_TEST_INS
