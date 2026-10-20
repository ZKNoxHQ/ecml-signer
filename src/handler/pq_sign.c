#include <stdint.h>
#include <string.h>

#include "os.h"
#include "buffer.h"
#include "io.h"

#include "pq_sign.h"
#include "constants.h"
#include "display.h"
#include "globals.h"
#include "sw.h"

// P1 values for the SIGN_DILITHIUM state machine.
#define P1_INIT     0x00
#define P1_ABSORB   0x01
#define P1_FINALIZE 0x80

// Reject sign if no key is loaded — detect by checking that the stored seed is
// non-zero. KEYGEN_DILITHIUM* (0x0c / 0x11) always writes a non-zero seed
// (SLIP-0010 output or caller-supplied) so an all-zero seed means no keygen
// happened since boot. Cheap sentinel and fails closed.
static bool is_key_loaded(void) {
    for (size_t i = 0; i < sizeof(G_context.tx_info.mldsa_seed); i++) {
        if (G_context.tx_info.mldsa_seed[i] != 0) {
            return true;
        }
    }
    return false;
}

static int handle_init(void) {
    if (!is_key_loaded()) {
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
    G_context.state = STATE_NONE;
    G_context.req_type = CONFIRM_PQ_SIGN;
    G_context.tx_info.raw_tx_len = 0;
    return io_send_sw(SWO_SUCCESS);
}

static int handle_absorb(buffer_t *cdata) {
    if (G_context.req_type != CONFIRM_PQ_SIGN || G_context.state != STATE_NONE) {
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
    if (G_context.tx_info.raw_tx_len + cdata->size > sizeof(G_context.tx_info.raw_tx)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }
    if (cdata->size == 0) {
        return io_send_sw(SWO_SUCCESS);
    }
    memmove(G_context.tx_info.raw_tx + G_context.tx_info.raw_tx_len, cdata->ptr, cdata->size);
    G_context.tx_info.raw_tx_len += cdata->size;
    return io_send_sw(SWO_SUCCESS);
}

static int handle_finalize(void) {
    if (G_context.req_type != CONFIRM_PQ_SIGN || G_context.state != STATE_NONE) {
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
    G_context.state = STATE_PARSED;
    return ui_display_pq_sign();
}

int handler_cmd_sign_dilithium(buffer_t *cdata, uint8_t p1) {
    switch (p1) {
        case P1_INIT:
            return handle_init();
        case P1_ABSORB:
            return handle_absorb(cdata);
        case P1_FINALIZE:
            return handle_finalize();
        default:
            return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}
