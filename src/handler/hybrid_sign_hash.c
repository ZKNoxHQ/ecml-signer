#include <stdint.h>
#include <string.h>

#include "os.h"
#include "buffer.h"
#include "io.h"

#include "hybrid_sign_hash.h"
#include "constants.h"
#include "display.h"
#include "globals.h"
#include "sw.h"

#define M_HASH_LEN 32

int handler_hybrid_sign_hash(buffer_t *cdata) {
    explicit_bzero(&G_context, sizeof(G_context));

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    if (cdata->size - cdata->offset != M_HASH_LEN) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    if (!buffer_move(cdata, G_context.tx_info.m_hash, M_HASH_LEN)) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    // NOTE: seed is derived inside validate_hybrid_sign_hash() (post-approval)
    // rather than here, to close the ZKNOX pre-approval seed-exfiltration
    // window described in this handler's .h file.

    G_context.state    = STATE_PARSED;
    G_context.req_type = CONFIRM_HYBRID_SIGN_HASH;

    return ui_display_hybrid_sign_hash();
}
