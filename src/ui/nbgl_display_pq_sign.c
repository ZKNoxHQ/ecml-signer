#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "os.h"
#include "glyphs.h"
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "validate.h"
#include "menu.h"

// Preview length shown on-screen. 32 bytes = 64 hex chars matches a typical
// message-hash size (Keccak-256 / SHA-256) — the most common ML-DSA use case.
#define PQ_SIGN_HEX_PREVIEW_BYTES 32

// Buffer for the "%d bytes" length label.
static char g_pq_length[16];
// Hex preview: PQ_SIGN_HEX_PREVIEW_BYTES * 2 + ellipsis + NUL.
static char g_pq_hex[PQ_SIGN_HEX_PREVIEW_BYTES * 2 + 4];
static nbgl_contentTagValue_t pq_pairs[2];
static nbgl_contentTagValueList_t pq_pairList;

static void pq_review_choice(bool confirm) {
    validate_pq_sign(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

int ui_display_pq_sign(void) {
    if (G_context.req_type != CONFIRM_PQ_SIGN || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        PRINTF("ui_display_pq_sign: bad state %d/%d\n", G_context.req_type, G_context.state);
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    explicit_bzero(g_pq_length, sizeof(g_pq_length));
    explicit_bzero(g_pq_hex, sizeof(g_pq_hex));

    snprintf(g_pq_length, sizeof(g_pq_length), "%u bytes", (unsigned) G_context.tx_info.raw_tx_len);

    // Hex-encode up to PQ_SIGN_HEX_PREVIEW_BYTES of the payload. Append an
    // ellipsis if we truncated so the user can see this isn't the whole thing.
    size_t preview = G_context.tx_info.raw_tx_len < PQ_SIGN_HEX_PREVIEW_BYTES
                         ? G_context.tx_info.raw_tx_len
                         : PQ_SIGN_HEX_PREVIEW_BYTES;
    if (format_hex(G_context.tx_info.raw_tx, preview, g_pq_hex, sizeof(g_pq_hex)) == -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }
    if (G_context.tx_info.raw_tx_len > PQ_SIGN_HEX_PREVIEW_BYTES) {
        size_t len = strlen(g_pq_hex);
        if (len + 3 < sizeof(g_pq_hex)) {
            g_pq_hex[len] = '.';
            g_pq_hex[len + 1] = '.';
            g_pq_hex[len + 2] = '.';
            g_pq_hex[len + 3] = '\0';
        }
    }

    pq_pairs[0].item = "Length";
    pq_pairs[0].value = g_pq_length;
    pq_pairs[1].item = "Payload";
    pq_pairs[1].value = g_pq_hex;

    pq_pairList.nbMaxLinesForValue = 0;
    pq_pairList.nbPairs = 2;
    pq_pairList.pairs = pq_pairs;
    pq_pairList.wrapping = true;

    const char *review_text = "Review\nML-DSA payload";
#ifdef SCREEN_SIZE_WALLET
    const char *sign_text = "Sign\nML-DSA payload?";
#else
    const char *sign_text = NULL;
#endif

    // Payload is opaque bytes with no in-app parsing; treat as blind-sign so
    // the SDK surfaces its warning.
    nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                   &pq_pairList,
                                   &ICON_APP,
                                   review_text,
                                   NULL,
                                   sign_text,
                                   NULL,
                                   pq_review_choice);
    return 0;
}
