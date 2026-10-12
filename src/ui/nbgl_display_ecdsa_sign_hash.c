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

// 32-byte hash -> 64 hex chars + NUL, kept as a static buffer since NBGL
// retains the pointer across the review flow.
static char g_hash_hex[64 + 1];
static nbgl_contentTagValue_t hash_pairs[1];
static nbgl_contentTagValueList_t hash_pairList;

static void ecdsa_hash_review_choice(bool confirm) {
    validate_transaction(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

int ui_display_ecdsa_sign_hash(void) {
    if (G_context.req_type != CONFIRM_ECDSA_SIGN_HASH || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        PRINTF("ui_display_ecdsa_sign_hash: bad state %d/%d\n",
               G_context.req_type,
               G_context.state);
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    explicit_bzero(g_hash_hex, sizeof(g_hash_hex));
    if (format_hex(G_context.tx_info.m_hash, 32, g_hash_hex, sizeof(g_hash_hex)) == -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    hash_pairs[0].item = "Hash";
    hash_pairs[0].value = g_hash_hex;

    hash_pairList.nbMaxLinesForValue = 0;
    hash_pairList.nbPairs = 1;
    hash_pairList.pairs = hash_pairs;
    hash_pairList.wrapping = true;

    const char *review_text = "Review\nhash to sign";
#ifdef SCREEN_SIZE_WALLET
    const char *sign_text = "Sign\nhash?";
#else
    const char *sign_text = NULL;
#endif

    nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                   &hash_pairList,
                                   &ICON_APP,
                                   review_text,
                                   NULL,
                                   sign_text,
                                   NULL,
                                   ecdsa_hash_review_choice);
    return 0;
}
