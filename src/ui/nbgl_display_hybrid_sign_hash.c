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
#include "mldsa_derive.h"

// 32-byte hash -> 64 hex chars + NUL. Kept as a static buffer because NBGL
// retains the pointer across the review flow.
static char g_hybrid_hash_hex[64 + 1];
// "ECDSA + ML-DSA-44" / "ECDSA + ML-DSA-65"
static char g_hybrid_scheme[8 + 9 + 1];
static nbgl_contentTagValue_t     hybrid_pairs[2];
static nbgl_contentTagValueList_t hybrid_pairList;

static void hybrid_hash_review_choice(bool confirm) {
    validate_hybrid_sign_hash(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

int ui_display_hybrid_sign_hash(void) {
    if (G_context.req_type != CONFIRM_HYBRID_SIGN_HASH || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        PRINTF("ui_display_hybrid_sign_hash: bad state %d/%d\n",
               G_context.req_type,
               G_context.state);
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    explicit_bzero(g_hybrid_hash_hex, sizeof(g_hybrid_hash_hex));
    if (format_hex(G_context.tx_info.m_hash, 32, g_hybrid_hash_hex, sizeof(g_hybrid_hash_hex))
        == -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    // The ML-DSA parameter set is chosen by the host (P2): show it so the
    // user knows which of the two independent ML-DSA keys is used.
    snprintf(g_hybrid_scheme,
             sizeof(g_hybrid_scheme),
             "ECDSA + %s",
             mldsa_param_name(G_context.tx_info.mldsa_param));

    hybrid_pairs[0].item  = "Signer";
    hybrid_pairs[0].value = g_hybrid_scheme;
    hybrid_pairs[1].item  = "Hash";
    hybrid_pairs[1].value = g_hybrid_hash_hex;

    hybrid_pairList.nbMaxLinesForValue = 0;
    hybrid_pairList.nbPairs            = 2;
    hybrid_pairList.pairs              = hybrid_pairs;
    hybrid_pairList.wrapping           = true;

    const char *review_text = "Review\nhybrid signature";
#ifdef SCREEN_SIZE_WALLET
    const char *sign_text = "Sign with\nECDSA + ML-DSA?";
#else
    const char *sign_text = NULL;
#endif

    nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                   &hybrid_pairList,
                                   &ICON_APP_BOILERPLATE,
                                   review_text,
                                   NULL,
                                   sign_text,
                                   NULL,
                                   hybrid_hash_review_choice);
    return 0;
}
