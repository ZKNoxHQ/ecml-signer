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
#include "hybrid_sign_userop.h"
#include "mldsa_derive.h"

// Pair buffers. Static so NBGL can hold pointers across the review flow.
// Sizes match what the ZKNOX reference used: 21 chars for uint64 decimals,
// 43 for a 0x-prefixed 20-byte address, 67 for a 0x-prefixed 32-byte hash.
static char g_userop_chain[21];
static char g_userop_sender[43];
static char g_userop_to[43];
static char g_userop_value[67];  // large enough for decimal wei or hex fallback
static char g_userop_hash[67];
// "ECDSA + ML-DSA-44" / "ECDSA + ML-DSA-65"
static char g_userop_scheme[8 + 9 + 1];

// Up to 6 pairs: signer / chain / sender / to / value / hash-fallback. Only
// one of (to+value) vs (hash) is populated at a time, so max 5 in practice.
static nbgl_contentTagValue_t userop_pairs[6];
static nbgl_contentTagValueList_t userop_pairList;

// Big-endian uint256 → decimal string, if it fits in uint64_t. Returns false
// if any of the top 24 bytes are nonzero (overflow) or if the output buffer
// is too small.
static bool uint256_be_to_dec(const uint8_t be[32], char *out, size_t out_len) {
    for (int i = 0; i < 24; i++) {
        if (be[i] != 0) return false;
    }
    uint64_t v = 0;
    for (int i = 24; i < 32; i++) {
        v = (v << 8) | be[i];
    }
    if (v == 0) {
        if (out_len < 2) return false;
        out[0] = '0';
        out[1] = '\0';
        return true;
    }
    char tmp[21];  // UINT64_MAX has 20 digits + NUL
    int pos = 0;
    while (v > 0 && pos < (int) sizeof(tmp) - 1) {
        tmp[pos++] = '0' + (char) (v % 10);
        v /= 10;
    }
    if ((size_t) pos + 1 > out_len) return false;
    for (int i = 0; i < pos; i++) {
        out[i] = tmp[pos - 1 - i];
    }
    out[pos] = '\0';
    return true;
}

static void userop_review_choice(bool confirm) {
    // Reuses the ECDSA + ML-DSA signing action from HYBRID_SIGN_HASH.
    // validate_hybrid_sign_hash signs G_context.tx_info.m_hash (which the
    // userop handler populated with the ERC-4337 v0.7 userOpHash) and does
    // not check req_type, so it is safe to share between the two flows.
    validate_hybrid_sign_hash(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

int ui_display_hybrid_sign_userop(void) {
    if (G_context.req_type != CONFIRM_HYBRID_SIGN_USEROP || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        PRINTF("ui_display_hybrid_sign_userop: bad state %d/%d\n",
               G_context.req_type,
               G_context.state);
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    explicit_bzero(g_userop_chain, sizeof(g_userop_chain));
    explicit_bzero(g_userop_sender, sizeof(g_userop_sender));
    explicit_bzero(g_userop_to, sizeof(g_userop_to));
    explicit_bzero(g_userop_value, sizeof(g_userop_value));
    explicit_bzero(g_userop_hash, sizeof(g_userop_hash));

    int pair_index = 0;

    // The ML-DSA parameter set is chosen by the host (P2): show it so the
    // user knows which of the two independent ML-DSA keys is used.
    snprintf(g_userop_scheme,
             sizeof(g_userop_scheme),
             "ECDSA + %s",
             mldsa_param_name(G_context.tx_info.mldsa_param));
    userop_pairs[pair_index].item = "Signer";
    userop_pairs[pair_index].value = g_userop_scheme;
    pair_index++;

    if (uint256_be_to_dec(userop_get_chain_id(), g_userop_chain, sizeof(g_userop_chain))) {
        userop_pairs[pair_index].item = "Chain ID";
        userop_pairs[pair_index].value = g_userop_chain;
        pair_index++;
    }

    if (format_hex(userop_get_sender(), 20, g_userop_sender, sizeof(g_userop_sender)) != -1) {
        userop_pairs[pair_index].item = "Sender";
        userop_pairs[pair_index].value = g_userop_sender;
        pair_index++;
    }

    if (userop_has_call_info()) {
        if (format_hex(userop_get_call_to(), 20, g_userop_to, sizeof(g_userop_to)) != -1) {
            userop_pairs[pair_index].item = "To";
            userop_pairs[pair_index].value = g_userop_to;
            pair_index++;
        }
        // Decimal wei if it fits in uint64; hex fallback otherwise.
        if (!uint256_be_to_dec(userop_get_call_value(), g_userop_value, sizeof(g_userop_value))) {
            format_hex(userop_get_call_value(), 32, g_userop_value, sizeof(g_userop_value));
        }
        if (g_userop_value[0] != '\0') {
            userop_pairs[pair_index].item = "Value (wei)";
            userop_pairs[pair_index].value = g_userop_value;
            pair_index++;
        }
    } else {
        // No callData parsed — show the computed UserOpHash for transparency.
        if (format_hex(G_context.tx_info.m_hash, 32, g_userop_hash, sizeof(g_userop_hash)) != -1) {
            userop_pairs[pair_index].item = "UserOp Hash";
            userop_pairs[pair_index].value = g_userop_hash;
            pair_index++;
        }
    }

    userop_pairList.nbMaxLinesForValue = 0;
    userop_pairList.nbPairs = pair_index;
    userop_pairList.pairs = userop_pairs;
    userop_pairList.wrapping = true;

    const char *review_text = "Review UserOp\nfor hybrid signing";
#ifdef SCREEN_SIZE_WALLET
    const char *sign_text = "Sign with\nECDSA + ML-DSA?";
#else
    const char *sign_text = NULL;
#endif

    if (userop_has_call_info()) {
        // Clear signing: To / Value parsed from execute(address,uint256,bytes).
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &userop_pairList,
                           &ICON_APP,
                           review_text,
                           NULL,
                           sign_text,
                           userop_review_choice);
    } else {
        // Only the userOpHash can be shown: blind signing. The handler only
        // gets here when the user has opted in to blind signing; surface the
        // SDK warning like every other blind flow of the app.
        nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                       &userop_pairList,
                                       &ICON_APP,
                                       review_text,
                                       NULL,
                                       sign_text,
                                       NULL,
                                       userop_review_choice);
    }
    return 0;
}
