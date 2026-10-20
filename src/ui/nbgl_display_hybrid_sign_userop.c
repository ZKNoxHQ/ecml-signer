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

// A uint256 has at most 78 decimal digits (2^256 - 1 ~ 1.16e77).
#define UINT256_DEC_DIGITS 78
// 20-byte address as hex, as format_hex writes it (2 chars per byte + NUL).
#define ADDRESS_HEX_LEN (20 * 2 + 1)
#define HASH_HEX_LEN    (32 * 2 + 1)

// Pair buffers. Static so NBGL can hold pointers across the review flow.
static char g_userop_chain[UINT256_DEC_DIGITS + 1];
static char g_userop_sender[ADDRESS_HEX_LEN];
static char g_userop_token[ADDRESS_HEX_LEN];
static char g_userop_to[ADDRESS_HEX_LEN];
static char g_userop_value[UINT256_DEC_DIGITS + 1];
static char g_userop_hash[HASH_HEX_LEN];
// "ECDSA + ML-DSA-44" / "ECDSA + ML-DSA-65"
static char g_userop_scheme[8 + 9 + 1];

// At most: signer / chain / sender / token / to / amount (ERC-20 transfer).
static nbgl_contentTagValue_t userop_pairs[6];
static nbgl_contentTagValueList_t userop_pairList;

// Big-endian uint256 -> decimal, full width (no uint64 truncation, no hex
// fallback): long division by 10 over a 32-byte copy. Returns false only if
// the output buffer is too small.
static bool uint256_be_to_dec(const uint8_t be[32], char *out, size_t out_len) {
    uint8_t n[32];
    char rev[UINT256_DEC_DIGITS];
    size_t pos = 0;
    bool nonzero;

    memmove(n, be, sizeof(n));
    do {
        uint32_t rem = 0;
        nonzero = false;
        for (size_t i = 0; i < sizeof(n); i++) {
            uint32_t cur = (rem << 8) | n[i];
            n[i] = (uint8_t) (cur / 10);
            rem = cur % 10;
            nonzero |= (n[i] != 0);
        }
        rev[pos++] = (char) ('0' + rem);
    } while (nonzero && pos < sizeof(rev));

    if (nonzero || pos + 1 > out_len) {
        return false;
    }
    for (size_t i = 0; i < pos; i++) {
        out[i] = rev[pos - 1 - i];
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
    explicit_bzero(g_userop_token, sizeof(g_userop_token));
    explicit_bzero(g_userop_to, sizeof(g_userop_to));
    explicit_bzero(g_userop_value, sizeof(g_userop_value));
    explicit_bzero(g_userop_hash, sizeof(g_userop_hash));

    // Every line below is mandatory for its review: if one cannot be
    // formatted, refuse to review rather than show a partial screen.
    bool ok = true;
    int pair_index = 0;
    const userop_call_kind_t kind = userop_get_call_kind();

    // The ML-DSA parameter set is chosen by the host (P2): show it so the
    // user knows which of the two independent ML-DSA keys is used.
    snprintf(g_userop_scheme,
             sizeof(g_userop_scheme),
             "ECDSA + %s",
             mldsa_param_name(G_context.tx_info.mldsa_param));
    userop_pairs[pair_index].item = "Signer";
    userop_pairs[pair_index++].value = g_userop_scheme;

    ok &= uint256_be_to_dec(userop_get_chain_id(), g_userop_chain, sizeof(g_userop_chain));
    userop_pairs[pair_index].item = "Chain ID";
    userop_pairs[pair_index++].value = g_userop_chain;

    ok &= format_hex(userop_get_sender(), 20, g_userop_sender, sizeof(g_userop_sender)) != -1;
    userop_pairs[pair_index].item = "Sender";
    userop_pairs[pair_index++].value = g_userop_sender;

    switch (kind) {
        case USEROP_CALL_NATIVE:
            ok &= format_hex(userop_get_call_to(), 20, g_userop_to, sizeof(g_userop_to)) != -1;
            userop_pairs[pair_index].item = "To";
            userop_pairs[pair_index++].value = g_userop_to;
            ok &=
                uint256_be_to_dec(userop_get_call_value(), g_userop_value, sizeof(g_userop_value));
            userop_pairs[pair_index].item = "Value (wei)";
            userop_pairs[pair_index++].value = g_userop_value;
            break;
        case USEROP_CALL_ERC20:
            // No token metadata for this chain on the device: show the
            // contract and the raw amount, never a guessed ticker/decimals.
            ok &= format_hex(userop_get_call_token(), 20, g_userop_token, sizeof(g_userop_token)) !=
                  -1;
            userop_pairs[pair_index].item = "Token";
            userop_pairs[pair_index++].value = g_userop_token;
            ok &= format_hex(userop_get_call_to(), 20, g_userop_to, sizeof(g_userop_to)) != -1;
            userop_pairs[pair_index].item = "To";
            userop_pairs[pair_index++].value = g_userop_to;
            ok &=
                uint256_be_to_dec(userop_get_call_value(), g_userop_value, sizeof(g_userop_value));
            userop_pairs[pair_index].item = "Amount (base units)";
            userop_pairs[pair_index++].value = g_userop_value;
            break;
        default:
            // Nothing decodable: blind signing, show the hash that is signed.
            ok &= format_hex(G_context.tx_info.m_hash, 32, g_userop_hash, sizeof(g_userop_hash)) !=
                  -1;
            userop_pairs[pair_index].item = "UserOp Hash";
            userop_pairs[pair_index++].value = g_userop_hash;
            break;
    }

    if (!ok) {
        G_context.state = STATE_NONE;
        return io_send_sw(SWO_INCORRECT_DATA);
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

    if (kind != USEROP_CALL_NONE) {
        // Clear signing: a decoded native or ERC-20 transfer.
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
