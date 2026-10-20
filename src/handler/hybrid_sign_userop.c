#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "buffer.h"
#include "io.h"
#include "lcx_sha3.h"

#include "hybrid_sign_userop.h"
#include "mldsa_derive.h"
#include "constants.h"
#include "display.h"
#include "globals.h"
#include "sw.h"

// ABI layout of the outer call, execute(address dest, uint256 value, bytes data)
// (selector 0xb61d27f6), canonically encoded:
//   [  0..  4) selector
//   [  4.. 36) dest   (address, left-padded with 12 zero bytes)
//   [ 36.. 68) value
//   [ 68..100) offset of `data` = 0x60, the only canonical value
//   [100..132) length L of `data`
//   [132..132 + ceil32(L)) data, zero-padded to a 32-byte boundary
#define ABI_WORD            32
#define ABI_SELECTOR_LEN    4
#define ABI_ADDRESS_PAD     12  // zero bytes before a 20-byte address in its word
#define EXEC_DEST_OFF       4
#define EXEC_VALUE_OFF      36
#define EXEC_DATA_PTR_OFF   68
#define EXEC_DATA_LEN_OFF   100
#define EXEC_DATA_OFF       132
#define EXEC_DATA_PTR_CANON 0x60

// Inner call recognised for clear signing: ERC-20 transfer(address to,
// uint256 amount) (selector 0xa9059cbb), exactly selector + 2 words.
#define ERC20_TO_OFF       4
#define ERC20_AMOUNT_OFF   36
#define ERC20_TRANSFER_LEN 68

static const uint8_t EXECUTE_SELECTOR[ABI_SELECTOR_LEN] = {0xb6, 0x1d, 0x27, 0xf6};
static const uint8_t ERC20_TRANSFER_SELECTOR[ABI_SELECTOR_LEN] = {0xa9, 0x05, 0x9c, 0xbb};

#define P1_USEROP_PATH          0x00
#define P1_USEROP_METADATA      0x01
#define P1_USEROP_PACKED_FIELDS 0x02
#define P1_USEROP_CALLDATA      0x03

// Accumulator lives across the 4-APDU flow. RAM cost ~380 B in .bss; wiped on
// every fresh P1=0x00 and on any mid-flow failure.
typedef struct {
    uint8_t chain_id[32];
    uint8_t entry_point[20];

    uint8_t sender[20];
    uint8_t nonce[32];
    uint8_t hash_init_code[32];
    uint8_t hash_call_data[32];
    uint8_t account_gas_limits[32];
    uint8_t pre_verification_gas[32];
    uint8_t gas_fees[32];
    uint8_t hash_paymaster_and_data[32];

    // What the device could decode, i.e. what it can clear-sign. NONE means
    // blind signing: only the userOpHash can be shown.
    userop_call_kind_t call_kind;
    uint8_t call_to[20];     // NATIVE: destination. ERC20: token recipient.
    uint8_t call_value[32];  // NATIVE: wei. ERC20: token amount (base units).
    uint8_t call_token[20];  // ERC20: token contract.

    MLDSA_param_t param;  // ML-DSA parameter set fixed by the P1 = 0x00 APDU
    uint8_t step;         // tracks which P1 we expect next
} userop_ctx_t;

static userop_ctx_t userop_ctx;

// ---------------------------------------------------------------------------
// Keccak helpers
// ---------------------------------------------------------------------------

static inline int keccak_absorb_word(cx_sha3_t *ctx, const uint8_t *word32) {
    return cx_hash_no_throw((cx_hash_t *) ctx, 0, word32, 32, NULL, 0);
}

static int keccak_absorb_address(cx_sha3_t *ctx, const uint8_t *addr20) {
    uint8_t padded[32] = {0};
    memmove(padded + 12, addr20, 20);
    int rc = keccak_absorb_word(ctx, padded);
    explicit_bzero(padded, sizeof(padded));
    return rc;
}

// Compute the ERC-4337 v0.7 userOpHash from the accumulated context.
// Result goes into G_context.tx_info.m_hash.
static int compute_userop_hash(void) {
    cx_sha3_t kctx;
    uint8_t inner_hash[32] = {0};

    // 1. Inner hash: keccak256(abi.encode(packed fields))
    if (cx_keccak_init_no_throw(&kctx, 256) != CX_OK) return -1;

    if (keccak_absorb_address(&kctx, userop_ctx.sender) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.nonce) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.hash_init_code) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.hash_call_data) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.account_gas_limits) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.pre_verification_gas) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.gas_fees) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, userop_ctx.hash_paymaster_and_data) != CX_OK) return -1;

    if (cx_hash_no_throw((cx_hash_t *) &kctx, CX_LAST, NULL, 0, inner_hash, sizeof(inner_hash)) !=
        CX_OK) {
        return -1;
    }

    // 2. Outer hash: keccak256(abi.encode(innerHash, entryPoint, chainId))
    if (cx_keccak_init_no_throw(&kctx, 256) != CX_OK) return -1;
    if (keccak_absorb_word(&kctx, inner_hash) != CX_OK) return -1;
    if (keccak_absorb_address(&kctx, userop_ctx.entry_point) != CX_OK) return -1;

    if (cx_hash_no_throw((cx_hash_t *) &kctx,
                         CX_LAST,
                         userop_ctx.chain_id,
                         32,
                         G_context.tx_info.m_hash,
                         sizeof(G_context.tx_info.m_hash)) != CX_OK) {
        return -1;
    }

    explicit_bzero(inner_hash, sizeof(inner_hash));
    explicit_bzero(&kctx, sizeof(kctx));
    return 0;
}

static bool all_zero(const uint8_t *buf, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= buf[i];
    }
    return acc == 0;
}

// A 32-byte ABI word holding a small integer: fails unless the value fits in
// 16 bits, which bounds every length/offset below and keeps the arithmetic
// overflow-free.
static bool abi_word_to_u16(const uint8_t word[ABI_WORD], uint16_t *out) {
    if (!all_zero(word, ABI_WORD - 2)) {
        return false;
    }
    *out = (uint16_t) ((word[ABI_WORD - 2] << 8) | word[ABI_WORD - 1]);
    return true;
}

// Decode a hash-verified callData into what the review can show. Strict on
// purpose: anything that is not exactly one of the two recognised shapes, in
// canonical ABI encoding, is USEROP_CALL_NONE (blind signing). Accepting a
// non-canonical encoding would let the screen show one reading of bytes that
// a contract may decode differently.
static userop_call_kind_t decode_calldata(const uint8_t *data, uint16_t len) {
    uint16_t ptr, inner_len;

    if (len < EXEC_DATA_OFF || memcmp(data, EXECUTE_SELECTOR, ABI_SELECTOR_LEN) != 0) {
        return USEROP_CALL_NONE;
    }
    if (!all_zero(data + EXEC_DEST_OFF, ABI_ADDRESS_PAD)) {
        return USEROP_CALL_NONE;  // dirty address padding
    }
    if (!abi_word_to_u16(data + EXEC_DATA_PTR_OFF, &ptr) || ptr != EXEC_DATA_PTR_CANON) {
        return USEROP_CALL_NONE;
    }
    if (!abi_word_to_u16(data + EXEC_DATA_LEN_OFF, &inner_len)) {
        return USEROP_CALL_NONE;
    }
    // Exactly the data plus its zero padding, nothing trailing. 32-bit math:
    // inner_len <= 0xFFFF, so no overflow.
    uint32_t padded = ((uint32_t) inner_len + ABI_WORD - 1) / ABI_WORD * ABI_WORD;
    if ((uint32_t) len != EXEC_DATA_OFF + padded) {
        return USEROP_CALL_NONE;
    }
    const uint8_t *inner = data + EXEC_DATA_OFF;
    if (!all_zero(inner + inner_len, padded - inner_len)) {
        return USEROP_CALL_NONE;  // dirty padding
    }

    if (inner_len == 0) {
        // Plain native transfer (or a call to a receive/fallback with no data).
        memmove(userop_ctx.call_to, data + EXEC_DEST_OFF + ABI_ADDRESS_PAD, 20);
        memmove(userop_ctx.call_value, data + EXEC_VALUE_OFF, ABI_WORD);
        return USEROP_CALL_NATIVE;
    }

    if (inner_len == ERC20_TRANSFER_LEN &&
        memcmp(inner, ERC20_TRANSFER_SELECTOR, ABI_SELECTOR_LEN) == 0 &&
        all_zero(inner + ERC20_TO_OFF, ABI_ADDRESS_PAD) &&
        // A token transfer that also sends native value is not a shape we can
        // show honestly on one screen: refuse to clear-sign it.
        all_zero(data + EXEC_VALUE_OFF, ABI_WORD)) {
        memmove(userop_ctx.call_token, data + EXEC_DEST_OFF + ABI_ADDRESS_PAD, 20);
        memmove(userop_ctx.call_to, inner + ERC20_TO_OFF + ABI_ADDRESS_PAD, 20);
        memmove(userop_ctx.call_value, inner + ERC20_AMOUNT_OFF, ABI_WORD);
        return USEROP_CALL_ERC20;
    }

    return USEROP_CALL_NONE;  // any other inner call: approve, swap, ...
}

// Verify keccak256(callData) matches hashCallData, then decode it for clear
// signing. len == 0 means the host withheld callData: nothing is verified and
// nothing can be shown (USEROP_CALL_NONE).
static int process_calldata(const uint8_t *data, uint16_t len) {
    userop_ctx.call_kind = USEROP_CALL_NONE;

    if (len == 0) {
        return 0;
    }

    cx_sha3_t kctx;
    uint8_t computed[32] = {0};
    int rc = -1;

    if (cx_keccak_init_no_throw(&kctx, 256) != CX_OK) goto end;
    if (cx_hash_no_throw((cx_hash_t *) &kctx, CX_LAST, data, len, computed, sizeof(computed)) !=
        CX_OK) {
        goto end;
    }
    if (memcmp(computed, userop_ctx.hash_call_data, 32) != 0) {
        PRINTF("handler_hybrid_sign_userop: callData hash mismatch\n");
        goto end;
    }

    userop_ctx.call_kind = decode_calldata(data, len);
    rc = 0;

end:
    explicit_bzero(computed, sizeof(computed));
    explicit_bzero(&kctx, sizeof(kctx));
    return rc;
}

// ---------------------------------------------------------------------------
// Public handler
// ---------------------------------------------------------------------------

int handler_hybrid_sign_userop(buffer_t *cdata, uint8_t p1, MLDSA_param_t param) {
    // The parameter set is chosen by the first APDU; every following APDU of
    // the sequence must repeat it (a mismatch is a client bug, fail closed).
    if (p1 != P1_USEROP_PATH && param != userop_ctx.param) {
        return io_send_sw(SWO_INCORRECT_P1_P2);
    }

    switch (p1) {
        case P1_USEROP_PATH: {
            explicit_bzero(&userop_ctx, sizeof(userop_ctx));
            userop_ctx.param = param;

            if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
                !buffer_read_bip32_path(cdata,
                                        G_context.bip32_path,
                                        (size_t) G_context.bip32_path_len)) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            userop_ctx.step = P1_USEROP_METADATA;
            return io_send_sw(SWO_SUCCESS);
        }

        case P1_USEROP_METADATA: {
            if (userop_ctx.step != P1_USEROP_METADATA) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (cdata->size - cdata->offset != 32 + 20 + 20 + 32) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            // The SDK's buffer_move/buffer_copy has surprising semantics for
            // fixed-size reads (returns false when the buffer has MORE bytes
            // than the target — intended for "read all remaining into target").
            // We use direct memmove + buffer_seek_cur, matching the ZKNOX and
            // existing sign_tx patterns.
            memmove(userop_ctx.chain_id, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);
            memmove(userop_ctx.entry_point, cdata->ptr + cdata->offset, 20);
            buffer_seek_cur(cdata, 20);
            memmove(userop_ctx.sender, cdata->ptr + cdata->offset, 20);
            buffer_seek_cur(cdata, 20);
            memmove(userop_ctx.nonce, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);

            userop_ctx.step = P1_USEROP_PACKED_FIELDS;
            return io_send_sw(SWO_SUCCESS);
        }

        case P1_USEROP_PACKED_FIELDS: {
            if (userop_ctx.step != P1_USEROP_PACKED_FIELDS) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (cdata->size - cdata->offset != 6 * 32) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            memmove(userop_ctx.hash_init_code, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);
            memmove(userop_ctx.hash_call_data, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);
            memmove(userop_ctx.account_gas_limits, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);
            memmove(userop_ctx.pre_verification_gas, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);
            memmove(userop_ctx.gas_fees, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);
            memmove(userop_ctx.hash_paymaster_and_data, cdata->ptr + cdata->offset, 32);
            buffer_seek_cur(cdata, 32);

            userop_ctx.step = P1_USEROP_CALLDATA;
            return io_send_sw(SWO_SUCCESS);
        }

        case P1_USEROP_CALLDATA: {
            if (userop_ctx.step != P1_USEROP_CALLDATA) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            uint16_t remaining = cdata->size - cdata->offset;

            if (process_calldata(cdata->ptr + cdata->offset, remaining) != 0) {
                explicit_bzero(&userop_ctx, sizeof(userop_ctx));
                return io_send_sw(SWO_INCORRECT_DATA);
            }

            // Clear signing needs something decoded to show (see
            // decode_calldata: a native transfer or an ERC-20 transfer). Without
            // it the review falls back to the bare userOpHash, which is blind
            // signing. Refuse unless the user has opted in, and wipe the
            // accumulated UserOp. This is the same condition the review screen
            // branches on (userop_get_call_kind), so the gate and the screen
            // cannot disagree.
            if (userop_ctx.call_kind == USEROP_CALL_NONE && !BLIND_SIGNING_ALLOWED()) {
                explicit_bzero(&userop_ctx, sizeof(userop_ctx));
                return io_send_sw(SW_BLIND_SIGNING_DISABLED);
            }

            if (compute_userop_hash() != 0) {
                explicit_bzero(&userop_ctx, sizeof(userop_ctx));
                return io_send_sw(SWO_INCORRECT_DATA);
            }

            G_context.tx_info.mldsa_param = userop_ctx.param;
            G_context.req_type = CONFIRM_HYBRID_SIGN_USEROP;
            G_context.state = STATE_PARSED;
            userop_ctx.step = 0xFF;

            return ui_display_hybrid_sign_userop();
        }

        default:
            return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}

// ---------------------------------------------------------------------------
// Accessors for the NBGL display layer
// ---------------------------------------------------------------------------

const uint8_t *userop_get_sender(void) {
    return userop_ctx.sender;
}
const uint8_t *userop_get_chain_id(void) {
    return userop_ctx.chain_id;
}
const uint8_t *userop_get_call_to(void) {
    return userop_ctx.call_to;
}
const uint8_t *userop_get_call_value(void) {
    return userop_ctx.call_value;
}
userop_call_kind_t userop_get_call_kind(void) {
    return userop_ctx.call_kind;
}
const uint8_t *userop_get_call_token(void) {
    return userop_ctx.call_token;
}
