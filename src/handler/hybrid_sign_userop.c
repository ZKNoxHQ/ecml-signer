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

// execute(address,uint256,bytes) function selector (Keccak-256 of the signature,
// first 4 bytes) = 0xb61d27f6.
#define EXECUTE_SELECTOR_0 0xb6
#define EXECUTE_SELECTOR_1 0x1d
#define EXECUTE_SELECTOR_2 0x27
#define EXECUTE_SELECTOR_3 0xf6
#define EXECUTE_MIN_LEN    68  // 4-byte selector + 32-byte dest word + 32-byte value word

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

    uint8_t call_to[20];
    uint8_t call_value[32];
    bool    has_call_info;

    MLDSA_param_t param;  // ML-DSA parameter set fixed by the P1 = 0x00 APDU
    uint8_t       step;   // tracks which P1 we expect next
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
    uint8_t   inner_hash[32] = {0};

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

    if (cx_hash_no_throw((cx_hash_t *) &kctx, CX_LAST, NULL, 0, inner_hash, sizeof(inner_hash))
        != CX_OK) {
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
                         sizeof(G_context.tx_info.m_hash))
        != CX_OK) {
        return -1;
    }

    explicit_bzero(inner_hash, sizeof(inner_hash));
    explicit_bzero(&kctx, sizeof(kctx));
    return 0;
}

// Verify keccak256(callData) matches hashCallData, and try to parse
// execute(address,uint256,bytes) to populate call_to/call_value for
// clear-signing. len == 0 means the host chose to skip callData verification;
// UI will fall back to showing the userOpHash.
static int process_calldata(const uint8_t *data, uint16_t len) {
    userop_ctx.has_call_info = false;

    if (len == 0) {
        return 0;
    }

    cx_sha3_t kctx;
    uint8_t   computed[32] = {0};

    if (cx_keccak_init_no_throw(&kctx, 256) != CX_OK) return -1;
    if (cx_hash_no_throw((cx_hash_t *) &kctx, CX_LAST, data, len, computed, sizeof(computed))
        != CX_OK) {
        explicit_bzero(computed, sizeof(computed));
        return -1;
    }

    if (memcmp(computed, userop_ctx.hash_call_data, 32) != 0) {
        PRINTF("handler_hybrid_sign_userop: callData hash mismatch\n");
        explicit_bzero(computed, sizeof(computed));
        return -1;
    }

    // Try to parse execute(address dest, uint256 value, bytes data).
    if (len >= EXECUTE_MIN_LEN && data[0] == EXECUTE_SELECTOR_0 && data[1] == EXECUTE_SELECTOR_1
        && data[2] == EXECUTE_SELECTOR_2 && data[3] == EXECUTE_SELECTOR_3) {
        // dest is right-aligned in a 32-byte ABI word starting at offset 4.
        memmove(userop_ctx.call_to, data + 4 + 12, 20);
        // value is a full 32-byte word at offset 36.
        memmove(userop_ctx.call_value, data + 4 + 32, 32);
        userop_ctx.has_call_info = true;
    }

    explicit_bzero(computed, sizeof(computed));
    explicit_bzero(&kctx, sizeof(kctx));
    return 0;
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

            if (compute_userop_hash() != 0) {
                explicit_bzero(&userop_ctx, sizeof(userop_ctx));
                return io_send_sw(SWO_INCORRECT_DATA);
            }

            G_context.tx_info.mldsa_param = userop_ctx.param;
            G_context.req_type            = CONFIRM_HYBRID_SIGN_USEROP;
            G_context.state               = STATE_PARSED;
            userop_ctx.step               = 0xFF;

            return ui_display_hybrid_sign_userop();
        }

        default:
            return io_send_sw(SWO_INCORRECT_P1_P2);
    }
}

// ---------------------------------------------------------------------------
// Accessors for the NBGL display layer
// ---------------------------------------------------------------------------

const uint8_t *userop_get_sender(void)     { return userop_ctx.sender; }
const uint8_t *userop_get_chain_id(void)   { return userop_ctx.chain_id; }
const uint8_t *userop_get_call_to(void)    { return userop_ctx.call_to; }
const uint8_t *userop_get_call_value(void) { return userop_ctx.call_value; }
bool           userop_has_call_info(void)  { return userop_ctx.has_call_info; }
