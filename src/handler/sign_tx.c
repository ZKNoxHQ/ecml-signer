/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "sign_tx.h"
#include "sw.h"
#include "globals.h"
#include "display.h"
#include "tx_types.h"
#include "deserialize.h"
#include "validate.h"
#include "token_db.h"
#include "dynamic_token_info.h"

/**
 * Initialize transaction context for chunk 0
 *
 * @param[in] cdata Buffer containing BIP32 path
 * @param[in] req_type Request type (CONFIRM_TRANSACTION or CONFIRM_TOKEN_TRANSACTION)
 * @return SWO_SUCCESS on success, error code otherwise
 */
static int init_transaction_context(buffer_t *cdata,
                                    uint8_t req_type,
                                    bool is_mldsa,
                                    MLDSA_param_t param) {
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = req_type;
    G_context.state = STATE_NONE;
    G_context.tx_info.is_mldsa = is_mldsa;
    G_context.tx_info.mldsa_param = param;

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    return io_send_sw(SWO_SUCCESS);
}

/**
 * Accumulate transaction data from APDU chunks
 * TODO: This should NOT be handled in each handler but at the dispatcher level
 *
 * @param[in] cdata Buffer containing transaction chunk
 * @param[in] req_type Expected request type for validation
 * @return SWO_SUCCESS on success, error code otherwise
 */
static uint16_t accumulate_transaction_data(buffer_t *cdata, uint8_t req_type) {
    if (G_context.req_type != req_type) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }
    if (G_context.tx_info.raw_tx_len + cdata->size > sizeof(G_context.tx_info.raw_tx)) {
        return SWO_WRONG_DATA_LENGTH;
    }
    if (!buffer_move(cdata, G_context.tx_info.raw_tx + G_context.tx_info.raw_tx_len, cdata->size)) {
        return SWO_INCORRECT_DATA;
    }
    G_context.tx_info.raw_tx_len += cdata->size;
    return SWO_SUCCESS;
}

static uint16_t process_transaction(bool is_token_tx) {
    // last APDU for this transaction, let's parse, display and request a sign confirmation
    buffer_t buf = {.ptr = G_context.tx_info.raw_tx,
                    .size = G_context.tx_info.raw_tx_len,
                    .offset = 0};

    G_context.tx_info.is_token_tx = is_token_tx;
    parser_status_e status =
        transaction_deserialize(&buf, &G_context.tx_info.transaction, is_token_tx);
    PRINTF("Parsing status: %d.\n", status);
    if (status != PARSING_OK) {
        return SWO_INCORRECT_DATA;
    }

    if (is_token_tx) {
        // Look up token information from database
        if (!get_token_info(G_context.tx_info.transaction.token_address,
                            &G_context.tx_info.token_info)) {
            PRINTF("Token not found in database\n");
            return SWO_INCORRECT_DATA;
        }

        PRINTF("Token found: %s (decimals: %d)\n",
               G_context.tx_info.token_info.ticker,
               G_context.tx_info.token_info.decimals);
    }

    G_context.state = STATE_PARSED;

    if (cx_keccak_256_hash(G_context.tx_info.raw_tx,
                           G_context.tx_info.raw_tx_len,
                           G_context.tx_info.m_hash) != CX_OK) {
        return SWO_INCORRECT_DATA;
    }
    PRINTF("Hash: %.*H\n", sizeof(G_context.tx_info.m_hash), G_context.tx_info.m_hash);
    return SWO_SUCCESS;
}

int handler_sign_tx(buffer_t *cdata,
                    uint8_t chunk,
                    bool more,
                    bool is_token_tx,
                    bool is_mldsa,
                    MLDSA_param_t param) {
    uint8_t req_type = is_token_tx ? CONFIRM_TOKEN_TRANSACTION : CONFIRM_TRANSACTION;
    if (chunk == 0) {
        // first APDU, parse BIP32 path and return
        return init_transaction_context(cdata, req_type, is_mldsa, param);
    } else {
        // the parameter set is fixed by the first chunk: a later chunk carrying
        // another value is a client bug, fail closed
        if (is_mldsa && param != G_context.tx_info.mldsa_param) {
            return io_send_sw(SWO_INCORRECT_P1_P2);
        }
        // parse transaction
        uint16_t err = accumulate_transaction_data(cdata, req_type);
        if (err != SWO_SUCCESS) {
            return io_send_sw(err);
        }
        if (more) {
            // more APDUs with transaction part are expected.
            // Send a SWO_SUCCESS to signal that we have received the chunk
            return io_send_sw(SWO_SUCCESS);

        } else {
            // last APDU for this transaction, let's parse, display and request a sign confirmation
            err = process_transaction(is_token_tx);
            if (err != SWO_SUCCESS) {
                return io_send_sw(err);
            }

            // Example to trig a blind-sign flow.
            // NOTE: the trigger is the memo, which is attacker-controlled, so a
            // crafted transaction can ask for the blind review instead of the
            // clear one. Gated on the user's opt-in; this demo branch should be
            // deleted outright once nothing depends on it.
            if (strcmp((char *) G_context.tx_info.transaction.memo, "Blind-sign") == 0) {
                if (!BLIND_SIGNING_ALLOWED()) {
                    G_context.state = STATE_NONE;
                    return io_send_sw(SW_BLIND_SIGNING_DISABLED);
                }
                return ui_display_blind_signed_transaction();
            } else if (is_token_tx) {
                return ui_display_token_transaction();
            } else {
                return ui_display_transaction();
            }
        }
    }
    return 0;
}
