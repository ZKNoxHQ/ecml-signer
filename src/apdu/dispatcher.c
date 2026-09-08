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

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "dispatcher.h"
#include "constants.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "get_version.h"
#include "get_app_name.h"
#include "get_public_key.h"
#include "sign_tx.h"
#include "provide_token_info.h"
#include "pq_primitives.h"
#include "pq_keygen.h"
#include "pq_chunks.h"
#include "pq_sign.h"
#include "ecdsa_sign_hash.h"
#include "hybrid_sign_hash.h"
#include "hybrid_sign_userop.h"

int apdu_dispatcher(const command_t *cmd) {
    LEDGER_ASSERT(cmd != NULL, "NULL cmd");

    if (cmd->cla != CLA) {
        return io_send_sw(SWO_INVALID_CLA);
    }

    buffer_t buf = {0};

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            return handler_get_version();

        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            return handler_get_app_name();

        case GET_PUBLIC_KEY:
            if (cmd->p1 > 1 || cmd->p2 > 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_get_public_key(&buf, (bool) cmd->p1);

        case SIGN_TX:
        case SIGN_TOKEN_TX:
        case SIGN_TX_MLDSA:
            // Common handler for SIGN_TX / SIGN_TOKEN_TX / SIGN_TX_MLDSA: chunked upload of
            // BIP32 path + raw transaction. Only the signing algorithm differs at approval time.
            PRINTF("APDU_DISPATCHER: %d\n", cmd->ins);
            if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||  //
                cmd->p1 > P1_MAX ||                             //
                (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE)) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_sign_tx(&buf,
                                   cmd->p1,
                                   (bool) (cmd->p2 & P2_MORE),
                                   cmd->ins == SIGN_TOKEN_TX,
                                   cmd->ins == SIGN_TX_MLDSA);

        case PROVIDE_TOKEN_INFO:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_provide_token_info(&buf);

        case DUMMY:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_dummy(&buf);

        case SAMPLE_IN_BALL:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_sample_in_ball(&buf);

        case KEYGEN_DILITHIUM_CORE:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_keygen_core_dilithium(&buf);

        case KEYGEN_DILITHIUM:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_keygen_dilithium(&buf);

        case GET_PK_CHUNK:
            // No inbound data; P1/P2 carry the chunk index and length. Bounds
            // check is enforced inside the handler.
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_get_pk_chunk(&buf, cmd->p1, cmd->p2);

        case GET_SIG_CHUNK:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_get_sig_chunk(&buf, cmd->p1, cmd->p2);

        case SIGN_DILITHIUM:
            // P1 encodes the state machine step (0=init, 1=absorb, 128=finalize).
            // The handler validates P1; dispatcher just passes it through.
            if (cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_cmd_sign_dilithium(&buf, cmd->p1);

        case ECDSA_SIGN_HASH:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_ecdsa_sign_hash(&buf);

        case HYBRID_SIGN_HASH:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_hybrid_sign_hash(&buf);

        case HYBRID_SIGN_USEROP:
            // P1 encodes the 4-step state machine (0=path, 1=metadata,
            // 2=packed, 3=calldata+finalize). Handler enforces the sequence.
            if (cmd->p1 > 0x03 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            // callData step accepts lc=0 to skip callData verification.
            if (cmd->p1 != 0x03 && !cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }

            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;

            return handler_hybrid_sign_userop(&buf, cmd->p1);

        default:
            return io_send_sw(SWO_INVALID_INS);
    }
}
