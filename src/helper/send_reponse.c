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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <string.h>  // memmove

#include "buffer.h"

#include "send_response.h"
#include "constants.h"
#include "globals.h"
#include "mldsa_derive.h"
#include "sw.h"

int helper_send_response_pubkey() {
    uint8_t resp[1 + PUBKEY_LEN + 1 + CHAINCODE_LEN] = {0};
    size_t offset = 0;

    resp[offset++] = PUBKEY_LEN;
    memmove(resp + offset, G_context.pk_info.raw_public_key, PUBKEY_LEN);
    offset += PUBKEY_LEN;
    resp[offset++] = CHAINCODE_LEN;
    memmove(resp + offset, G_context.pk_info.chain_code, CHAINCODE_LEN);
    offset += CHAINCODE_LEN;

    return io_send_response_pointer(resp, offset, SWO_SUCCESS);
}

int helper_send_response_sig() {
    uint8_t resp[1 + MAX_DER_SIG_LEN + 1] = {0};
    size_t offset = 0;

    resp[offset++] = G_context.tx_info.signature_len;
    memmove(resp + offset, G_context.tx_info.signature, G_context.tx_info.signature_len);
    offset += G_context.tx_info.signature_len;
    resp[offset++] = (uint8_t) G_context.tx_info.v;

    return io_send_response_pointer(resp, offset, SWO_SUCCESS);
}

int helper_send_response_mldsa_sig() {
    // Response layout: pk_len(2 BE) || pk || sig_len(2 BE) || sig. The lengths
    // are those of the parameter set of the flow; the four parts are sent as
    // a buffer list straight from the context (no stack copy).
    size_t pk_len = mldsa_pk_bytes(G_context.tx_info.mldsa_param);
    size_t sig_len = G_context.tx_info.mldsa_sig_len;
    uint8_t pk_len_be[2] = {(uint8_t) (pk_len >> 8), (uint8_t) (pk_len & 0xFF)};
    uint8_t sig_len_be[2] = {(uint8_t) (sig_len >> 8), (uint8_t) (sig_len & 0xFF)};

    if (sig_len > sizeof(G_context.tx_info.mldsa_sig)) {
        return io_send_sw(SWO_SECURITY_ISSUE);
    }

    // The whole pk + sig must fit in one APDU response (5265 B for ML-DSA-65).
    // On Nano X the I/O buffer is deliberately kept at 4096 B to leave stack
    // headroom (see the Makefile), so this response is ML-DSA-44 only there;
    // the ML-DSA-65 key and signature are still reachable through
    // GET_PK_CHUNK / GET_SIG_CHUNK. Report it as a clear status rather than
    // letting the I/O layer truncate.
    if (2 + pk_len + 2 + sig_len > sizeof(G_io_tx_buffer) - 2) {
        PRINTF("helper_send_response_mldsa_sig: response does not fit in the I/O buffer\n");
        return io_send_sw(SWO_INSUFFICIENT_MEMORY);
    }

    const buffer_t parts[4] = {
        {.ptr = pk_len_be, .size = sizeof(pk_len_be), .offset = 0},
        {.ptr = G_context.tx_info.mldsa_pk, .size = pk_len, .offset = 0},
        {.ptr = sig_len_be, .size = sizeof(sig_len_be), .offset = 0},
        {.ptr = G_context.tx_info.mldsa_sig, .size = sig_len, .offset = 0},
    };

    return io_send_response_buffers(parts, 4, SWO_SUCCESS);
}
