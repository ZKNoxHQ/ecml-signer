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

#include <stdbool.h>  // bool
#include <string.h>   // explicit_bzero

#include "os.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "lcx_mldsa.h"
#include "cx_mldsa_internal.h"

#include "validate.h"
#include "menu.h"
#include "sw.h"
#include "globals.h"
#include "send_response.h"

void validate_pubkey(bool choice) {
    if (choice) {
        helper_send_response_pubkey();
    } else {
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}

static int crypto_sign_message(void) {
    uint32_t info = 0;
    size_t sig_len = sizeof(G_context.tx_info.signature);

    cx_err_t error = bip32_derive_ecdsa_sign_hash_256(CX_CURVE_256K1,
                                                      G_context.bip32_path,
                                                      G_context.bip32_path_len,
                                                      CX_RND_RFC6979 | CX_LAST,
                                                      CX_SHA256,
                                                      G_context.tx_info.m_hash,
                                                      sizeof(G_context.tx_info.m_hash),
                                                      G_context.tx_info.signature,
                                                      &sig_len,
                                                      &info);
    if (error != CX_OK) {
        return -1;
    }

    PRINTF("Signature: %.*H\n", sig_len, G_context.tx_info.signature);

    G_context.tx_info.signature_len = sig_len;
    G_context.tx_info.v = (uint8_t) (info & CX_ECCINFO_PARITY_ODD);

    return 0;
}

// SLIP-0010 HMAC-SHA512 key used to derive the ML-DSA-44 master seed from the
// device root seed. Kept distinct from "Bitcoin seed" / "ed25519 seed" so the
// ML-DSA key tree is independent of any ECDSA/Ed25519 tree at the same path.
static const char MLDSA_SLIP10_KEY[] = "mldsa-44";

// The ML-DSA seed is 32 bytes; SDK requires a 64-byte raw_privkey output buffer.
static int crypto_sign_message_mldsa(void) {
    uint8_t raw_privkey[64] = {0};
    // Secret key is bulky (2560 B for ML-DSA-44); keep it on the stack scoped to
    // this call so it is scrubbed on return rather than living in .bss.
    uint8_t sk[MLDSA44_SECRETKEYBYTES] = {0};
    cx_err_t error;
    int status = -1;

    // SLIP-0010 derivation using "mldsa-44" as the HMAC-SHA512 key.
    error = os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10,
                                               CX_CURVE_Ed25519,
                                               G_context.bip32_path,
                                               G_context.bip32_path_len,
                                               raw_privkey,
                                               NULL,
                                               (unsigned char *) MLDSA_SLIP10_KEY,
                                               sizeof(MLDSA_SLIP10_KEY) - 1);
    if (error != CX_OK) {
        PRINTF("SLIP-10 derivation failed: 0x%x\n", error);
        goto end;
    }

    // Deterministic ML-DSA keypair from the 32-byte derived seed.
    error = MLDSA_internal_keygen(G_context.tx_info.mldsa_pk,
                                  sizeof(G_context.tx_info.mldsa_pk),
                                  sk,
                                  sizeof(sk),
                                  raw_privkey,
                                  MLDSA_44);
    if (error != CX_OK) {
        PRINTF("MLDSA_internal_keygen failed: 0x%x\n", error);
        goto end;
    }

    // Sign the transaction hash. No context string (ctx_len == 0).
    error = MLDSA_sign(G_context.tx_info.mldsa_sig,
                       sizeof(G_context.tx_info.mldsa_sig),
                       &G_context.tx_info.mldsa_sig_len,
                       G_context.tx_info.m_hash,
                       sizeof(G_context.tx_info.m_hash),
                       NULL,
                       0,
                       sk,
                       sizeof(sk),
                       MLDSA_44);
    if (error != CX_OK) {
        PRINTF("MLDSA_sign failed: 0x%x\n", error);
        goto end;
    }

    PRINTF("MLDSA sig len: %d\n", G_context.tx_info.mldsa_sig_len);
    status = 0;

end:
    explicit_bzero(sk, sizeof(sk));
    explicit_bzero(raw_privkey, sizeof(raw_privkey));
    return status;
}

void validate_transaction(bool choice) {
    if (choice) {
        G_context.state = STATE_APPROVED;

        if (G_context.tx_info.is_mldsa) {
            if (crypto_sign_message_mldsa() != 0) {
                G_context.state = STATE_NONE;
                io_send_sw(SWO_SECURITY_ISSUE);
            } else {
                helper_send_response_mldsa_sig();
            }
        } else {
            if (crypto_sign_message() != 0) {
                G_context.state = STATE_NONE;
                io_send_sw(SWO_SECURITY_ISSUE);
            } else {
                helper_send_response_sig();
            }
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}
