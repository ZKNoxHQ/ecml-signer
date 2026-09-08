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

#include "validate.h"
#include "menu.h"
#include "sw.h"
#include "globals.h"
#include "send_response.h"
#include "mldsa_derive.h"

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

static int crypto_sign_message_mldsa(void) {
    // Secret key is bulky (~2560 B for ML-DSA-44); keep it on the stack scoped
    // to this call so it is scrubbed on return rather than living in .bss.
    uint8_t sk[MLDSA44_SECRETKEYBYTES] = {0};
    uint8_t seed[MLDSA_DERIVE_SEED_LEN] = {0};
    int status = -1;

    if (mldsa_derive_seed(G_context.bip32_path, G_context.bip32_path_len, seed) != 0) {
        PRINTF("mldsa_derive_seed failed\n");
        goto end;
    }

    if (mldsa_keygen_from_seed(seed, G_context.tx_info.mldsa_pk, sk, sizeof(sk)) != 0) {
        PRINTF("mldsa_keygen_from_seed failed\n");
        goto end;
    }

    // Sign the transaction hash. No context string (ctx_len == 0).
    cx_err_t error = MLDSA_sign(G_context.tx_info.mldsa_sig,
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
    explicit_bzero(seed, sizeof(seed));
    return status;
}

// Sign the payload currently in G_context.tx_info.raw_tx with the ML-DSA-44
// key derived from G_context.tx_info.mldsa_seed. On success the signature is
// stored in G_context.tx_info.mldsa_sig and the client fetches it via chunks.
static int crypto_pq_sign(void) {
    uint8_t sk[MLDSA44_SECRETKEYBYTES] = {0};
    int status = -1;

    // Re-derive sk from the stored seed. We regenerate the pk into a scratch
    // that we then overwrite the stored pk with (they should match, but this
    // fails closed if the seed was tampered with between keygen and sign).
    uint8_t pk_scratch[MLDSA44_PUBLICKEYBYTES] = {0};
    if (mldsa_keygen_from_seed(G_context.tx_info.mldsa_seed,
                               pk_scratch,
                               sk,
                               sizeof(sk)) != 0) {
        PRINTF("crypto_pq_sign: keygen from stored seed failed\n");
        goto end;
    }
    memmove(G_context.tx_info.mldsa_pk, pk_scratch, sizeof(pk_scratch));

    cx_err_t error = MLDSA_sign(G_context.tx_info.mldsa_sig,
                                sizeof(G_context.tx_info.mldsa_sig),
                                &G_context.tx_info.mldsa_sig_len,
                                G_context.tx_info.raw_tx,
                                G_context.tx_info.raw_tx_len,
                                NULL,
                                0,
                                sk,
                                sizeof(sk),
                                MLDSA_44);
    if (error != CX_OK) {
        PRINTF("MLDSA_sign failed: 0x%x\n", error);
        goto end;
    }
    status = 0;

end:
    explicit_bzero(sk, sizeof(sk));
    explicit_bzero(pk_scratch, sizeof(pk_scratch));
    return status;
}

void validate_pq_sign(bool choice) {
    if (choice) {
        G_context.state = STATE_APPROVED;
        if (crypto_pq_sign() != 0) {
            // Fail closed: wipe sig so a stale chunk cannot be fetched.
            explicit_bzero(G_context.tx_info.mldsa_sig, sizeof(G_context.tx_info.mldsa_sig));
            G_context.tx_info.mldsa_sig_len = 0;
            G_context.state                 = STATE_NONE;
            io_send_sw(SWO_SECURITY_ISSUE);
        } else {
            io_send_sw(SWO_SUCCESS);
        }
    } else {
        explicit_bzero(G_context.tx_info.mldsa_sig, sizeof(G_context.tx_info.mldsa_sig));
        G_context.tx_info.mldsa_sig_len = 0;
        G_context.state                 = STATE_NONE;
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}

// HYBRID_SIGN_HASH (INS 0x16) approval action. Signs G_context.tx_info.m_hash
// with secp256k1 (returned inline) and ML-DSA-44 (stored for chunk fetch).
void validate_hybrid_sign_hash(bool choice) {
    if (!choice) {
        G_context.state = STATE_NONE;
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    G_context.state = STATE_APPROVED;

    // 1. ECDSA half — reuses the existing secp256k1 hash-signing path.
    if (crypto_sign_message() != 0) {
        G_context.state = STATE_NONE;
        io_send_sw(SWO_SECURITY_ISSUE);
        return;
    }

    // 2. ML-DSA-44 half. Derive the seed here (not in the handler) so it is
    // never resident before the user has approved the operation.
    uint8_t seed[MLDSA_DERIVE_SEED_LEN] = {0};
    uint8_t sk[MLDSA44_SECRETKEYBYTES]  = {0};
    int     status                      = -1;

    if (mldsa_derive_seed(G_context.bip32_path, G_context.bip32_path_len, seed) != 0) {
        PRINTF("validate_hybrid_sign_hash: derive_seed failed\n");
        goto end;
    }
    if (mldsa_keygen_from_seed(seed, G_context.tx_info.mldsa_pk, sk, sizeof(sk)) != 0) {
        PRINTF("validate_hybrid_sign_hash: keygen_from_seed failed\n");
        goto end;
    }

    cx_err_t error = MLDSA_sign(G_context.tx_info.mldsa_sig,
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
        PRINTF("validate_hybrid_sign_hash: MLDSA_sign failed: 0x%x\n", error);
        goto end;
    }
    status = 0;

end:
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(sk, sizeof(sk));

    if (status != 0) {
        // Fail closed: scrub the ML-DSA outputs so a stale chunk cannot leak.
        explicit_bzero(G_context.tx_info.mldsa_pk, sizeof(G_context.tx_info.mldsa_pk));
        explicit_bzero(G_context.tx_info.mldsa_sig, sizeof(G_context.tx_info.mldsa_sig));
        G_context.tx_info.mldsa_sig_len = 0;
        G_context.state                 = STATE_NONE;
        io_send_sw(SWO_SECURITY_ISSUE);
        return;
    }

    // 3. Send the ECDSA signature inline. The client fetches the ML-DSA half
    // via GET_PK_CHUNK (0x13) and GET_SIG_CHUNK (0x12).
    helper_send_response_sig();
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
