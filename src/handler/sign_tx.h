#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "buffer.h"
#include "lcx_mldsa.h"

/**
 * Handler for SIGN_TX command. If successfully parse BIP32 path
 * and transaction, sign transaction and send APDU response.
 *
 * @see G_context.bip32_path, G_context.tx_info.raw_transaction,
 * G_context.tx_info.signature and G_context.tx_info.v.
 *
 * @param[in,out] cdata
 *   Command data with BIP32 path and raw transaction serialized.
 * @param[in]     chunk
 *   Index number of the APDU chunk.
 * @param[in]       more
 *   Whether more APDU chunk to be received or not.
 * @param[in]   is_token_tx
 *  Whether the transaction to sign is a token transaction or not.
 * @param[in]   is_mldsa
 *  Whether the transaction must be signed with ML-DSA instead of ECDSA.
 * @param[in]   param
 *  ML-DSA parameter set (SIGN_TX_MLDSA: low bits of P2, 0x00 = ML-DSA-44,
 *  0x01 = ML-DSA-65), fixed by the first chunk; ignored when !is_mldsa.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_sign_tx(buffer_t *cdata,
                    uint8_t chunk,
                    bool more,
                    bool is_token_tx,
                    bool is_mldsa,
                    MLDSA_param_t param);
