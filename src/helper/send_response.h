#pragma once

#include "os.h"
#include "macros.h"

/**
 * Length of public key.
 */
#define PUBKEY_LEN (MEMBER_SIZE(pubkey_ctx_t, raw_public_key))
/**
 * Length of chain code.
 */
#define CHAINCODE_LEN (MEMBER_SIZE(pubkey_ctx_t, chain_code))

/**
 * Helper to send APDU response with public key and chain code.
 *
 * response = PUBKEY_LEN (1) ||
 *            G_context.pk_info.public_key (PUBKEY_LEN) ||
 *            CHAINCODE_LEN (1) ||
 *            G_context.pk_info.chain_code (CHAINCODE_LEN)
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_pubkey(void);

/**
 * Helper to send APDU response with signature and v (parity of
 * y-coordinate of R).
 *
 * response = G_context.tx_info.signature_len (1) ||
 *            G_context.tx_info.signature (G_context.tx_info.signature_len) ||
 *            G_context.tx_info.v (1)
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_sig(void);

/**
 * Helper to send APDU response with an ML-DSA public key + signature.
 *
 * response = PK_LEN (2, big-endian) || pk (1312 or 1952 bytes) ||
 *            SIG_LEN (2, big-endian) || sig (mldsa_sig_len: 2420 or 3309)
 *
 * The public key is included so the host can verify the signature without
 * a separate GET_PUBLIC_KEY exchange. 2-byte lengths are required because
 * the ML-DSA sizes (>255 B) do not fit in the 1-byte prefix used by the
 * ECDSA response. The four parts are handed to the I/O layer as a buffer
 * list (no stack copy of the up-to-5265-byte response); the I/O buffer must
 * hold it (CUSTOM_IO_APDU_BUFFER_SIZE in the Makefile).
 *
 * @return zero or positive integer if success, -1 otherwise.
 */
int helper_send_response_mldsa_sig(void);
