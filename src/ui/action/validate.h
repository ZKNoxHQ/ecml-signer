#pragma once

#include <stdbool.h>  // bool

/**
 * Action for public key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejected).
 *
 */
void validate_pubkey(bool choice);

/**
 * Action for transaction information validation.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void validate_transaction(bool choice);

/**
 * Action for the SIGN_DILITHIUM (INS 0x0f) approval callback.
 *
 * On @p choice == true, signs the accumulated payload (G_context.tx_info.raw_tx)
 * with the currently-loaded ML-DSA key and stores the signature in
 * G_context.tx_info.mldsa_sig. The client fetches the sig via GET_SIG_CHUNK.
 *
 * On rejection, wipes the sig buffer and sends SWO_CONDITIONS_NOT_SATISFIED.
 */
void validate_pq_sign(bool choice);

/**
 * Action for the HYBRID_SIGN_HASH (INS 0x16) approval callback.
 *
 * On approval:
 *  - Signs G_context.tx_info.m_hash with secp256k1 (result in tx_info.signature)
 *  - Derives the ML-DSA-44 seed from the current BIP32 path
 *  - Generates the ML-DSA-44 keypair; stores pk in tx_info.mldsa_pk
 *  - Signs the same hash with ML-DSA-44; stores sig in tx_info.mldsa_sig
 *  - Sends the ECDSA sig inline; client fetches ML-DSA pk/sig via chunk INS.
 *
 * On rejection, wipes state and sends SWO_CONDITIONS_NOT_SATISFIED.
 */
void validate_hybrid_sign_hash(bool choice);
