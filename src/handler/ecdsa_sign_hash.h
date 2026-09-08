#pragma once

#include "buffer.h"

/**
 * ECDSA_SIGN_HASH (INS 0x15) — sign a caller-supplied 32-byte hash with the
 * secp256k1 key derived from a BIP32 path.
 *
 * This is a "blind-sign hash" primitive: the device has no way to interpret
 * the hash's meaning, so the review UI shows the hash bytes under an
 * ISO-compliant blind-signing warning.
 *
 * Wire format:
 *   cdata = [path_len:1][path:4*path_len][hash:32]
 * Response (async, after user approval):
 *   [sig_len:1][DER_sig:sig_len][v:1]  (identical to SIGN_TX response layout)
 *
 * P1 = P2 = 0.
 */
int handler_ecdsa_sign_hash(buffer_t *cdata);
