#pragma once

#include "buffer.h"

/**
 * HYBRID_SIGN_HASH (INS 0x16) — sign a 32-byte hash with BOTH secp256k1 ECDSA
 * and ML-DSA-44 for the same BIP32 path.
 *
 * Wire format:
 *   cdata = [path_len:1][path:4*path_len][hash:32]
 *   P1 = P2 = 0.
 *
 * Response (async, after user approval):
 *   The ECDSA half is returned inline in the async APDU response:
 *     [ecdsa_sig_len:1][ecdsa_DER_sig:sig_len][v:1]
 *   The ML-DSA-44 half is stored in device state (mldsa_pk[1312], mldsa_sig[2420]);
 *   the client fetches it with GET_PK_CHUNK (0x13) and GET_SIG_CHUNK (0x12).
 *
 * Deviations from ZKNOX-HW-MLDSA (documented under the "fix bugs silently"
 * posture agreed for the port):
 *  - SEED DERIVATION MOVED POST-APPROVAL. ZKNOX derived the ML-DSA seed in the
 *    handler (pre-approval), leaving a window in which the seed was resident
 *    in RAM but exfiltratable via 0x12/0x13. We derive it only inside
 *    `validate_hybrid_sign_hash(true)`.
 *  - MLDSA PK POPULATED. ZKNOX's hybrid handler discarded the derived pk;
 *    we store it so a client can fetch it via GET_PK_CHUNK without a
 *    separate KEYGEN round trip.
 *
 * SLIP-0010 personalization is "ML-DSA-44 seed" (matches ZKNOX), so the
 * ML-DSA key produced here interops with tooling built against ZKNOX for the
 * same BIP32 path. See src/crypto/mldsa_derive.c.
 */
int handler_hybrid_sign_hash(buffer_t *cdata);
