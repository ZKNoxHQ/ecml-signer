#pragma once

#include "buffer.h"
#include "lcx_mldsa.h"

/**
 * HYBRID_SIGN_HASH (INS 0x16) — sign a 32-byte hash with BOTH secp256k1 ECDSA
 * and ML-DSA (44 or 65) for the same BIP32 path.
 *
 * Wire format:
 *   cdata = [path_len:1][path:4*path_len][hash:32]
 *   P1 = 0, P2 = ML-DSA parameter set (0x00 = ML-DSA-44, 0x01 = ML-DSA-65).
 *
 * Response (async, after user approval):
 *   The ECDSA half is returned inline in the async APDU response:
 *     [ecdsa_sig_len:1][ecdsa_DER_sig:sig_len][v:1]
 *   The ML-DSA half is stored in device state (mldsa_pk, mldsa_sig; 1312 /
 *   2420 bytes for ML-DSA-44, 1952 / 3309 for ML-DSA-65); the client fetches
 *   it with GET_PK_CHUNK (0x13) and GET_SIG_CHUNK (0x12).
 *
 * The ML-DSA signature is the pure (non-prehash) FIPS 204 signature of the
 * 32-byte hash with an empty context, i.e. of M' = 0x00 || 0x00 || hash: the
 * exact input of ZKNOX_dilithium / ZKNOX_dilithium65 .verify(pk, bytes32 hash, sig)
 * (ETHDILITHIUM), so the device output verifies on-chain as is.
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
 * SLIP-0010 personalization is "ML-DSA-44 seed" (matches ZKNOX) or
 * "ML-DSA-65 seed", so the ML-DSA-44 key produced here interops with tooling
 * built against ZKNOX for the same BIP32 path. See src/crypto/mldsa_derive.c.
 */
int handler_hybrid_sign_hash(buffer_t *cdata, MLDSA_param_t param);
