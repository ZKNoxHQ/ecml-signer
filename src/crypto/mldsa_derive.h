#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "lcx_mldsa.h"

/**
 * ML-DSA seed length used by SLIP-0010 and FIPS 204 §6.1 keygen input (ξ).
 * Same for every parameter set.
 */
#define MLDSA_DERIVE_SEED_LEN 32

/**
 * Largest sizes over the parameter sets the app supports (ML-DSA-44 and
 * ML-DSA-65): the context buffers and the stack scratch buffers are sized
 * with these, the wire protocol uses the actual sizes of the selected set
 * (mldsa_pk_bytes / mldsa_sig_bytes / mldsa_sk_bytes).
 */
#define MLDSA_APP_MAX_PUBLICKEYBYTES MLDSA65_PUBLICKEYBYTES /* 1952 */
#define MLDSA_APP_MAX_SECRETKEYBYTES MLDSA65_SECRETKEYBYTES /* 4032 */
#define MLDSA_APP_MAX_SIGBYTES       MLDSA65_SIGBYTES       /* 3309 */

/**
 * Wire encoding of the parameter set, carried in P2 of the ML-DSA INS
 * (KEYGEN_DILITHIUM_CORE, KEYGEN_DILITHIUM, HYBRID_SIGN_HASH, every APDU of
 * HYBRID_SIGN_USEROP, SAMPLE_IN_BALL) and in the low bits of P2 of
 * SIGN_TX_MLDSA. 0x00 is ML-DSA-44, the value every pre-existing client
 * sends, so the protocol is backward compatible.
 */
#define MLDSA_P2_PARAM_44   0x00
#define MLDSA_P2_PARAM_65   0x01
#define MLDSA_P2_PARAM_MASK 0x7F

/**
 * Map the P2 parameter-set selector to the SDK's MLDSA_param_t.
 *
 * @param[in]  p2_param  P2 value (or P2 & MLDSA_P2_PARAM_MASK for SIGN_TX_MLDSA).
 * @param[out] param     MLDSA_44 or MLDSA_65.
 * @return true if the selector is valid.
 */
bool mldsa_param_from_p2(uint8_t p2_param, MLDSA_param_t *param);

/** Sizes and constants of a parameter set (from the SDK's MLDSA_PARAM table). */
size_t  mldsa_pk_bytes(MLDSA_param_t param);
size_t  mldsa_sk_bytes(MLDSA_param_t param);
size_t  mldsa_sig_bytes(MLDSA_param_t param);
uint8_t mldsa_tau(MLDSA_param_t param);

/** "ML-DSA-44" / "ML-DSA-65", for the review screens. */
const char *mldsa_param_name(MLDSA_param_t param);

/**
 * Derive the 32-byte ML-DSA seed (SLIP-0010 output) for a BIP32 path and a
 * parameter set.
 *
 * Uses HMAC-SHA512 with the personalization "ML-DSA-44 seed" or
 * "ML-DSA-65 seed" so the ML-DSA key tree is domain-separated from any
 * ECDSA/Ed25519 tree under the same path AND between the two parameter
 * sets (the ML-DSA-44 and ML-DSA-65 keys of one path are independent).
 * Path components must be hardened (SLIP-0010 ed25519-mode requirement);
 * the hardened bit is forced on every component here.
 *
 * @param[in]  path      BIP32 path (u32 components).
 * @param[in]  path_len  Number of components in @p path.
 * @param[in]  param     Parameter set (selects the personalization).
 * @param[out] seed_out  32-byte derived seed.
 *
 * @return 0 on success, negative on SDK error.
 */
int mldsa_derive_seed(const uint32_t *path,
                      size_t          path_len,
                      MLDSA_param_t   param,
                      uint8_t         seed_out[MLDSA_DERIVE_SEED_LEN]);

/**
 * Deterministic ML-DSA keygen from a 32-byte seed (FIPS 204 Alg. 6 with ξ = seed).
 *
 * Thin wrapper over MLDSA_internal_keygen so callers don't reach for the
 * internal header directly. @p pk / @p sk buffers must hold at least
 * mldsa_pk_bytes(param) / mldsa_sk_bytes(param) bytes.
 *
 * @return 0 on success, negative on SDK error or short buffers.
 */
int mldsa_keygen_from_seed(const uint8_t seed[MLDSA_DERIVE_SEED_LEN],
                           MLDSA_param_t param,
                           uint8_t      *pk,
                           size_t        pk_len,
                           uint8_t      *sk,
                           size_t        sk_len);
