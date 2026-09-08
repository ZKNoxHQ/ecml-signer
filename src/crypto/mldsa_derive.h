#pragma once

#include <stdint.h>
#include <stddef.h>

#include "lcx_mldsa.h"

/**
 * ML-DSA-44 seed length used by SLIP-0010 and FIPS 204 §6.1 keygen input (ξ).
 */
#define MLDSA_DERIVE_SEED_LEN 32

/**
 * Derive the 32-byte ML-DSA-44 seed (SLIP-0010 output) for a BIP32 path.
 *
 * Uses HMAC-SHA512 with the personalization "mldsa-44" so the ML-DSA key tree
 * is domain-separated from any ECDSA/Ed25519 tree under the same path. Path
 * components must be hardened (SLIP-0010 ed25519-mode requirement); the SDK
 * enforces this internally.
 *
 * @param[in]  path      BIP32 path (u32 components; hardened bit set for each).
 * @param[in]  path_len  Number of components in @p path.
 * @param[out] seed_out  32-byte derived seed.
 *
 * @return 0 on success, negative on SDK error.
 */
int mldsa_derive_seed(const uint32_t *path, size_t path_len, uint8_t seed_out[MLDSA_DERIVE_SEED_LEN]);

/**
 * Deterministic ML-DSA-44 keygen from a 32-byte seed.
 *
 * Thin wrapper over MLDSA_internal_keygen so callers don't reach for the
 * internal header directly. @p sk buffer must be at least MLDSA44_SECRETKEYBYTES.
 *
 * @return 0 on success, negative on SDK error.
 */
int mldsa_keygen_from_seed(const uint8_t seed[MLDSA_DERIVE_SEED_LEN],
                           uint8_t       pk[MLDSA44_PUBLICKEYBYTES],
                           uint8_t      *sk,
                           size_t        sk_len);
