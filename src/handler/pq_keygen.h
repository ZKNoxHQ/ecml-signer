#pragma once

#include "buffer.h"
#include "lcx_mldsa.h"

/**
 * KEYGEN_DILITHIUM_CORE (INS 0x0c) — deterministic ML-DSA keygen from a
 * caller-supplied 32-byte seed. Wire format: cdata = 32-byte seed,
 * P1 = 0, P2 = parameter set (0x00 = ML-DSA-44, 0x01 = ML-DSA-65).
 *
 * Stores the seed into G_context.tx_info.mldsa_seed, the parameter set into
 * G_context.tx_info.mldsa_param and the public key into
 * G_context.tx_info.mldsa_pk. The signature buffer is zeroed. Client must
 * fetch the pk via GET_PK_CHUNK (INS 0x13), whose bounds follow the
 * parameter set (1312 or 1952 bytes).
 *
 * The keygen is FIPS 204 Alg. 6 with ξ = seed: for a given seed the public
 * key equals the one of any FIPS 204 implementation (NIST ACVP keyGen
 * vectors, @noble/post-quantum keygen(seed), ...), see
 * tests/standalone/test_pq_keygen.py.
 *
 * Wire divergence from ZKNOX: ZKNOX took no cdata and relied on
 * g_zknox.mldsa_seed being pre-populated by GET_MLDSA_SEED (INS 0x14). Since
 * GET_MLDSA_SEED will be DEBUG-only in this port, KEYGEN_CORE takes the seed
 * directly. In practice, callers should prefer KEYGEN_DILITHIUM (INS 0x11)
 * which derives the seed from a BIP32 path on-device.
 */
int handler_cmd_keygen_core_dilithium(buffer_t *cdata, MLDSA_param_t param);

/**
 * KEYGEN_DILITHIUM (INS 0x11) — derive the ML-DSA keypair from a BIP32
 * path over the SLIP-0010 tree with the "ML-DSA-44 seed" / "ML-DSA-65 seed"
 * personalization of the parameter set.
 *
 * Wire format: cdata = [path_len:1][path:4*path_len] (all-hardened components),
 * P1 = 0, P2 = parameter set (0x00 = ML-DSA-44, 0x01 = ML-DSA-65).
 * Stores derived seed, parameter set and pk into G_context.tx_info;
 * signature buffer zeroed.
 *
 * Wire divergence from ZKNOX: ZKNOX called crypto_sign_keypair with a random
 * seed and discarded the result. Under "fix bugs silently" this INS now does
 * the useful thing (deterministic keygen from BIP32).
 */
int handler_cmd_keygen_dilithium(buffer_t *cdata, MLDSA_param_t param);
