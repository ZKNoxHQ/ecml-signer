#pragma once

#include "buffer.h"

/**
 * KEYGEN_DILITHIUM_CORE (INS 0x0c) — deterministic ML-DSA-44 keygen from a
 * caller-supplied 32-byte seed. Wire format: cdata = 32-byte seed.
 *
 * Stores the derived seed into G_context.tx_info.mldsa_seed and the public
 * key into G_context.tx_info.mldsa_pk. The signature buffer is zeroed.
 * Client must fetch the pk via GET_PK_CHUNK (INS 0x13).
 *
 * Wire divergence from ZKNOX: ZKNOX took no cdata and relied on
 * g_zknox.mldsa_seed being pre-populated by GET_MLDSA_SEED (INS 0x14). Since
 * GET_MLDSA_SEED will be DEBUG-only in this port, KEYGEN_CORE takes the seed
 * directly. In practice, callers should prefer KEYGEN_DILITHIUM (INS 0x11)
 * which derives the seed from a BIP32 path on-device.
 */
int handler_cmd_keygen_core_dilithium(buffer_t *cdata);

/**
 * KEYGEN_DILITHIUM (INS 0x11) — derive the ML-DSA-44 keypair from a BIP32
 * path over the SLIP-0010 tree with "mldsa-44" personalization.
 *
 * Wire format: cdata = [path_len:1][path:4*path_len] (all-hardened components).
 * Stores derived seed and pk into G_context.tx_info; signature buffer zeroed.
 *
 * Wire divergence from ZKNOX: ZKNOX called crypto_sign_keypair with a random
 * seed and discarded the result. Under "fix bugs silently" this INS now does
 * the useful thing (deterministic keygen from BIP32).
 */
int handler_cmd_keygen_dilithium(buffer_t *cdata);
