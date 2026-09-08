#pragma once

#include <stdint.h>

#include "buffer.h"

/**
 * GET_PK_CHUNK (INS 0x13) — return a slice of the last-generated ML-DSA-44 pk.
 *
 * Wire format:
 *   P1 = chunk index (0..CEIL(pk_len / 255) - 1)
 *   P2 = chunk length in bytes (typically 255, last one 37 for ML-DSA-44)
 * Returns pk[P1*255 .. P1*255 + P2 - 1].
 *
 * Fixes ZKNOX bug: strict bounds check on `P1*255 + P2 <= MLDSA44_PUBLICKEYBYTES`;
 * out-of-range requests return SWO_WRONG_DATA_LENGTH rather than leaking adjacent
 * globals (mldsa_seed, mldsa_sig, ...).
 */
int handler_cmd_get_pk_chunk(buffer_t *cdata, uint8_t p1, uint8_t p2);

/**
 * GET_SIG_CHUNK (INS 0x12) — return a slice of the last-generated ML-DSA-44 sig.
 *
 * Same wire semantics as GET_PK_CHUNK, but over the signature buffer
 * (2420 bytes for ML-DSA-44: 9×255 + 125).
 *
 * Same bounds-check hardening as GET_PK_CHUNK.
 */
int handler_cmd_get_sig_chunk(buffer_t *cdata, uint8_t p1, uint8_t p2);
