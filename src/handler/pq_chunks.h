#pragma once

#include <stdint.h>

#include "buffer.h"

/**
 * GET_PK_CHUNK (INS 0x13) — return a slice of the last-generated ML-DSA pk.
 *
 * Wire format:
 *   P1 = chunk index (0..CEIL(pk_len / 255) - 1)
 *   P2 = chunk length in bytes (typically 255; the last one 37 for ML-DSA-44,
 *        167 for ML-DSA-65)
 * Returns pk[P1*255 .. P1*255 + P2 - 1].
 *
 * The bound is the public key size of the parameter set of the loaded key
 * (1312 bytes for ML-DSA-44, 1952 for ML-DSA-65), not the buffer size:
 * out-of-range requests return SWO_WRONG_DATA_LENGTH rather than leaking
 * adjacent globals or the unused tail of the buffer (fixes a ZKNOX bug).
 */
int handler_cmd_get_pk_chunk(buffer_t *cdata, uint8_t p1, uint8_t p2);

/**
 * GET_SIG_CHUNK (INS 0x12) — return a slice of the last-generated ML-DSA sig.
 *
 * Same wire semantics as GET_PK_CHUNK, but over the signature buffer
 * (2420 bytes for ML-DSA-44: 9×255 + 125; 3309 bytes for ML-DSA-65:
 * 12×255 + 249). The bound is the signature size of the parameter set of
 * the loaded key; after a keygen the buffer reads as zeros.
 */
int handler_cmd_get_sig_chunk(buffer_t *cdata, uint8_t p1, uint8_t p2);
