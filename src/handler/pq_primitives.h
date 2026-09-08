#pragma once

#include "buffer.h"

/**
 * DUMMY (INS 0x0a) — echo cdata unchanged. I/O smoke test with no state or UI.
 *
 * P1/P2 accept any value.
 */
int handler_cmd_dummy(buffer_t *cdata);

/**
 * SAMPLE_IN_BALL (INS 0x0b) — expose ML-DSA's SampleInBall primitive.
 *
 * Runs FIPS 204 Algorithm 29 (SampleInBall) with `tau = MLDSA44_TAU = 39`
 * on the host-provided c_tilde seed, and returns the challenge polynomial c.
 *
 * Input:  c_tilde bytes (any length; MLDSA44_CTILDEBYTES=32 in normal use).
 * Output: 1024 bytes — raw `int32_t coeffs[256]` little-endian.
 *
 * Wire note: ZKNOX-HW-MLDSA returned only 256 bytes from a 1024-byte poly
 * struct (truncation bug). Since the ZKNOX response was not a well-defined
 * encoding of the challenge poly, we return the full raw poly here.
 *
 * P1/P2 accept any value.
 */
int handler_cmd_sample_in_ball(buffer_t *cdata);
