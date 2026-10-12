#pragma once

#include "buffer.h"
#include "lcx_mldsa.h"

/**
 * DUMMY (INS 0x0a) — echo cdata unchanged. I/O smoke test with no state or UI.
 *
 * P1/P2 accept any value.
 */
#ifdef HAVE_TEST_INS
int handler_cmd_dummy(buffer_t *cdata);

/**
 * SAMPLE_IN_BALL (INS 0x0b) — expose ML-DSA's SampleInBall primitive.
 *
 * Runs FIPS 204 Algorithm 29 (SampleInBall) with the tau of the parameter
 * set selected by P2 (0x00: ML-DSA-44, tau = 39; 0x01: ML-DSA-65, tau = 49)
 * on the host-provided c_tilde seed, and returns the challenge polynomial c.
 *
 * Input:  c_tilde bytes (any length; 32 bytes for ML-DSA-44 and 48 for
 *         ML-DSA-65 in normal use).
 * Output: 1024 bytes — raw `int32_t coeffs[256]` little-endian.
 *
 * Wire note: ZKNOX-HW-MLDSA returned only 256 bytes from a 1024-byte poly
 * struct (truncation bug). Since the ZKNOX response was not a well-defined
 * encoding of the challenge poly, we return the full raw poly here.
 *
 * P1 accepts any value; P2 other than 0x00 / 0x01 is SWO_INCORRECT_P1_P2.
 */
int handler_cmd_sample_in_ball(buffer_t *cdata, MLDSA_param_t param);
#endif  // HAVE_TEST_INS
