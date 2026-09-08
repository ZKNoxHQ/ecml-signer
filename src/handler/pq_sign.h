#pragma once

#include <stdint.h>

#include "buffer.h"

/**
 * SIGN_DILITHIUM (INS 0x0f) — sign a raw payload with the currently-loaded
 * ML-DSA-44 key.
 *
 * Multi-APDU protocol (matches ZKNOX-HW-MLDSA wire format):
 *   P1 = 0x00  Init. Discards any prior in-progress signing state and starts
 *              a fresh payload accumulator. cdata is ignored.
 *   P1 = 0x01  Absorb. Appends cdata to the payload accumulator. Multiple
 *              absorb calls concatenate the payload.
 *   P1 = 0x80  Finalize. Triggers a user-approval review of the payload.
 *              On approval, signs the accumulated payload with the key that
 *              was most recently loaded via KEYGEN_DILITHIUM_CORE (0x0c) or
 *              KEYGEN_DILITHIUM (0x11). The signature is stored in
 *              G_context.tx_info.mldsa_sig; client fetches via GET_SIG_CHUNK.
 *
 *              cdata is not required to be non-empty. ZKNOX prepended a
 *              2-byte "expected message length" header here and discarded it;
 *              we accept any (or no) header and ignore it.
 *
 * State enforcement: 0x01 and 0x80 require a prior 0x00 in the same session
 * and a loaded key; otherwise SWO_CONDITIONS_NOT_SATISFIED.
 *
 * Response: SW only; signature is returned asynchronously after user approval
 * on the finalize APDU (0x80). ZKNOX also included the first 256 B of the sig
 * inline in the 0x80 response — we don't (client fetches all chunks via 0x12).
 */
int handler_cmd_sign_dilithium(buffer_t *cdata, uint8_t p1);
