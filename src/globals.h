#pragma once

#include <stdint.h>

#include "ux.h"

#include "io.h"
#include "types.h"
#include "constants.h"

/**
 * Global context for user requests.
 */
extern global_ctx_t G_context;

/**
 * Global structure for NVM data storage.
 */
typedef struct internal_storage_t {
    // Blind signing: allow operations whose review screen cannot represent the
    // bytes being signed (a bare 32-byte hash, an opaque ML-DSA payload, a
    // UserOp whose callData preimage was withheld). OFF on first boot; the
    // user must enable it explicitly in Settings, behind a confirmation.
    uint8_t blind_signing_allowed;
    uint8_t initialized;
} internal_storage_t;

extern const internal_storage_t N_storage_real;
#define N_storage (*(volatile internal_storage_t *) PIC(&N_storage_real))

/**
 * True when the user has opted in to blind signing in Settings.
 */
#define BLIND_SIGNING_ALLOWED() (N_storage.blind_signing_allowed == 0x01)
