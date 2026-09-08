#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "lcx_mldsa.h"
#include "cx_mldsa_internal.h"

#include "mldsa_derive.h"

// SLIP-0010 HMAC-SHA512 personalization used to derive the ML-DSA-44 master
// seed. Distinct from "Bitcoin seed" and "ed25519 seed" so the ML-DSA key tree
// is independent of any ECDSA/Ed25519 tree at the same BIP32 path.
//
// Matches the ZKNOX-HW-MLDSA convention byte-for-byte, so pk/sig produced by
// this repo interop with tooling built against ZKNOX for the same BIP32 path.
static const char MLDSA_SLIP10_KEY[] = "ML-DSA-44 seed";

// Cap the number of components we can safely hardening-force on the stack.
// Matches MAX_BIP32_PATH in constants.h; kept as a local static assert-style
// check so this helper stays self-contained.
#define MLDSA_DERIVE_MAX_PATH 10

int mldsa_derive_seed(const uint32_t *path,
                      size_t          path_len,
                      uint8_t         seed_out[MLDSA_DERIVE_SEED_LEN]) {
    if (path_len > MLDSA_DERIVE_MAX_PATH) {
        return -1;
    }

    // ML-DSA seed derivation uses SLIP-0010 in ed25519 mode, which requires
    // ALL path components to be hardened. Force the hardened bit on every
    // component here so callers can pass a "logical" path (like the standard
    // m/44'/60'/0'/0/0 they use for ECDSA) and get a consistent, SLIP-0010-
    // conformant ML-DSA key. This is what pqslip.js does client-side; we
    // mirror it on-device so hybrid signing (0x16 / 0x17) can use the same
    // path input for both halves: ECDSA half sees the raw path, ML-DSA half
    // sees the hardened variant.
    uint32_t hardened_path[MLDSA_DERIVE_MAX_PATH];
    for (size_t i = 0; i < path_len; i++) {
        hardened_path[i] = path[i] | 0x80000000u;
    }

    // SDK writes 64 bytes: [priv(32) | chain_code(32)]; we only keep the priv half.
    uint8_t raw_privkey[64] = {0};
    cx_err_t error = os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10,
                                                        CX_CURVE_Ed25519,
                                                        hardened_path,
                                                        path_len,
                                                        raw_privkey,
                                                        NULL,
                                                        (unsigned char *) MLDSA_SLIP10_KEY,
                                                        sizeof(MLDSA_SLIP10_KEY) - 1);
    if (error != CX_OK) {
        explicit_bzero(raw_privkey, sizeof(raw_privkey));
        return -1;
    }
    memmove(seed_out, raw_privkey, MLDSA_DERIVE_SEED_LEN);
    explicit_bzero(raw_privkey, sizeof(raw_privkey));
    return 0;
}

int mldsa_keygen_from_seed(const uint8_t seed[MLDSA_DERIVE_SEED_LEN],
                           uint8_t       pk[MLDSA44_PUBLICKEYBYTES],
                           uint8_t      *sk,
                           size_t        sk_len) {
    cx_err_t error =
        MLDSA_internal_keygen(pk, MLDSA44_PUBLICKEYBYTES, sk, sk_len, seed, MLDSA_44);
    return (error == CX_OK) ? 0 : -1;
}
