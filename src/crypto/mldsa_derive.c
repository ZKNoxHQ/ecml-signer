#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "lcx_mldsa.h"
#include "cx_mldsa_internal.h"

#include "mldsa_derive.h"

// SLIP-0010 HMAC-SHA512 personalizations used to derive the ML-DSA master
// seeds. Distinct from "Bitcoin seed" and "ed25519 seed" so the ML-DSA key
// trees are independent of any ECDSA/Ed25519 tree at the same BIP32 path, and
// distinct from each other so the ML-DSA-44 and ML-DSA-65 keys of one path
// are independent (a compromise of one says nothing about the other).
//
// "ML-DSA-44 seed" matches the ZKNOX-HW-MLDSA convention byte-for-byte, so
// pk/sig produced by this repo interop with tooling built against ZKNOX for
// the same BIP32 path. "ML-DSA-65 seed" follows the same pattern.
static const char MLDSA44_SLIP10_KEY[] = "ML-DSA-44 seed";
static const char MLDSA65_SLIP10_KEY[] = "ML-DSA-65 seed";

// Cap the number of components we can safely hardening-force on the stack.
// Matches MAX_BIP32_PATH in constants.h; kept as a local static assert-style
// check so this helper stays self-contained.
#define MLDSA_DERIVE_MAX_PATH 10

bool mldsa_param_from_p2(uint8_t p2_param, MLDSA_param_t *param) {
    switch (p2_param) {
        case MLDSA_P2_PARAM_44:
            *param = MLDSA_44;
            return true;
        case MLDSA_P2_PARAM_65:
            *param = MLDSA_65;
            return true;
        default:
            return false;
    }
}

// The SDK's MLDSA_PARAM table holds every derived size; the app only ever
// indexes it with MLDSA_44 / MLDSA_65 (mldsa_param_from_p2 is the single
// place a parameter set comes from the wire).
size_t mldsa_pk_bytes(MLDSA_param_t param) {
    return MLDSA_PARAM[param].pk_bytes;
}

size_t mldsa_sk_bytes(MLDSA_param_t param) {
    return MLDSA_PARAM[param].sk_bytes;
}

size_t mldsa_sig_bytes(MLDSA_param_t param) {
    return MLDSA_PARAM[param].sig_bytes;
}

uint8_t mldsa_tau(MLDSA_param_t param) {
    return MLDSA_PARAM[param].tau;
}

const char *mldsa_param_name(MLDSA_param_t param) {
    return (param == MLDSA_65) ? "ML-DSA-65" : "ML-DSA-44";
}

int mldsa_derive_seed(const uint32_t *path,
                      size_t          path_len,
                      MLDSA_param_t   param,
                      uint8_t         seed_out[MLDSA_DERIVE_SEED_LEN]) {
    if (path_len > MLDSA_DERIVE_MAX_PATH) {
        return -1;
    }

    const char *slip10_key;
    size_t      slip10_key_len;
    switch (param) {
        case MLDSA_44:
            slip10_key     = MLDSA44_SLIP10_KEY;
            slip10_key_len = sizeof(MLDSA44_SLIP10_KEY) - 1;
            break;
        case MLDSA_65:
            slip10_key     = MLDSA65_SLIP10_KEY;
            slip10_key_len = sizeof(MLDSA65_SLIP10_KEY) - 1;
            break;
        default:
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
                                                        (unsigned char *) slip10_key,
                                                        slip10_key_len);
    if (error != CX_OK) {
        explicit_bzero(raw_privkey, sizeof(raw_privkey));
        return -1;
    }
    memmove(seed_out, raw_privkey, MLDSA_DERIVE_SEED_LEN);
    explicit_bzero(raw_privkey, sizeof(raw_privkey));
    return 0;
}

int mldsa_keygen_from_seed(const uint8_t seed[MLDSA_DERIVE_SEED_LEN],
                           MLDSA_param_t param,
                           uint8_t      *pk,
                           size_t        pk_len,
                           uint8_t      *sk,
                           size_t        sk_len) {
    if (pk_len < mldsa_pk_bytes(param) || sk_len < mldsa_sk_bytes(param)) {
        return -1;
    }
    cx_err_t error =
        MLDSA_internal_keygen(pk, mldsa_pk_bytes(param), sk, mldsa_sk_bytes(param), seed, param);
    return (error == CX_OK) ? 0 : -1;
}
