#include <stdint.h>
#include <string.h>

#include "os.h"
#include "buffer.h"
#include "io.h"
#include "lcx_mldsa.h"

#include "pq_keygen.h"
#include "mldsa_derive.h"
#include "globals.h"
#include "sw.h"

static int keygen_common(void) {
    // Secret key is bulky (~2560 B for ML-DSA-44). Keep it on the stack scoped
    // to this function so it is scrubbed on return rather than living in .bss.
    uint8_t sk[MLDSA44_SECRETKEYBYTES] = {0};

    int rc = mldsa_keygen_from_seed(G_context.tx_info.mldsa_seed,
                                    G_context.tx_info.mldsa_pk,
                                    sk,
                                    sizeof(sk));
    explicit_bzero(sk, sizeof(sk));

    if (rc != 0) {
        // Fail closed: wipe pk on error so a subsequent GET_PK_CHUNK cannot
        // return partial or stale key material.
        explicit_bzero(G_context.tx_info.mldsa_pk, sizeof(G_context.tx_info.mldsa_pk));
        return io_send_sw(SWO_SECURITY_ISSUE);
    }

    // Zero the sig buffer so a stale chunk cannot be fetched after a fresh keygen.
    explicit_bzero(G_context.tx_info.mldsa_sig, sizeof(G_context.tx_info.mldsa_sig));
    G_context.tx_info.mldsa_sig_len = 0;

    return io_send_sw(SWO_SUCCESS);
}

int handler_cmd_keygen_core_dilithium(buffer_t *cdata) {
    if (cdata->size != MLDSA_DERIVE_SEED_LEN) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    explicit_bzero(&G_context, sizeof(G_context));
    memmove(G_context.tx_info.mldsa_seed, cdata->ptr, MLDSA_DERIVE_SEED_LEN);
    return keygen_common();
}

int handler_cmd_keygen_dilithium(buffer_t *cdata) {
    explicit_bzero(&G_context, sizeof(G_context));

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    if (mldsa_derive_seed(G_context.bip32_path,
                          G_context.bip32_path_len,
                          G_context.tx_info.mldsa_seed) != 0) {
        return io_send_sw(SWO_SECURITY_ISSUE);
    }

    return keygen_common();
}
