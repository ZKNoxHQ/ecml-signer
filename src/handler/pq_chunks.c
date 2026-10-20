#include <stdint.h>

#include "buffer.h"
#include "io.h"
#include "lcx_mldsa.h"

#include "pq_chunks.h"
#include "mldsa_derive.h"
#include "globals.h"
#include "sw.h"

// P1 is a chunk index; each chunk is up to 255 bytes (APDU response limit).
#define PQ_CHUNK_STRIDE 255U

static int send_chunk(const uint8_t *buf, size_t buf_size, uint8_t p1, uint8_t p2) {
    // Compute offset without risking uint32 overflow (p1*255 fits in uint32 for uint8).
    uint32_t offset = (uint32_t) p1 * PQ_CHUNK_STRIDE;
    uint32_t end = offset + (uint32_t) p2;

    if (end > buf_size || end < offset) {
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    return io_send_response_pointer(buf + offset, p2, SWO_SUCCESS);
}

int handler_cmd_get_pk_chunk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void) cdata;  // No inbound data expected on chunk-fetch APDUs.
    // Bound: the pk size of the loaded key's parameter set (<= buffer size).
    return send_chunk(G_context.tx_info.mldsa_pk,
                      mldsa_pk_bytes(G_context.tx_info.mldsa_param),
                      p1,
                      p2);
}

int handler_cmd_get_sig_chunk(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void) cdata;
    // Bound: the signature size of the loaded key's parameter set, so that a
    // freshly-keygen'd (zeroed) buffer can be read up to that size.
    return send_chunk(G_context.tx_info.mldsa_sig,
                      mldsa_sig_bytes(G_context.tx_info.mldsa_param),
                      p1,
                      p2);
}
