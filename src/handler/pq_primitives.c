#include <stdint.h>
#include <string.h>

#include "buffer.h"
#include "io.h"

#include "cx_mldsa_poly.h"
#include "cx_mldsa_sample.h"
#include "lcx_mldsa.h"

#include "pq_primitives.h"
#include "mldsa_derive.h"
#include "stack_watermark.h"
#include "sw.h"

int handler_cmd_dummy(buffer_t *cdata) {
#ifdef HAVE_STACK_WATERMARK
    // DEBUG_STACK_WATERMARK=1 builds: echo || used(4 BE) || total(4 BE), so a
    // test can read the peak stack depth back after exercising a deep path.
    uint32_t used, total;
    stack_watermark_get(&used, &total);
    uint8_t wm[8] = {(uint8_t) (used >> 24),
                     (uint8_t) (used >> 16),
                     (uint8_t) (used >> 8),
                     (uint8_t) used,
                     (uint8_t) (total >> 24),
                     (uint8_t) (total >> 16),
                     (uint8_t) (total >> 8),
                     (uint8_t) total};
    const buffer_t parts[2] = {
        {.ptr = cdata->ptr, .size = cdata->size, .offset = 0},
        {.ptr = wm, .size = sizeof(wm), .offset = 0},
    };
    return io_send_response_buffers(parts, 2, SWO_SUCCESS);
#else
    return io_send_response_pointer(cdata->ptr, cdata->size, SWO_SUCCESS);
#endif
}

int handler_cmd_sample_in_ball(buffer_t *cdata, MLDSA_param_t param) {
    mldsa_poly c;
    memset(&c, 0, sizeof(c));

    MLDSA_SAMPLE_challenge(&c, cdata->ptr, cdata->size, mldsa_tau(param));

    return io_send_response_pointer((const uint8_t *) c.coeffs, sizeof(c.coeffs), SWO_SUCCESS);
}
