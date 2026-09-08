#include <stdint.h>
#include <string.h>

#include "buffer.h"
#include "io.h"

#include "cx_mldsa_poly.h"
#include "cx_mldsa_sample.h"
#include "lcx_mldsa.h"

#include "pq_primitives.h"
#include "sw.h"

int handler_cmd_dummy(buffer_t *cdata) {
    return io_send_response_pointer(cdata->ptr, cdata->size, SWO_SUCCESS);
}

int handler_cmd_sample_in_ball(buffer_t *cdata) {
    mldsa_poly c;
    memset(&c, 0, sizeof(c));

    MLDSA_SAMPLE_challenge(&c, cdata->ptr, cdata->size, MLDSA44_TAU);

    return io_send_response_pointer((const uint8_t *) c.coeffs, sizeof(c.coeffs), SWO_SUCCESS);
}
