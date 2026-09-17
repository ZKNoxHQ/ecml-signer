#pragma once

/**
 * Diagnostic stack high-water mark (build with DEBUG_STACK_WATERMARK=1: the
 * release optimisation level with PRINTF). The free part of the app stack is
 * filled with a pattern at start-up; after every APDU the first byte that
 * lost the pattern gives the peak stack depth so far, printed on the
 * Speculos console as
 *   stack watermark: <used> / <total> bytes
 * Used to size the ML-DSA buffers (ML-DSA-65 keygen + sign is the deepest
 * path of the app). Compiled out otherwise.
 */
#include <stdint.h>

#ifdef HAVE_STACK_WATERMARK
void stack_watermark_init(void);
void stack_watermark_report(void);

/**
 * Peak stack depth so far and the size of the app stack, in bytes. Also
 * appended to the DUMMY (INS 0x0a) response in these builds, so a test can
 * read the figure back over the wire after exercising a deep path
 * (tests/standalone/test_stack_watermark.py).
 */
void stack_watermark_get(uint32_t *used, uint32_t *total);
#else
#define stack_watermark_init()
#define stack_watermark_report()
#endif
