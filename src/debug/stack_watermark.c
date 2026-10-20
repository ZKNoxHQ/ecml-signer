#ifdef HAVE_STACK_WATERMARK

#include <stdint.h>
#include <string.h>

#include "os.h"

#include "stack_watermark.h"

// Linker symbols of the app stack (target/<device>/script.ld).
extern uint8_t _stack;
extern uint8_t _estack;

#define WATERMARK_PATTERN 0xA5
// Keep a margin below the current stack pointer when painting, the paint
// call itself uses the stack.
#define WATERMARK_MARGIN 128

static inline uint8_t *current_sp(void) {
    uint8_t *sp;
    __asm volatile("mov %0, sp" : "=r"(sp));
    return sp;
}

void stack_watermark_init(void) {
    uint8_t *lo = &_stack;
    uint8_t *hi = current_sp() - WATERMARK_MARGIN;
    if (hi > lo) {
        memset(lo, WATERMARK_PATTERN, (size_t) (hi - lo));
    }
}

void stack_watermark_get(uint32_t *used, uint32_t *total) {
    uint8_t *p = &_stack;
    while (p < &_estack && *p == WATERMARK_PATTERN) {
        p++;
    }
    *used = (uint32_t) (&_estack - p);
    *total = (uint32_t) (&_estack - &_stack);
}

void stack_watermark_report(void) {
    uint32_t used, total;
    stack_watermark_get(&used, &total);
    PRINTF("stack watermark: %u / %u bytes\n", (unsigned) used, (unsigned) total);
}

#endif  // HAVE_STACK_WATERMARK
