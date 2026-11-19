/* C11 ring buffer fixture with comments and indirect call. */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t buf[64];
    size_t head;
    size_t tail;
} RingBuf;

/* Sibling block comment preserved across edits. */
size_t ring_count(const RingBuf *r) {
    return (r->head - r->tail) & 63u;
}

// Inline comment preserved across edits.
int ring_push(RingBuf *r, uint8_t byte) {
    if (ring_count(r) >= 63u) {
        return -1;
    }
    r->buf[r->head & 63u] = byte;
    r->head = (r->head + 1u) & 63u;
    return 0;
}

typedef uint8_t (*transform_fn)(uint8_t);

uint8_t ring_apply(transform_fn cb, uint8_t value) {
    return (*cb)(value);
}
