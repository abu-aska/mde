#include <stdint.h>

#define SCALE_FACTOR(x) ((x) * 4u)

#ifdef USE_FAST_PATH
uint32_t scale_value(uint32_t x) {
    return SCALE_FACTOR(x);
}
#else
uint32_t scale_value(uint32_t x) {
    return x + x;
}
#endif
