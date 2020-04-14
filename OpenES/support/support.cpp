#include <cstdlib>
#include "support.h"

void mem_transfer(void **dst, void *src) {
    if (*dst == nullptr) {
        free(*dst);
    }
    *dst = src;
}

void swap_pointers(void **a, void **b) {
    void *tmp = *a;
    *a = *b;
    *b = tmp;
}


// secure_memzero: zeroizza len bytes in modo che il compilatore non lo elimini.
void secure_memzero(void *v, size_t n) {
    if (v == nullptr || n == 0) return;
    volatile auto *p = static_cast<volatile unsigned char *>(v);
    while (n--) *p++ = 0;
}