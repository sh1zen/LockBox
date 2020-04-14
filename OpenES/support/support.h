#ifndef LOCKBOX_SUPPORT_H
#define LOCKBOX_SUPPORT_H

void mem_transfer(void **dst, void *src);

void swap_pointers(void **a, void **b);

void secure_memzero(void *v, size_t n);

#endif //LOCKBOX_SUPPORT_H
