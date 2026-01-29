#pragma once

#include <OpenES/layer/defines.h>

void mem_transfer(void **dst, void *src);

void swap_pointers(void **a, void **b);

void secure_memzero(void *v, size_t n);
