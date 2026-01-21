#ifndef LOCKBOX_BLOCK_INTERFACE_H
#define LOCKBOX_BLOCK_INTERFACE_H

#include "m_block.h"

MBLOCK *toOESBlock(void *data, size_t len);

std::pair<void *, size_t> exportBlock(MBLOCK *block, int mode);

MBLOCK *importBlock(const void *data, size_t len, int mode);

#endif //LOCKBOX_BLOCK_INTERFACE_H
