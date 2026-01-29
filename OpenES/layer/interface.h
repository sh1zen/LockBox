#pragma once

#include "m_block.h"

MBLOCK *toOESBlock(void *data, size_t len);

std::pair<void *, size_t> exportBlock(MBLOCK *block, int mode);

MBLOCK *importBlock(const void *data, size_t len, int mode);
