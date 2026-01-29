#pragma once

#include "m_block.h"

MBLOCK *oes_raw_hmac(const MBLOCK *key, const MBLOCK *data, size_t hmacLen);
