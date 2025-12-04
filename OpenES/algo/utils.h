#ifndef LOCKBOX_UTILS_H
#define LOCKBOX_UTILS_H

#include "m_block.h"
MBLOCK* oes_raw_hmac(const MBLOCK* key, const MBLOCK* data, size_t hmacLen);

#endif //LOCKBOX_UTILS_H