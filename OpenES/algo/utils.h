#pragma once

#include "m_block.h"
class OESHasher;

MBLOCK *oes_raw_hmac(const MBLOCK *key, const MBLOCK *data, size_t hmacLen);
bool oes_raw_hmac_prehashed_into(const MBLOCK *prehashedKey, const MBLOCK *data, size_t hmacLen, m_block *out);
bool oes_raw_hmac_prehashed_into(OESHasher &hasher, const MBLOCK *prehashedKey, const MBLOCK *data, size_t hmacLen,
                                 m_block *out);
