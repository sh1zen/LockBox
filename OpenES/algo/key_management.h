#pragma once

#include <vector>
#include "m_block.h"

std::vector<MBLOCK *> PBKDF(const MBLOCK &key, size_t outLen, size_t count, m_block salt = m_block(0xa54ff53a),
                            size_t iterations = 16);

MBLOCK *key_expansion(const MBLOCK *key, size_t outLen, m_block salt, size_t iterations);

MBLOCK *key_scheduler(const MBLOCK *key, size_t outLen, size_t session);

void cleanup_pbkdf_keys(std::vector<MBLOCK *> &roundKey);
