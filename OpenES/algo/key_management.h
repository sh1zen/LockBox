#pragma once

#include "m_block.h"

MBLOCK *key_expansion(const MBLOCK *key, size_t outLen, m_block salt, size_t iterations);

MBLOCK *key_scheduler(const MBLOCK *key, size_t outLen, size_t session);
