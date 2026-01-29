#pragma once

#include "m_block.h"

size_t closestMultiple(size_t near, size_t multiple);

size_t calcPairsOfSize(size_t number, size_t of);

uint8_t requestedPadding(size_t dataLen, uint8_t blockSize);

uint64_t randomGenerator(uint64_t seed);

m_block deterministicRandomXorShift(m_block seed);

void xTimeMBlock(m_block *w);

m_block xtime(m_block x);

size_t next_pow2(size_t x);

size_t ceil_log2(size_t x);
