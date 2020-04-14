#ifndef LOCKBOX_RAW_LAYER_H
#define LOCKBOX_RAW_LAYER_H

#include "converter.h"

m_block *mBlock_padding_einer(const m_block *src, size_t len, size_t outLen, m_block pad = 0);
uint32_t mBlock_get_padding_einer(const m_block *block, size_t len, bool inner = true, m_block pad = 0);

void mBlock_xor(m_block *a, const m_block *b, size_t len, bool alternate = false);

m_block mBlock_rotr(m_block seed, size_t i);
m_block mBlock_rotl(m_block seed, size_t i);

void mBlock_rotr_vec(m_block *block, size_t blockLen, size_t i);
void mBlock_rotl_vec(m_block *block, size_t blockLen, size_t i);

void mBlock_dump(const m_block *data, size_t dataLen, bool printable = false);

void mBlock_toggleBit(m_block *block, size_t pos, int bitN);

#endif //LOCKBOX_RAW_LAYER_H
