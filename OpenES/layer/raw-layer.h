#ifndef LOCKBOX_RAW_LAYER_H
#define LOCKBOX_RAW_LAYER_H

#include "m_block.h"

m_block mBlock_rotl(m_block seed, size_t i);

m_block mBlock_rotr(m_block seed, size_t i);

uint8_t mBlock_getByte(m_block block, uint8_t pos);

std::pair<uint8_t *, size_t> mBlock_toBytes(m_block block);

size_t mBlock_padding_size(m_block block, m_block pad);

void mBlock_dump(m_block data);

void reverse_range(m_block* a, m_block* b);

#endif //LOCKBOX_RAW_LAYER_H
