#pragma once

#include "m_block.h"

namespace mBlock {
    inline m_block rotr(const m_block seed, size_t r) noexcept {
        r &= OES_MEM_SIZE_MASK;
        return (seed >> r) | (seed << ((OES_MEM_SIZE - r) & OES_MEM_SIZE_MASK));
    }

    inline m_block rotl(const m_block seed, size_t r) noexcept {
        r &= OES_MEM_SIZE_MASK;
        return (seed << r) | (seed >> (OES_MEM_SIZE - r & OES_MEM_SIZE_MASK));
    }

    uint8_t getByte(m_block block, uint8_t pos);

    std::pair<uint8_t *, size_t> toBytes(m_block block);

    size_t padding_size(m_block block, m_block pad);

    void reverse_range(m_block *a, m_block *b);

    template<typename T>
    void dump(T x, const char *label = "m_block");
}
