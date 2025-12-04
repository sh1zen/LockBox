#ifndef LOCKBOX_RAW_LAYER_H
#define LOCKBOX_RAW_LAYER_H

#include "m_block.h"

namespace mBlock {

    inline m_block rotr(const m_block seed, size_t i) noexcept {
        i &= (OES_MEM_SIZE - 1);
        return (seed >> i) | (seed << ((OES_MEM_SIZE - i) & (OES_MEM_SIZE - 1)));
    }

    inline m_block rotl(const m_block seed, size_t r) noexcept {
        r &= (OES_MEM_SIZE - 1);
        return (seed << r) | (seed >> ((OES_MEM_SIZE - r) & (OES_MEM_SIZE - 1)));
    }

    uint8_t getByte(m_block block, uint8_t pos);

    std::pair<uint8_t *, size_t> toBytes(m_block block);

    size_t padding_size(m_block block, m_block pad);

    void reverse_range(m_block *a, m_block *b);

    template<typename T>
    void dump(T x, const char *label = "m_block");
}


#endif //LOCKBOX_RAW_LAYER_H
