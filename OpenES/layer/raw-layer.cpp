#include <OpenES/support/oes-exception.h>
#include "raw-layer.h"

m_block mBlock_rotr(const m_block seed, size_t i) {
    if (i > OES_MEM_SIZE) i &= (OES_MEM_SIZE - 1);
    return (i ? (seed >> i) | (seed << (OES_MEM_SIZE - i)) : seed);
}

m_block mBlock_rotl(const m_block seed, size_t i) {
    if (i > OES_MEM_SIZE) i &= (OES_MEM_SIZE - 1);
    return (i ? (seed << i) | (seed >> (OES_MEM_SIZE - i)) : seed);
}

/**
 * Extract a single byte from m_block at given position
 *
 * @param block m_block to extract from
 * @param pos Byte position (0 = LSB)
 * @return Extracted byte
 */
uint8_t mBlock_getByte(m_block block, uint8_t pos) {
    if (pos >= OES_BYTES_X_BLOCK) {
        return 0;
    }
    return (block >> (pos * 8)) & 0xFF;
}

/**
 * Convert m_block to byte array (raw, no padding removal)
 *
 * @param block Input m_block array
 * @return Pair of (byte array, length)
 */
std::pair<uint8_t *, size_t> mBlock_toBytes(m_block block) {
    if (!block) {
        return std::make_pair(nullptr, 0);
    }

    auto *bytes = new uint8_t[OES_BYTES_X_BLOCK];

    for (size_t j = 0; j < OES_BYTES_X_BLOCK; j++) {
        bytes[j] = (block >> (8 * (OES_BYTES_X_BLOCK - 1 - j))) & 0xFF;
    }

    return std::make_pair(bytes, OES_BYTES_X_BLOCK);
}

size_t mBlock_padding_size(m_block block, m_block pad) {
    // Extract bytes in big-endian order
    auto [bytes, _] = mBlock_toBytes(block);

    // Last byte indicates padding length
    const size_t padding = bytes[OES_BYTES_X_BLOCK - 1];

    // Verify padding bytes
    for (size_t i = 1; i < padding && i < OES_BYTES_X_BLOCK; i++) {
        if (bytes[OES_BYTES_X_BLOCK - 1 - i] != pad) {
            throw OESException("OES exception:: invalid padding", OES_EXCEPTION_INV_PAD);
        }
    }

    return padding;
}

void mBlock_dump(const m_block data) {
    printf("\n========= m_block dump ===========\n%02x\n", data);
}

void reverse_range(m_block* a, m_block* b) {
    while (a < b) {
        m_block tmp = *a;
        *a++ = *--b;
        *b = tmp;
    }
}