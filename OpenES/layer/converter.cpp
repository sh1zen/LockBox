#include <utility>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include "raw-layer.h"
#include <OpenES/support/oesMath.h>
#include "converter.h"
#include "support.h"

/**
 * Convert byte array to m_block array with padding
 *
 * @param data Input byte data
 * @param nByte Number of bytes
 * @return Pair of (m_block array, length)
 */
std::pair<m_block*, size_t> toMBlock(const void* data, const size_t nByte) {
    if (!data || nByte == 0) {
        return std::make_pair(nullptr, 0);
    }

    size_t requestedLen = calcPairsOfSize(nByte, OES_BYTES_X_BLOCK);

    // Add one block if perfectly aligned (for padding)
    if (nByte % OES_BYTES_X_BLOCK == 0) {
        requestedLen++;
    }

    auto converted = static_cast<m_block*>(calloc(requestedLen, sizeof(m_block)));
    if (!converted) {
        return std::make_pair(nullptr, 0);
    }

    size_t pos = 0;
    const auto* byteData = static_cast<const uint8_t*>(data);

    // Pack bytes into m_blocks (big-endian)
    for (size_t i = 0; i < nByte; i++) {
        if (i != 0 && i % OES_BYTES_X_BLOCK == 0) {
            pos++;
        }
        converted[pos] = (converted[pos] << 8) | byteData[i];
    }

    // Add padding
    if (nByte % OES_BYTES_X_BLOCK) {
        const uint8_t padding = requestedPadding(nByte, OES_BYTES_X_BLOCK);
        converted[pos] = converted[pos] << (padding * 8);
        converted[pos] += padding;
    } else {
        converted[requestedLen - 1] = OES_BYTES_X_BLOCK;
    }

    return std::make_pair(converted, requestedLen);
}

/**
 * Extract a single byte from m_block at given position
 *
 * @param block m_block to extract from
 * @param pos Byte position (0 = LSB)
 * @return Extracted byte
 */
uint8_t getByte(m_block block, uint8_t pos) {
    if (pos >= OES_BYTES_X_BLOCK) {
        return 0;
    }
    return (block >> (pos * 8)) & 0xFF;
}

/**
 * Convert m_block array to byte array (raw, no padding removal)
 *
 * @param t Input m_block array
 * @param len Length of m_block array
 * @param extraSize Extra bytes to allocate
 * @return Pair of (byte array, length)
 */
std::pair<uint8_t*, size_t> toByte_raw(const m_block* t, size_t len, size_t extraSize) {
    if (!t || len == 0) {
        return std::make_pair(nullptr, 0);
    }

    size_t outLen = OES_BYTES_X_BLOCK * len + extraSize;

    auto converted = static_cast<uint8_t*>(calloc(outLen, sizeof(uint8_t)));
    if (!converted) {
        return std::make_pair(nullptr, 0);
    }

    // Unpack m_blocks to bytes (big-endian)
    for (size_t i = 0; i < len; i++) {
        size_t pos = i * OES_BYTES_X_BLOCK;

#if OES_LOGIC_BLOCK_SIZE == 32
        converted[pos + 0] = (t[i] >> 24) & 0xFF;
        converted[pos + 1] = (t[i] >> 16) & 0xFF;
        converted[pos + 2] = (t[i] >> 8) & 0xFF;
        converted[pos + 3] = t[i] & 0xFF;
#elif OES_LOGIC_BLOCK_SIZE == 64
        converted[pos + 0] = (t[i] >> 56) & 0xFF;
        converted[pos + 1] = (t[i] >> 48) & 0xFF;
        converted[pos + 2] = (t[i] >> 40) & 0xFF;
        converted[pos + 3] = (t[i] >> 32) & 0xFF;
        converted[pos + 4] = (t[i] >> 24) & 0xFF;
        converted[pos + 5] = (t[i] >> 16) & 0xFF;
        converted[pos + 6] = (t[i] >> 8) & 0xFF;
        converted[pos + 7] = t[i] & 0xFF;
#else
        // Generic implementation for arbitrary block sizes
        for (size_t j = 0; j < OES_BYTES_X_BLOCK; j++) {
            converted[pos + j] = (t[i] >> (8 * (OES_BYTES_X_BLOCK - 1 - j))) & 0xFF;
        }
#endif
    }

    return std::make_pair(converted, outLen);
}

/**
 * Convert m_block array to byte array with padding removal
 *
 * @param t Input m_block array
 * @param len Length of m_block array
 * @return Pair of (byte array, actual length without padding)
 */
std::pair<uint8_t*, size_t> toBytes(const m_block* t, size_t len) {
    if (!t || len == 0) {
        return std::make_pair(nullptr, 0);
    }

    std::pair<uint8_t*, size_t> converted = toByte_raw(t, len, 0);
    if (!converted.first) {
        return std::make_pair(nullptr, 0);
    }

    // Calculate and remove padding
    uint32_t oesBlockPadding = mBlock_get_padding_einer(t, len, false, 0);
    uint32_t mBlockPadding = mBlock_get_padding_einer(t, len - oesBlockPadding, true, 0);

    return std::make_pair(converted.first,  converted.second - (oesBlockPadding * OES_BYTES_X_BLOCK) - mBlockPadding);
}

/**
 * Clone m_block array
 *
 * @param dst Destination buffer (allocated if NULL)
 * @param src Source buffer
 * @param len Number of m_blocks to copy
 * @return Pointer to destination buffer
 */
m_block* mBlock_clone(m_block* dst, const m_block* src, size_t len) {
    if (!src || len == 0) {
        return nullptr;
    }

    if (!dst) {
        dst = static_cast<m_block*>(malloc(len * sizeof(m_block)));
        if (!dst) {
            return nullptr;
        }
    }

    std::memcpy(dst, src, len * sizeof(m_block));

    return dst;
}

/**
 * Concatenate two m_block arrays
 *
 * @param a First array
 * @param a_len Length of first array
 * @param b Second array
 * @param b_len Length of second array
 * @return Concatenated array (caller must free)
 */
m_block* mBlock_concat(const m_block* a, size_t a_len, const m_block* b, size_t b_len) {
    if (!a || !b || a_len == 0 || b_len == 0) {
        return nullptr;
    }

    size_t total_len = a_len + b_len;
    size_t a_size = a_len * sizeof(m_block);
    size_t b_size = b_len * sizeof(m_block);

    auto concatenated = static_cast<m_block*>(malloc(total_len * sizeof(m_block)));
    if (!concatenated) {
        return nullptr;
    }

    std::memcpy(concatenated, a, a_size);
    std::memcpy(concatenated + a_len, b, b_size);

    return concatenated;
}

/**
 * Create and optionally initialize m_block array
 *
 * @param len Number of m_blocks to allocate
 * @param value Initial value (0 for zero-initialization)
 * @return Allocated array (caller must free)
 */
m_block* mBlock_create(size_t len, m_block value) {
    if (len == 0) {
        return nullptr;
    }

    auto filledBlock = static_cast<m_block*>(calloc(len, sizeof(m_block)));
    if (!filledBlock) {
        return nullptr;
    }

    if (value != 0) {
        for (size_t i = 0; i < len; i++) {
            filledBlock[i] = value;
        }
    }

    return filledBlock;
}

/**
 * Safely free m_block array
 *
 * @param ptr Pointer to free
 */
void mBlock_free(m_block* ptr) {
    if (ptr) {
        free(ptr);
    }
}

/**
 * Securely zero and free m_block array (for sensitive data)
 *
 * @param ptr Pointer to secure free
 * @param len Length of array
 */
void mBlock_secure_free(m_block* ptr, size_t len) {
    if (ptr && len > 0) {
        secure_memzero(ptr, len * sizeof(m_block));
        free(ptr);
    }
}