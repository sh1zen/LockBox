#include "interface.h"

#include <cstdlib>
#include <new>

#include <OpenES/support/base64/base64.h>
#include "support.h"

// Lookup table for byte -> 2 hex chars (precomputed)
static const char hex_lut[256][2] = {
    {'0', '0'}, {'0', '1'}, {'0', '2'}, {'0', '3'}, {'0', '4'}, {'0', '5'}, {'0', '6'}, {'0', '7'},
    {'0', '8'}, {'0', '9'}, {'0', 'a'}, {'0', 'b'}, {'0', 'c'}, {'0', 'd'}, {'0', 'e'}, {'0', 'f'},
    {'1', '0'}, {'1', '1'}, {'1', '2'}, {'1', '3'}, {'1', '4'}, {'1', '5'}, {'1', '6'}, {'1', '7'},
    {'1', '8'}, {'1', '9'}, {'1', 'a'}, {'1', 'b'}, {'1', 'c'}, {'1', 'd'}, {'1', 'e'}, {'1', 'f'},
    {'2', '0'}, {'2', '1'}, {'2', '2'}, {'2', '3'}, {'2', '4'}, {'2', '5'}, {'2', '6'}, {'2', '7'},
    {'2', '8'}, {'2', '9'}, {'2', 'a'}, {'2', 'b'}, {'2', 'c'}, {'2', 'd'}, {'2', 'e'}, {'2', 'f'},
    {'3', '0'}, {'3', '1'}, {'3', '2'}, {'3', '3'}, {'3', '4'}, {'3', '5'}, {'3', '6'}, {'3', '7'},
    {'3', '8'}, {'3', '9'}, {'3', 'a'}, {'3', 'b'}, {'3', 'c'}, {'3', 'd'}, {'3', 'e'}, {'3', 'f'},
    {'4', '0'}, {'4', '1'}, {'4', '2'}, {'4', '3'}, {'4', '4'}, {'4', '5'}, {'4', '6'}, {'4', '7'},
    {'4', '8'}, {'4', '9'}, {'4', 'a'}, {'4', 'b'}, {'4', 'c'}, {'4', 'd'}, {'4', 'e'}, {'4', 'f'},
    {'5', '0'}, {'5', '1'}, {'5', '2'}, {'5', '3'}, {'5', '4'}, {'5', '5'}, {'5', '6'}, {'5', '7'},
    {'5', '8'}, {'5', '9'}, {'5', 'a'}, {'5', 'b'}, {'5', 'c'}, {'5', 'd'}, {'5', 'e'}, {'5', 'f'},
    {'6', '0'}, {'6', '1'}, {'6', '2'}, {'6', '3'}, {'6', '4'}, {'6', '5'}, {'6', '6'}, {'6', '7'},
    {'6', '8'}, {'6', '9'}, {'6', 'a'}, {'6', 'b'}, {'6', 'c'}, {'6', 'd'}, {'6', 'e'}, {'6', 'f'},
    {'7', '0'}, {'7', '1'}, {'7', '2'}, {'7', '3'}, {'7', '4'}, {'7', '5'}, {'7', '6'}, {'7', '7'},
    {'7', '8'}, {'7', '9'}, {'7', 'a'}, {'7', 'b'}, {'7', 'c'}, {'7', 'd'}, {'7', 'e'}, {'7', 'f'},
    {'8', '0'}, {'8', '1'}, {'8', '2'}, {'8', '3'}, {'8', '4'}, {'8', '5'}, {'8', '6'}, {'8', '7'},
    {'8', '8'}, {'8', '9'}, {'8', 'a'}, {'8', 'b'}, {'8', 'c'}, {'8', 'd'}, {'8', 'e'}, {'8', 'f'},
    {'9', '0'}, {'9', '1'}, {'9', '2'}, {'9', '3'}, {'9', '4'}, {'9', '5'}, {'9', '6'}, {'9', '7'},
    {'9', '8'}, {'9', '9'}, {'9', 'a'}, {'9', 'b'}, {'9', 'c'}, {'9', 'd'}, {'9', 'e'}, {'9', 'f'},
    {'a', '0'}, {'a', '1'}, {'a', '2'}, {'a', '3'}, {'a', '4'}, {'a', '5'}, {'a', '6'}, {'a', '7'},
    {'a', '8'}, {'a', '9'}, {'a', 'a'}, {'a', 'b'}, {'a', 'c'}, {'a', 'd'}, {'a', 'e'}, {'a', 'f'},
    {'b', '0'}, {'b', '1'}, {'b', '2'}, {'b', '3'}, {'b', '4'}, {'b', '5'}, {'b', '6'}, {'b', '7'},
    {'b', '8'}, {'b', '9'}, {'b', 'a'}, {'b', 'b'}, {'b', 'c'}, {'b', 'd'}, {'b', 'e'}, {'b', 'f'},
    {'c', '0'}, {'c', '1'}, {'c', '2'}, {'c', '3'}, {'c', '4'}, {'c', '5'}, {'c', '6'}, {'c', '7'},
    {'c', '8'}, {'c', '9'}, {'c', 'a'}, {'c', 'b'}, {'c', 'c'}, {'c', 'd'}, {'c', 'e'}, {'c', 'f'},
    {'d', '0'}, {'d', '1'}, {'d', '2'}, {'d', '3'}, {'d', '4'}, {'d', '5'}, {'d', '6'}, {'d', '7'},
    {'d', '8'}, {'d', '9'}, {'d', 'a'}, {'d', 'b'}, {'d', 'c'}, {'d', 'd'}, {'d', 'e'}, {'d', 'f'},
    {'e', '0'}, {'e', '1'}, {'e', '2'}, {'e', '3'}, {'e', '4'}, {'e', '5'}, {'e', '6'}, {'e', '7'},
    {'e', '8'}, {'e', '9'}, {'e', 'a'}, {'e', 'b'}, {'e', 'c'}, {'e', 'd'}, {'e', 'e'}, {'e', 'f'},
    {'f', '0'}, {'f', '1'}, {'f', '2'}, {'f', '3'}, {'f', '4'}, {'f', '5'}, {'f', '6'}, {'f', '7'},
    {'f', '8'}, {'f', '9'}, {'f', 'a'}, {'f', 'b'}, {'f', 'c'}, {'f', 'd'}, {'f', 'e'}, {'f', 'f'}
};

// Lookup table for hex char -> nibble (255 = invalid)
// Index is ASCII value, value is nibble (0-15) or 255 if invalid
static const uint8_t unhex_lut[256] = {
    //  0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x00-0x0F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x10-0x1F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    // 0x20-0x2F (space, !"#$%&'()*+,-./)
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, // 0x30-0x3F ('0'-'9' at 0x30-0x39)
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x40-0x4F ('A'-'F' at 0x41-0x46)
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x50-0x5F
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x60-0x6F ('a'-'f' at 0x61-0x66)
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x70-0x7F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x80-0x8F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0x90-0x9F
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0xA0-0xAF
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0xB0-0xBF
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0xC0-0xCF
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0xD0-0xDF
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0xE0-0xEF
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 // 0xF0-0xFF
};

// Convert m_block to hex using LUT (big-endian output)
static inline void m_block_to_hex(m_block val, char *out) {
    for (int i = OES_BYTES_X_BLOCK - 1; i >= 0; --i) {
        const auto byte = static_cast<uint8_t>(val >> (i * 8));
        out[0] = hex_lut[byte][0];
        out[1] = hex_lut[byte][1];
        out += 2;
    }
}

// Convert hex to m_block using LUT (returns false on invalid char)
static inline bool hex_to_m_block(const char *hex, m_block &out) {
    m_block val = 0;
    // Process 2 hex chars per byte, OES_BYTES_X_BLOCK bytes total
    // Input is big-endian (MSB first), so first byte goes to highest position
    for (size_t i = 0; i < OES_BYTES_X_BLOCK; ++i) {
        const uint8_t hi = unhex_lut[static_cast<uint8_t>(hex[i * 2])];
        const uint8_t lo = unhex_lut[static_cast<uint8_t>(hex[i * 2 + 1])];
        if ((hi | lo) & 0x80) return false;
        const uint8_t byte = (hi << 4) | lo;
        // Place byte at correct position (big-endian: first byte = MSB)
        val |= static_cast<m_block>(byte) << ((OES_BYTES_X_BLOCK - 1 - i) * 8);
    }
    out = val;
    return true;
}

std::pair<char *, size_t> oes_export_block_to_string(MBLOCK *block) {
    if (!block || block->isNull()) return {nullptr, 0};

    auto [raw, len] = block->toBytes();
    if (!raw) return {nullptr, 0};

    auto result = static_cast<char *>(malloc(len + 1));
    if (!result) {
        secure_memzero(raw, len);
        free(raw);
        return {nullptr, 0};
    }

    memcpy(result, raw, len);
    result[len] = '\0';

    secure_memzero(raw, len);
    free(raw);

    return {result, len + 1};
}

std::pair<char *, size_t> oes_export_block_to_base64(MBLOCK *block) {
    if (!block || block->isNull()) return {nullptr, 0};

    auto [bytes, len] = block->toBytes();
    if (!bytes) return {nullptr, 0};

    auto result = base64_encode(bytes, len);

    secure_memzero(bytes, len);
    free(bytes);

    return result;
}

std::pair<char *, size_t> oes_export_block_to_hex_string(MBLOCK *block) {
    if (!block || block->isNull()) return {nullptr, 0};

    const size_t count = block->getLen();
    constexpr size_t chars_per_block = 2 * OES_BYTES_X_BLOCK;
    const size_t out_len = chars_per_block * count + 1;

    char *output = static_cast<char *>(malloc(out_len));
    if (!output) return {nullptr, 0};

    char *ptr = output;
    for (size_t i = 0; i < count; ++i) {
        m_block_to_hex(block->getBlock(i), ptr);
        ptr += chars_per_block;
    }
    *ptr = '\0';

    return {output, out_len};
}

MBLOCK *oes_import_block_from_hex_string(const char *hex) {
    if (!hex) return nullptr;

    const size_t hex_len = strlen(hex);
    constexpr size_t chars_per_block = 2 * OES_BYTES_X_BLOCK;

    if (hex_len == 0 || hex_len % chars_per_block != 0) return nullptr;

    const size_t count = hex_len / chars_per_block;
    auto *data = new(std::nothrow) m_block[count];
    if (!data) return nullptr;

    for (size_t i = 0; i < count; ++i) {
        if (!hex_to_m_block(hex + i * chars_per_block, data[i])) {
            delete[] data;
            return nullptr;
        }
    }

    return new MBLOCK(data, count, true);
}

MBLOCK *oes_import_block_from_base64(const char *b64) {
    if (!b64) return nullptr;

    auto [decoded, len] = base64_decode(b64, strlen(b64));
    if (!decoded) return nullptr;

    MBLOCK *block = MBLOCK::fromBytes(decoded, len);

    secure_memzero(decoded, len);
    free(decoded);

    return block;
}

std::pair<void *, size_t> exportBlock(MBLOCK *block, int mode) {
    if (!block || block->isNull()) return {nullptr, 0};

    switch (mode) {
        case OES_TYPE_HEX:
            return oes_export_block_to_hex_string(block);

        case OES_TYPE_UINT8:
            return block->toBytes();

        case OES_TYPE_RAW_UINT8:
            return block->toBytes_raw();

        case OES_TYPE_CHAR:
            return oes_export_block_to_string(block);

        case OES_EXPORT_BASE64:
            return oes_export_block_to_base64(block);

        case OES_TYPE_MBLOCK:
        default: {
            const size_t count = block->getLen();
            const size_t bytes = count * sizeof(m_block);
            auto copy = static_cast<m_block *>(malloc(bytes));
            if (!copy) return {nullptr, 0};

            // Direct copy if MBLOCK stores contiguously, else element-wise
            for (size_t i = 0; i < count; i++) {
                copy[i] = block->getBlock(i);
            }
            return {copy, count};
        }
    }
}

MBLOCK *importBlock(const void *data, size_t len, int mode) {
    if (!data) return nullptr;

    switch (mode) {
        case OES_TYPE_HEX:
            return oes_import_block_from_hex_string(static_cast<const char *>(data));

        case OES_TYPE_UINT8:
            return MBLOCK::fromBytes(data, len);

        case OES_TYPE_RAW_UINT8:
            return MBLOCK::fromBytes_raw(data, len);

        case OES_TYPE_CHAR:
            return MBLOCK::fromBytes(data, len > 0 ? len - 1 : 0);

        case OES_EXPORT_BASE64:
            return oes_import_block_from_base64(static_cast<const char *>(data));

        case OES_TYPE_MBLOCK:
        default: {
            if (len == 0) return nullptr;
            const size_t bytes = len * sizeof(m_block);
            auto *copy = new(std::nothrow) m_block[len];
            if (!copy) return nullptr;
            memcpy(copy, data, bytes);
            return new MBLOCK(copy, len, true);
        }
    }
}
