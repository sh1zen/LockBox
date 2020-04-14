#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/support/base64/base64.h>
#include "block-interface.h"

#include "support.h"

/**
 * Convert raw data to OES_BLOCK structure
 *
 * @param data Input data buffer
 * @param len Length of input data in bytes
 * @return OES_BLOCK structure (caller must free with unset_block)
 */
OES_BLOCK toOESBlock(void* data, size_t len) {
    if (!data || len == 0) {
        return nullptr;
    }

    auto block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!block) {
        return nullptr;
    }

    const std::pair<m_block*, size_t> converted = toMBlock(data, len);
    if (!converted.first || converted.second == 0) {
        free(block);
        return nullptr;
    }

    block->data = converted.first;
    block->len = converted.second;

    return block;
}

/**
 * Export OES_BLOCK to null-terminated string
 *
 * @param block OES_BLOCK to export
 * @return Pair of (null-terminated string, length including null terminator) - caller must free
 */
std::pair<char*, size_t> oes_export_block_to_string(OES_BLOCK block) {
    if (!block || !block->data || block->len == 0) {
        return std::make_pair(nullptr, 0);
    }

    // Converti senza byte extra
    std::pair<uint8_t*, size_t> converted = toBytes(block->data, block->len);
    if (!converted.first || converted.second == 0) {
        return std::make_pair(nullptr, 0);
    }

    // Alloca nuova memoria con spazio per il null terminator
    size_t total_size = converted.second + 1;
    char* result = static_cast<char*>(malloc(total_size));
    if (!result) {
        secure_memzero(converted.first, converted.second);
        free(converted.first);
        return std::make_pair(nullptr, 0);
    }

    // Copia i dati e aggiungi null terminator
    std::memcpy(result, converted.first, converted.second);
    result[converted.second] = '\0';

    // Pulisci il buffer temporaneo
    secure_memzero(converted.first, converted.second);
    free(converted.first);

    return std::make_pair(result, total_size);
}

/**
 * Export OES_BLOCK to Base64-encoded string
 *
 * @param block OES_BLOCK to export
 * @return Pair of (Base64 string, length including null terminator) - caller must free
 */
std::pair<char*, size_t> oes_export_block_to_base64(OES_BLOCK block) {
    if (!block || !block->data || block->len == 0) {
        return std::make_pair(nullptr, 0);
    }

    std::pair<uint8_t*, size_t> converted = toBytes(block->data, block->len);
    if (!converted.first || converted.second == 0) {
        return std::make_pair(nullptr, 0);
    }

    char* b64 = base64_encode(converted.first, converted.second);

    // Clean up temporary buffer
    secure_memzero(converted.first, converted.second);
    free(converted.first);

    if (!b64) {
        return std::make_pair(nullptr, 0);
    }

    return std::make_pair(b64, strlen(b64) + 1);
}

/**
 * Export OES_BLOCK to hexadecimal string
 *
 * @param block OES_BLOCK to export
 * @return Pair of (Hex string, length including null terminator) - caller must free
 */
std::pair<char*, size_t> oes_export_block_to_hex_string(OES_BLOCK block) {
    if (!block || !block->data || block->len == 0) {
        return std::make_pair(nullptr, 0);
    }

    // Calculate output length: 2 hex chars per byte + null terminator
    size_t outLen = 2 * OES_BYTES_X_BLOCK * block->len + 1;

    auto output = static_cast<char*>(malloc(outLen * sizeof(char)));
    if (!output) {
        return std::make_pair(nullptr, 0);
    }

    char* ptr = output;

    // Convert each m_block to hex string
    for (size_t i = 0; i < block->len; i++) {
#if OES_LOGIC_BLOCK_SIZE == 32
        int written = snprintf(ptr, outLen - (ptr - output), "%08x",
                              static_cast<uint32_t>(block->data[i]));
#elif OES_LOGIC_BLOCK_SIZE == 64
        int written = snprintf(ptr, outLen - (ptr - output), "%016lx",
                              static_cast<uint64_t>(block->data[i]));
#else
        // Generic implementation for arbitrary sizes
        int written = snprintf(ptr, outLen - (ptr - output), "%0*lx",
                              static_cast<int>(2 * OES_BYTES_X_BLOCK),
                              static_cast<unsigned long>(block->data[i]));
#endif

        if (written < 0 || written >= static_cast<int>(outLen - (ptr - output))) {
            // Overflow or error
            free(output);
            return std::make_pair(nullptr, 0);
        }

        ptr += written;
    }

    *ptr = '\0';

    return std::make_pair(output, outLen);
}

/**
 * Dump OES_BLOCK contents to stdout
 *
 * @param block OES_BLOCK to dump
 * @param printable If true, show printable representation
 */
void oes_block_dump(OES_BLOCK block, bool printable) {
    if (!block || !block->data || block->len == 0) {
        printf("(null or empty block)\n");
        return;
    }

    mBlock_dump(block->data, block->len, printable);
}

/**
 * Create OES_BLOCK from hex string
 *
 * @param hexString Hexadecimal string
 * @return OES_BLOCK structure (caller must free with unset_block)
 */
OES_BLOCK oes_import_block_from_hex_string(const char* hexString) {
    if (!hexString) {
        return nullptr;
    }

    size_t hexLen = strlen(hexString);
    if (hexLen == 0 || hexLen % (2 * OES_BYTES_X_BLOCK) != 0) {
        return nullptr;
    }

    size_t blockCount = hexLen / (2 * OES_BYTES_X_BLOCK);

    auto block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!block) {
        return nullptr;
    }

    block->data = static_cast<m_block*>(malloc(blockCount * sizeof(m_block)));
    if (!block->data) {
        free(block);
        return nullptr;
    }

    block->len = blockCount;

    // Parse hex string into m_blocks
    for (size_t i = 0; i < blockCount; i++) {
        const char* hexBlock = hexString + i * (2 * OES_BYTES_X_BLOCK);

#if OES_LOGIC_BLOCK_SIZE == 32
        if (sscanf(hexBlock, "%8x", reinterpret_cast<uint32_t*>(&block->data[i])) != 1) {
#elif OES_LOGIC_BLOCK_SIZE == 64
        if (sscanf(hexBlock, "%16lx", reinterpret_cast<uint64_t*>(&block->data[i])) != 1) {
#else
        char fmt[16];
        snprintf(fmt, sizeof(fmt), "%%%dlx", static_cast<int>(2 * OES_BYTES_X_BLOCK));
        if (sscanf(hexBlock, fmt, reinterpret_cast<unsigned long*>(&block->data[i])) != 1) {
#endif
            free(block->data);
            free(block);
            return nullptr;
        }
    }

    return block;
}

/**
 * Create OES_BLOCK from Base64 string
 *
 * @param base64String Base64-encoded string
 * @return OES_BLOCK structure (caller must free with unset_block)
 */
OES_BLOCK oes_import_block_from_base64(const char* base64String) {
    if (!base64String) {
        return nullptr;
    }

    size_t decodedLen = 0;
    uint8_t* decoded = base64_decode(base64String, strlen(base64String), &decodedLen);
    if (!decoded || decodedLen == 0) {
        return nullptr;
    }

    OES_BLOCK block = toOESBlock(decoded, decodedLen);

    // Clean up temporary buffer
    secure_memzero(decoded, decodedLen);
    free(decoded);

    return block;
}

/**
 * Clone an OES_BLOCK
 *
 * @param src Source block
 * @return Cloned block (caller must free with unset_block)
 */
OES_BLOCK oes_block_clone(OES_BLOCK src) {
    if (!src || !src->data || src->len == 0) {
        return nullptr;
    }

    auto block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!block) {
        return nullptr;
    }

    block->data = mBlock_clone(nullptr, src->data, src->len);
    if (!block->data) {
        free(block);
        return nullptr;
    }

    block->len = src->len;

    return block;
}

/**
 * Compare two OES_BLOCKs
 *
 * @param a First block
 * @param b Second block
 * @return true if blocks are equal, false otherwise
 */
bool oes_block_compare(OES_BLOCK a, OES_BLOCK b) {
    if (!a || !b) {
        return a == b; // Both null = equal
    }

    if (a->len != b->len) {
        return false;
    }

    return std::memcmp(a->data, b->data, a->len * sizeof(m_block)) == 0;
}