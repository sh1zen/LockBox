#include <cstdio>
#include <cstdlib>
#include <utility>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/support/base64/base64.h>
#include "interface.h"
#include "support.h"


std::pair<void *, size_t> exportBlock(MBLOCK *block, int mode) {
    if (!block || block->isNull()) {
        return std::make_pair(nullptr, 0);
    }

    switch (mode) {
        case OES_EXPORT_HEX: {
            auto [fst, snd] = oes_export_block_to_hex_string(block);
            return std::make_pair(fst, snd);
        }

        case OES_EXPORT_UINT8: {
            auto [fst, snd] = block->toBytes();
            return std::make_pair(fst, snd);
        }

        case OES_EXPORT_CHAR: {
            auto [fst, snd] = oes_export_block_to_string(block);
            return std::make_pair(fst, snd);
        }

        case OES_EXPORT_BASE64: {
            auto [fst, snd] = oes_export_block_to_base64(block);
            return std::make_pair(fst, snd);
        }

        case OES_EXPORT_RAW:
        default: {
            size_t blockLen = block->getLen();
            auto *copy = static_cast<m_block *>(malloc(blockLen * sizeof(m_block)));
            if (!copy) {
                return std::make_pair(nullptr, 0);
            }
            for (size_t i = 0; i < blockLen; i++) {
                copy[i] = block->getBlock(i);
            }
            return std::make_pair(copy, blockLen);
        }
    }
}

/**
 * Export OES_BLOCK to null-terminated string
 *
 * @param block OES_BLOCK to export
 * @return Pair of (null-terminated string, length including null terminator) - caller must free
 */
std::pair<char *, size_t> oes_export_block_to_string(MBLOCK *block) {
    if (!block || block->isNull()) {
        return std::make_pair(nullptr, 0);
    }

    // Converti senza byte extra
    auto [raw_bytes, raw_len] = block->toBytes();
    if (!raw_bytes || raw_len == 0) {
        return std::make_pair(nullptr, 0);
    }

    // Alloca nuova memoria con spazio per il null terminator
    size_t total_size = raw_len + 1;
    auto result = static_cast<char*>(malloc(total_size * sizeof(char)));
    if (!result) {
        secure_memzero(raw_bytes, raw_len);
        free(raw_bytes);
        return std::make_pair(nullptr, 0);
    }

    // Copia i dati e aggiungi null terminator
    memcpy(result, raw_bytes, raw_len);
    result[raw_len] = '\0';

    // Pulisci il buffer temporaneo
    secure_memzero(raw_bytes, raw_len);
    free(raw_bytes);

    return std::make_pair(result, total_size);
}

/**
 * Export OES_BLOCK to Base64-encoded string
 *
 * @param block OES_BLOCK to export
 * @return Pair of (Base64 string, length including null terminator) - caller must free
 */
std::pair<char *, size_t> oes_export_block_to_base64(MBLOCK *block) {
    if (block->isNull()) {
        return std::make_pair(nullptr, 0);
    }

    std::pair<uint8_t *, size_t> converted = block->toBytes();
    if (!converted.first || converted.second == 0) {
        return std::make_pair(nullptr, 0);
    }

    char *b64 = base64_encode(converted.first, converted.second);

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
std::pair<char *, size_t> oes_export_block_to_hex_string(MBLOCK *block) {
    if (block->isNull()) {
        return std::make_pair(nullptr, 0);
    }

    // Calculate output length: 2 hex chars per byte + null terminator
    size_t outLen = 2 * OES_BYTES_X_BLOCK * block->getLen() + 1;

    auto output = static_cast<char *>(malloc(outLen * sizeof(char)));
    if (!output) {
        return std::make_pair(nullptr, 0);
    }

    char *ptr = output;

    // Convert each m_block to hex string
    for (size_t i = 0; i < block->getLen(); i++) {
#if OES_LOGIC_BLOCK_SIZE == 32
        int written = snprintf(ptr, outLen - (ptr - output), "%08x", static_cast<uint32_t>(block->getBlock(i)));
#elif OES_LOGIC_BLOCK_SIZE == 64
        int written = snprintf(ptr, outLen - (ptr - output), "%016lx", static_cast<uint64_t>(block->getBlock(i)));
#else
        // Generic implementation for arbitrary sizes
        int written = snprintf(ptr, outLen - (ptr - output), "%0*lx",
                               static_cast<int>(2 * OES_BYTES_X_BLOCK),
                               static_cast<unsigned long>(block->getBlock(i)));
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
 * Create OES_BLOCK from hex string
 *
 * @param hexString Hexadecimal string
 * @return OES_BLOCK structure (caller must free with unset_block)
 */
MBLOCK *oes_import_block_from_hex_string(const char *hexString) {
    if (!hexString) {
        return nullptr;
    }

    size_t hexLen = strlen(hexString);
    if (hexLen == 0 || hexLen % (2 * OES_BYTES_X_BLOCK) != 0) {
        return nullptr;
    }

    size_t blockCount = hexLen / (2 * OES_BYTES_X_BLOCK);

    auto data = new m_block[blockCount];

    // Parse hex string into m_blocks
    for (size_t i = 0; i < blockCount; i++) {
        const char *hexBlock = hexString + i * (2 * OES_BYTES_X_BLOCK);

#if OES_LOGIC_BLOCK_SIZE == 32
        if (sscanf(hexBlock, "%8x", reinterpret_cast<uint32_t *>(&data[i])) != 1) {
#elif OES_LOGIC_BLOCK_SIZE == 64
            if (sscanf(hexBlock, "%16lx", reinterpret_cast<uint64_t *>(&data[i])) != 1) {
#else
            char fmt[16];
            snprintf(fmt, sizeof(fmt), "%%%dlx", static_cast<int>(2 * OES_BYTES_X_BLOCK));
            if (sscanf(hexBlock, fmt, reinterpret_cast<unsigned long *>(&data[i])) != 1) {
#endif
            delete[] data;
            return nullptr;
        }
    }

    // Create MBLOCK with ownership transfer (no copy)
    auto block = new MBLOCK(data, blockCount, true);

    return block;
}


/**
 * Create OES_BLOCK from Base64 string
 *
 * @param base64String Base64-encoded string
 * @return OES_BLOCK structure (caller must free with unset_block)
 */
MBLOCK *oes_import_block_from_base64(const char *base64String) {
    if (!base64String) {
        return nullptr;
    }

    size_t decodedLen = 0;
    uint8_t *decoded = base64_decode(base64String, strlen(base64String), &decodedLen);
    if (!decoded || decodedLen == 0) {
        return nullptr;
    }

    // Use MBLOCK::fromBytes to convert byte array to MBLOCK
    MBLOCK *block = MBLOCK::fromBytes(decoded, decodedLen);

    // Clean up temporary buffer
    secure_memzero(decoded, decodedLen);
    free(decoded);

    return block;
}
