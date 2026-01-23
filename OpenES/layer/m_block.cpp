#include <OpenES/support/oes-exception.h>
#include "m_block.h"
#include "raw-layer.h"
#include "support.h"

// ========== ROTAZIONE VETTORE DI BLOCCHI ==========
void MBLOCK::rotl(size_t i) const {
    if (len <= 1 || i == 0) return;
    i %= len;
    if (i == 0) return;

    mBlock::reverse_range(data, data + i);
    mBlock::reverse_range(data + i, data + len);
    mBlock::reverse_range(data, data + len);
}

void MBLOCK::rotr(size_t i) const {
    if (len <= 1 || i == 0) return;
    i %= len;
    if (i == 0) return;
    rotl(len - i); // Riusa rotl invece di duplicare logica
}

// ========== OPERAZIONI XOR ==========

void MBLOCK::xor_with(const MBLOCK &other, bool alternate) const {
    const size_t n = (len < other.len) ? len : other.len;
    if (n == 0) return;

    m_block *__restrict dst = data;
    const m_block *__restrict src = other.data;

    if (alternate) {
        for (size_t i = 0; i < n; i += 2)
            dst[i] ^= src[i];
    } else {
        for (size_t i = 0; i < n; ++i)
            dst[i] ^= src[i];
    }
}

// ========== BIT MANIPULATION ==========

void MBLOCK::toggleBit(size_t pos, int bitN) const {
    if (pos < len && bitN >= 0 && bitN < OES_LOGIC_BLOCK_SIZE) {
        data[pos] ^= static_cast<m_block>(1) << bitN;
    }
}

// ========== PADDING ==========

MBLOCK *MBLOCK::add_padding_outer(size_t outLen, m_block pad) const {
    if (outLen == 0) return nullptr;
    if (outLen <= len) return new MBLOCK(data, len, false); // shallow copy se non serve padding

    auto *padded = new m_block[outLen];

    if (len > 0) {
        std::memcpy(padded, data, len * sizeof(m_block));
    }

    std::fill(padded + len, padded + outLen - 1, pad);
    padded[outLen - 1] = static_cast<m_block>(len);

    return new MBLOCK(padded, outLen, true);
}

size_t MBLOCK::get_padding_size_outer() const {
    if (!data || len == 0) return 0;

    const auto stored_len = static_cast<size_t>(data[len - 1]);
    if (stored_len > len) {
        throw OESException("Wrong padding size");
    }
    return len - stored_len;
}

size_t MBLOCK::getBytesLen() const {
    if (!data || len == 0) return 0;
    return len * OES_BYTES_X_BLOCK - mBlock::padding_size(data[len - 1], 0);
}

void MBLOCK::dump(bool printable) const {
    if (!data || len == 0) {
        puts("\n========= mBlock dump (empty) ===========");
        return;
    }

    auto [bytes, bytesLen] = toBytes_raw(0);
    if (!bytes) {
        puts("\n========= mBlock dump (empty) ===========");
        return;
    }

    puts("\n========= mBlock dump ===========");
    size_t chars = 0;
    for (size_t i = 0; i < bytesLen; i++) {
        if (i && i % OES_BYTES_X_BLOCK == 0) {
            putchar('|');
            chars++;
            if (chars + OES_BYTES_X_BLOCK * 2 > 90) {
                putchar('\n');
                chars = 0;
            }
        }
        printf("%02x", bytes[i]);
        chars += 2;
    }

    if (printable) {
        putchar('\n');
        const size_t printLen = bytesLen - mBlock::padding_size(data[len - 1], 0);
        for (size_t i = 0; i < printLen; i++) {
            putchar(static_cast<char>(bytes[i]));
        }
    }

    delete[] bytes;
    putchar('\n');
}

// ========== BLOCK ACCESS ==========

bool MBLOCK::setBlock(size_t pos, m_block value) const {
    if (pos >= len || !data) return false;
    data[pos] = value;
    return true;
}

m_block MBLOCK::getBlock(size_t pos) const {
    if (pos >= len || !data) return 0;
    return data[pos];
}

// ========== MEMORY MANAGEMENT ==========

MBLOCK *MBLOCK::create(size_t len, m_block value) {
    if (len == 0) return nullptr;

    auto *d = new m_block[len];

    if (value == 0) {
        std::memset(d, 0, len * sizeof(m_block));
    } else {
        std::fill_n(d, len, value);
    }

    return new MBLOCK(d, len, true);
}

MBLOCK *MBLOCK::concat(const MBLOCK &a, const MBLOCK &b) {
    if (a.len == 0 && b.len == 0) return nullptr;

    // Gestisce casi con un solo array valido
    if (!a.data || a.len == 0) {
        auto *d = new m_block[b.len];
        std::memcpy(d, b.data, b.len * sizeof(m_block));
        return new MBLOCK(d, b.len, true);
    }
    if (!b.data || b.len == 0) {
        auto *d = new m_block[a.len];
        std::memcpy(d, a.data, a.len * sizeof(m_block));
        return new MBLOCK(d, a.len, true);
    }

    const size_t total = a.len + b.len;
    auto *d = new m_block[total];

    std::memcpy(d, a.data, a.len * sizeof(m_block));
    std::memcpy(d + a.len, b.data, b.len * sizeof(m_block));

    return new MBLOCK(d, total, true);
}

void MBLOCK::extend(size_t new_len, m_block fill) {
    if (new_len == len) return;

    if (new_len == 0) {
        if (data) {
            secure_zero();
            delete[] data;
            data = nullptr;
            len = 0;
        }
        return;
    }

    if (new_len < len) {
        // Azzera memoria oltre new_len prima di ridurre
        if (data) {
            secure_memzero(data + new_len, (len - new_len) * sizeof(m_block));
        }
        len = new_len;
        return;
    }

    auto *new_data = new m_block[new_len];
    const size_t old_bytes = len * sizeof(m_block);

    if (data && len > 0) {
        std::memcpy(new_data, data, old_bytes);
    }

    // Riempi nuova area
    if (fill == 0) {
        std::memset(new_data + len, 0, (new_len - len) * sizeof(m_block));
    } else {
        std::fill(new_data + len, new_data + new_len, fill);
    }

    if (data) {
        secure_zero();
        delete[] data;
    }

    data = new_data;
    len = new_len;
}

void MBLOCK::secure_zero() const {
    if (data && len > 0) {
        secure_memzero(data, len * sizeof(m_block));
    }
}

// ========== CONVERSION METHODS ==========
__attribute__((noinline))
MBLOCK *MBLOCK::fromBytes(const void *src, const size_t nByte) {
    if (!src || nByte == 0) return nullptr;

    const size_t baseBlocks = (nByte + OES_BYTES_X_BLOCK - 1) / OES_BYTES_X_BLOCK;
    const size_t blocks = (nByte % OES_BYTES_X_BLOCK == 0) ? baseBlocks + 1 : baseBlocks;

    auto *out = new m_block[blocks](); // Zero-initialized

    const auto *bytes = static_cast<const uint8_t *>(src);
    size_t pos = 0;

    for (size_t i = 0; i < nByte; ++i) {
        out[pos] = (out[pos] << 8) | bytes[i];
        if ((i + 1) % OES_BYTES_X_BLOCK == 0) ++pos;
    }

    if (const size_t remainder = nByte % OES_BYTES_X_BLOCK) {
        const auto padding = static_cast<uint8_t>(OES_BYTES_X_BLOCK - remainder);
        out[pos] = (out[pos] << (padding * 8)) | padding;
    } else {
        out[blocks - 1] = static_cast<m_block>(OES_BYTES_X_BLOCK);
    }

    return new MBLOCK(out, blocks, true);
}

__attribute__((noinline))
MBLOCK *MBLOCK::fromBytes_raw(const void *src, const size_t nByte) {
    if (!src || nByte == 0) return nullptr;

    // I dati cifrati DEVONO essere multiplo della dimensione del blocco
    if (nByte % OES_BYTES_X_BLOCK != 0) {
        return nullptr;
    }

    const size_t blocks = nByte / OES_BYTES_X_BLOCK;
    auto *out = new(std::nothrow) m_block[blocks]();
    if (!out) return nullptr;

    const auto *bytes = static_cast<const uint8_t *>(src);

    for (size_t i = 0; i < blocks; ++i) {
        const size_t pos = i * OES_BYTES_X_BLOCK;
        m_block block = 0;

#if OES_BYTES_X_BLOCK == 1
        block = bytes[pos];

#elif OES_BYTES_X_BLOCK == 2
        block = (static_cast<m_block>(bytes[pos]) << 8) |
                static_cast<m_block>(bytes[pos + 1]);

#elif OES_BYTES_X_BLOCK == 4
        block = (static_cast<m_block>(bytes[pos]) << 24) |
                (static_cast<m_block>(bytes[pos + 1]) << 16) |
                (static_cast<m_block>(bytes[pos + 2]) << 8) |
                static_cast<m_block>(bytes[pos + 3]);

#elif OES_BYTES_X_BLOCK == 8
        block = (static_cast<m_block>(bytes[pos]) << 56) |
                (static_cast<m_block>(bytes[pos + 1]) << 48) |
                (static_cast<m_block>(bytes[pos + 2]) << 40) |
                (static_cast<m_block>(bytes[pos + 3]) << 32) |
                (static_cast<m_block>(bytes[pos + 4]) << 24) |
                (static_cast<m_block>(bytes[pos + 5]) << 16) |
                (static_cast<m_block>(bytes[pos + 6]) << 8) |
                static_cast<m_block>(bytes[pos + 7]);

#elif OES_BYTES_X_BLOCK == 16
        // Per __uint128_t: costruisci dalle due metà (big-endian)
        uint64_t high = 0, low = 0;
        high = (static_cast<uint64_t>(bytes[pos]) << 56) |
               (static_cast<uint64_t>(bytes[pos + 1]) << 48) |
               (static_cast<uint64_t>(bytes[pos + 2]) << 40) |
               (static_cast<uint64_t>(bytes[pos + 3]) << 32) |
               (static_cast<uint64_t>(bytes[pos + 4]) << 24) |
               (static_cast<uint64_t>(bytes[pos + 5]) << 16) |
               (static_cast<uint64_t>(bytes[pos + 6]) << 8) |
               static_cast<uint64_t>(bytes[pos + 7]);
        low = (static_cast<uint64_t>(bytes[pos + 8]) << 56) |
              (static_cast<uint64_t>(bytes[pos + 9]) << 48) |
              (static_cast<uint64_t>(bytes[pos + 10]) << 40) |
              (static_cast<uint64_t>(bytes[pos + 11]) << 32) |
              (static_cast<uint64_t>(bytes[pos + 12]) << 24) |
              (static_cast<uint64_t>(bytes[pos + 13]) << 16) |
              (static_cast<uint64_t>(bytes[pos + 14]) << 8) |
              static_cast<uint64_t>(bytes[pos + 15]);
        block = (static_cast<m_block>(high) << 64) | static_cast<m_block>(low);

#else
        // Fallback generico (non raccomandato per tipi > 64 bit)
        for (size_t j = 0; j < OES_BYTES_X_BLOCK; j++) {
            block = (block << 8) | static_cast<m_block>(bytes[pos + j]);
        }
#endif
        out[i] = block;
    }

    auto *result = new(std::nothrow) MBLOCK(out, blocks, true);
    if (!result) {
        delete[] out;
        return nullptr;
    }
    return result;
}

__attribute__((noinline))
std::pair<uint8_t *, size_t> MBLOCK::toBytes_raw(const size_t extraSize) const {
    if (!data || len == 0) return {nullptr, 0};

    const size_t outLen = OES_BYTES_X_BLOCK * len + extraSize;
    auto *converted = new(std::nothrow) uint8_t[outLen]();
    if (!converted) return {nullptr, 0};

    for (size_t i = 0; i < len; i++) {
        const size_t pos = i * OES_BYTES_X_BLOCK;
        const m_block block = data[i];

#if OES_BYTES_X_BLOCK == 1
        converted[pos] = static_cast<uint8_t>(block);

#elif OES_BYTES_X_BLOCK == 2
        converted[pos] = static_cast<uint8_t>(block >> 8);
        converted[pos + 1] = static_cast<uint8_t>(block);

#elif OES_BYTES_X_BLOCK == 4
        converted[pos] = static_cast<uint8_t>(block >> 24);
        converted[pos + 1] = static_cast<uint8_t>(block >> 16);
        converted[pos + 2] = static_cast<uint8_t>(block >> 8);
        converted[pos + 3] = static_cast<uint8_t>(block);

#elif OES_BYTES_X_BLOCK == 8
        converted[pos] = static_cast<uint8_t>(block >> 56);
        converted[pos + 1] = static_cast<uint8_t>(block >> 48);
        converted[pos + 2] = static_cast<uint8_t>(block >> 40);
        converted[pos + 3] = static_cast<uint8_t>(block >> 32);
        converted[pos + 4] = static_cast<uint8_t>(block >> 24);
        converted[pos + 5] = static_cast<uint8_t>(block >> 16);
        converted[pos + 6] = static_cast<uint8_t>(block >> 8);
        converted[pos + 7] = static_cast<uint8_t>(block);

#elif OES_BYTES_X_BLOCK == 16
        // Per __uint128_t: estrai le due metà (big-endian)
        const auto high = static_cast<uint64_t>(block >> 64);
        const auto low = static_cast<uint64_t>(block);

        converted[pos] = static_cast<uint8_t>(high >> 56);
        converted[pos + 1] = static_cast<uint8_t>(high >> 48);
        converted[pos + 2] = static_cast<uint8_t>(high >> 40);
        converted[pos + 3] = static_cast<uint8_t>(high >> 32);
        converted[pos + 4] = static_cast<uint8_t>(high >> 24);
        converted[pos + 5] = static_cast<uint8_t>(high >> 16);
        converted[pos + 6] = static_cast<uint8_t>(high >> 8);
        converted[pos + 7] = static_cast<uint8_t>(high);
        converted[pos + 8] = static_cast<uint8_t>(low >> 56);
        converted[pos + 9] = static_cast<uint8_t>(low >> 48);
        converted[pos + 10] = static_cast<uint8_t>(low >> 40);
        converted[pos + 11] = static_cast<uint8_t>(low >> 32);
        converted[pos + 12] = static_cast<uint8_t>(low >> 24);
        converted[pos + 13] = static_cast<uint8_t>(low >> 16);
        converted[pos + 14] = static_cast<uint8_t>(low >> 8);
        converted[pos + 15] = static_cast<uint8_t>(low);

#else
        // Fallback generico
        for (size_t j = 0; j < OES_BYTES_X_BLOCK; j++) {
            converted[pos + j] = static_cast<uint8_t>(
                block >> (8 * (OES_BYTES_X_BLOCK - 1 - j))
            );
        }
#endif
    }

    return {converted, outLen};
}

__attribute__((noinline))
std::pair<uint8_t *, size_t> MBLOCK::toBytes() const {
    if (!data || len == 0) return {nullptr, 0};

    auto [raw_bytes, raw_len] = toBytes_raw(0);
    if (!raw_bytes) return {nullptr, 0};

    const size_t padding = mBlock::padding_size(data[len - 1], 0);
    return {raw_bytes, raw_len - padding};
}
