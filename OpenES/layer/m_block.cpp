#include <OpenES/support/oes-exception.h>
#include "m_block.h"
#include "oesMath.h"
#include "raw-layer.h"
#include "support.h"

// ========== ROTAZIONE VETTORE DI BLOCCHI ==========

void MBLOCK::rotl(size_t i) {
    if (len == 0 || i == 0) return;
    i %= len;
    if (i == 0) return;

    reverse_range(data, data + i);
    reverse_range(data + i, data + len);
    reverse_range(data, data + len);
}

void MBLOCK::rotr(size_t i) {
    if (len == 0 || i == 0) return;
    i %= len;
    if (i == 0) return;

    reverse_range(data, data + len);
    reverse_range(data, data + i);
    reverse_range(data + i, data + len);
}

// ========== OPERAZIONI XOR ==========

void MBLOCK::xor_with(const MBLOCK &other, bool alternate) {
    const size_t n = (len < other.len) ? len : other.len;
    m_block *__restrict dst = data;
    const m_block *__restrict src = other.data;

    if (!alternate) {
        // Fast path: XOR su tutti gli elementi
        for (size_t i = 0; i < n; ++i)
            dst[i] ^= src[i];
    } else {
        // Fast path alternate: solo indici pari, NO modulo
        for (size_t i = 0; i < n; i += 2) {
            dst[i] ^= src[i];
        }
    }
}

// ========== BIT MANIPULATION ==========

void MBLOCK::toggleBit(size_t pos, int bitN) {
    if (pos < len) {
        data[pos] ^= static_cast<m_block>(MASK_TO_BLOCK_SIZE(0x00000000, 0x00000001)) << bitN;
    }
}

// ========== PADDING ==========

MBLOCK *MBLOCK::add_padding_outer(size_t outLen, m_block pad) const {
    auto *padded = new m_block[outLen];

    // Copia iniziale
    std::memcpy(padded, data, len * sizeof(m_block));

    // Padding
    if (outLen > len) {
        std::fill(padded + len, padded + outLen - 1, pad);
        padded[outLen - 1] = static_cast<m_block>(len);
    }

    // Nessuna copia: ownership diretto
    return new MBLOCK(padded, outLen, true);
}

// Get padding length
size_t MBLOCK::get_padding_size_outer() const {
    if (!data || len == 0) {
        return 0;
    }
    return len - data[len - 1];
}

size_t MBLOCK::getBytesLen() const {
    return this->len * OES_BYTES_X_BLOCK - mBlock_padding_size(data[len - 1], 0);
}

void MBLOCK::dump(bool printable) const {
    // Use our own toBytes_raw method instead of external function
    std::pair<uint8_t *, size_t> converted = toBytes_raw(0);

    if (!converted.first) {
        puts("\n========= mBlock dump (empty) ===========");
        return;
    }

    puts("\n========= mBlock dump ===========");
    size_t chars = 0;
    for (size_t i = 0; i < converted.second; i++) {

        if (i && i % OES_BYTES_X_BLOCK == 0) {
            printf("|");
            chars++;

            if (chars + OES_BYTES_X_BLOCK * 2 > 90) {
                puts("");
                chars = 0;
            }
        }

        printf("%02x", converted.first[i]);
        chars += 2;
    }

    if (printable) {
        puts("");

        for (size_t i = 0; i < converted.second - mBlock_padding_size(this->data[this->len - 1], 0); i++) {
            printf("%c", converted.first[i]);
        }
    }

    delete[] converted.first;

    puts("");
}

// ========== BLOCK ACCESS ==========

bool MBLOCK::setBlock(size_t pos, m_block value) {
    if (pos >= len || !data) {
        return false;
    }
    data[pos] = value;
    return true;
}

m_block MBLOCK::getBlock(size_t pos) const {
    if (pos >= len || !data) {
        return 0;
    }
    return data[pos];
}

// ========== MEMORY MANAGEMENT ==========

MBLOCK *MBLOCK::create(size_t len, m_block value) {
    if (len == 0)
        return nullptr;

    auto *data = new m_block[len];

    if (value == 0) {
        std::memset(data, 0, len * sizeof(m_block));
    } else {
        for (size_t i = 0; i < len; ++i)
            data[i] = value;
    }

    return new MBLOCK(data, len, true);
}

MBLOCK *MBLOCK::concat(const MBLOCK &a, const MBLOCK &b) {
    if (!a.data || !b.data || a.len == 0 || b.len == 0)
        return nullptr;

    const size_t total_len = a.len + b.len;

    auto *data = new m_block[total_len];

    std::memcpy(data, a.data, a.len * sizeof(m_block));
    std::memcpy(data + a.len, b.data, b.len * sizeof(m_block));

    return new MBLOCK(data, total_len, true);
}

void MBLOCK::extend(size_t new_len, m_block fill) {
    if (new_len == len)
        return;

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
        this->len = new_len;
        return;
    }

    auto *new_data = new m_block[new_len];

    if (data) {
        std::memcpy(new_data, data, len * sizeof(m_block));
    }

    const size_t delta = new_len - len;

    if (fill == 0) {
        std::memset(new_data + len, 0, delta * sizeof(m_block));
    } else {
        for (size_t i = len; i < new_len; ++i)
            new_data[i] = fill;
    }

    if (data) {
        secure_zero();
        delete[] data;
    }

    data = new_data;
    len = new_len;
}


void MBLOCK::secure_zero() {
    if (data && len > 0) {
        secure_memzero(data, len * sizeof(m_block));
    }
}

// ========== CONVERSION METHODS ==========

MBLOCK *MBLOCK::fromBytes(const void *src, size_t nByte) {
    if (!src || nByte == 0)
        return nullptr;

    size_t blocks = calcPairsOfSize(nByte, OES_BYTES_X_BLOCK);

    // Extra block per padding se allineato
    if (nByte % OES_BYTES_X_BLOCK == 0)
        ++blocks;

    auto *out = new m_block[blocks];

    // Inizializzazione a zero (fondamentale per gli shift)
    std::memset(out, 0, blocks * sizeof(m_block));

    const auto *bytes = static_cast<const uint8_t *>(src);
    size_t pos = 0;

    // Pack big-endian
    for (size_t i = 0; i < nByte; ++i) {
        out[pos] = (out[pos] << 8) | bytes[i];

        if ((i + 1) % OES_BYTES_X_BLOCK == 0)
            ++pos;
    }

    // Padding finale
    if (nByte % OES_BYTES_X_BLOCK) {
        const uint8_t padding = requestedPadding(nByte, OES_BYTES_X_BLOCK);
        out[pos] = (out[pos] << (padding * 8)) | padding;
    } else {
        out[blocks - 1] = static_cast<m_block>(OES_BYTES_X_BLOCK);
    }

    // Ownership diretto, NESSUN delete[]
    return new MBLOCK(out, blocks, true);
}


std::pair<uint8_t *, size_t> MBLOCK::toBytes_raw(size_t extraSize) const {
    if (!data || len == 0) {
        return std::make_pair(nullptr, 0);
    }

    size_t outLen = OES_BYTES_X_BLOCK * len + extraSize;

    auto converted = new uint8_t[outLen]();

    // Unpack m_blocks to bytes (big-endian)
    for (size_t i = 0; i < len; i++) {
        const size_t pos = i * OES_BYTES_X_BLOCK;

#if OES_LOGIC_BLOCK_SIZE == 16
        converted[pos + 0] = (data[i] >> 8) & 0xFF;
        converted[pos + 1] = data[i] & 0xFF;
#elif OES_LOGIC_BLOCK_SIZE == 32
        converted[pos + 0] = (data[i] >> 24) & 0xFF;
        converted[pos + 1] = (data[i] >> 16) & 0xFF;
        converted[pos + 2] = (data[i] >> 8) & 0xFF;
        converted[pos + 3] = data[i] & 0xFF;
#elif OES_LOGIC_BLOCK_SIZE == 64
        converted[pos + 0] = (data[i] >> 56) & 0xFF;
        converted[pos + 1] = (data[i] >> 48) & 0xFF;
        converted[pos + 2] = (data[i] >> 40) & 0xFF;
        converted[pos + 3] = (data[i] >> 32) & 0xFF;
        converted[pos + 4] = (data[i] >> 24) & 0xFF;
        converted[pos + 5] = (data[i] >> 16) & 0xFF;
        converted[pos + 6] = (data[i] >> 8) & 0xFF;
        converted[pos + 7] = data[i] & 0xFF;
#else
        // Generic implementation for arbitrary block sizes
        for (size_t j = 0; j < OES_BYTES_X_BLOCK; j++) {
            converted[pos + j] = (data[i] >> (8 * (OES_BYTES_X_BLOCK - 1 - j))) & 0xFF;
        }
#endif
    }

    return std::make_pair(converted, outLen);
}

std::pair<uint8_t *, size_t> MBLOCK::toBytes() const {
    if (!data || len == 0) {
        return std::make_pair(nullptr, 0);
    }

    // Get raw bytes first
    auto [raw_bytes, raw_len] = this->toBytes_raw(0);
    if (!raw_bytes) {
        return std::make_pair(nullptr, 0);
    }

    // Calculate and remove internal padding
    size_t mBlockPadding = mBlock_padding_size(data[len - 1], 0);

    return std::make_pair(raw_bytes, raw_len - mBlockPadding);
}
