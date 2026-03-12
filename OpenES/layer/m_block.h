#pragma once

#include <cstring>
#include <utility>

#include "defines.h"

// ============================================================================
//  TYPE DEFINITIONS
// ============================================================================

#if OES_LOGIC_BLOCK_SIZE <= 8
    __extension__ typedef uint8_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 16
    __extension__ typedef uint16_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 32
    __extension__ typedef uint32_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 64
    __extension__ typedef uint64_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 128
#ifdef _MSC_VER
    typedef __uint128_t_msvc m_block;
#else
    __extension__ typedef __uint128_t m_block;
#endif
#endif

// ============================================================================
//  CLASS DEFINITION
// ============================================================================

class MBLOCK {
protected:
    m_block *data;
    size_t len;

public:
    // ======================================================================
    //  LIFECYCLE MANAGEMENT
    // ======================================================================

    MBLOCK() : data(nullptr), len(0) {
    }

    explicit MBLOCK(size_t l) : data(nullptr), len(l) {
        if (l > 0) {
            data = new m_block[l]();
        }
    }

    MBLOCK(m_block *d, size_t l, bool takeOwnership = false)
        : data(nullptr), len(l) {
        if (takeOwnership) {
            data = d;
        } else {
            data = new m_block[l];
            std::memcpy(data, d, l * sizeof(m_block));
        }
    }

    ~MBLOCK() {
        if (data) {
            secure_zero();
            delete[] data;
        }
    }

    // ======================================================================
    //  COPY / MOVE SEMANTICS
    // ======================================================================

    MBLOCK(const MBLOCK &) = delete;

    MBLOCK &operator=(const MBLOCK &) = delete;

    MBLOCK(MBLOCK &&other) noexcept
        : data(other.data), len(other.len) {
        other.data = nullptr;
        other.len = 0;
    }

    MBLOCK &operator=(MBLOCK &&other) noexcept {
        if (this != &other) {
            if (data) {
                secure_zero();
                delete[] data;
            }
            data = other.data;
            len = other.len;
            other.data = nullptr;
            other.len = 0;
        }
        return *this;
    }

    [[nodiscard]] MBLOCK *clone() const {
        auto *data_copy = new m_block[len];
        std::memcpy(data_copy, data, len * sizeof(m_block));
        return new MBLOCK(data_copy, len, true);
    }

    // ======================================================================
    //  STATE & BASIC ACCESS
    // ======================================================================

    [[nodiscard]] bool isNull() const {
        return data == nullptr && len == 0;
    }

    static MBLOCK null() {
        return {};
    }

    [[nodiscard]] size_t getLen() const {
        return len;
    }

    [[nodiscard]] size_t getBytesLen() const;

    [[nodiscard]] m_block *getData() const {
        auto *out = new m_block[len];
        std::memcpy(out, data, len * sizeof(m_block));
        return out;
    }

    [[nodiscard]] m_block *&getDataRef() {
        return data;
    }

    // ======================================================================
    //  DATA UPDATE & MEMORY CONTROL
    // ======================================================================

    /**
     * Update block with new data transferring ownership.
     * If data is nullptr, the block is cleared but still allocated.
     */
    void update(m_block *newData, size_t newLen) {
        if (data) {
            secure_zero();
            delete[] data;
        }
        data = newData;
        len = newLen;
    }

    void extend(size_t new_len, m_block fill);

    void secure_zero() const;

    // ======================================================================
    //  ELEMENT / BLOCK ACCESS
    // ======================================================================

    [[nodiscard]] bool setBlock(size_t pos, m_block value) const;

    [[nodiscard]] m_block getBlock(size_t pos) const;

    m_block &operator[](size_t i) {
        return data[i];
    }

    const m_block &operator[](size_t i) const {
        return data[i];
    }

    // ======================================================================
    //  BLOCK OPERATIONS
    // ======================================================================

    void xor_with(const MBLOCK &other, bool alternate = false) const;

    // ======================================================================
    //  ROTATIONS
    // ======================================================================

    void rotr(size_t i) const;

    void rotl(size_t i) const;

    // ======================================================================
    //  BIT MANIPULATION
    // ======================================================================

    void toggleBit(size_t pos, int bitN) const;

    // ======================================================================
    //  PADDING
    // ======================================================================

    [[nodiscard]] MBLOCK *add_padding_outer(size_t outLen, m_block pad) const;

    [[nodiscard]] size_t get_padding_size_outer() const;

    // ======================================================================
    //  FACTORIES & COMPOSITION
    // ======================================================================

    static MBLOCK *create(size_t len, m_block value = 0);

    static MBLOCK *concat(const MBLOCK &a, const MBLOCK &b);

    // ======================================================================
    //  BYTE CONVERSIONS
    // ======================================================================

    // Conversione da bytes CON padding (per plaintext)
    static MBLOCK *fromBytes(const void *src, size_t nByte);

    // Conversione da bytes SENZA padding (per ciphertext)
    static MBLOCK *fromBytes_raw(const void *src, size_t nByte);

    [[nodiscard]] std::pair<uint8_t *, size_t>
    toBytes_raw(size_t extraSize = 0) const;

    [[nodiscard]] std::pair<uint8_t *, size_t>
    toBytes() const;

    // ======================================================================
    //  DEBUG / UTILITIES
    // ======================================================================
    void dump(bool printable = false) const;
};
