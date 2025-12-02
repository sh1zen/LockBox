#ifndef LOCKBOX_M_BLOCK_H
#define LOCKBOX_M_BLOCK_H

#include "defines.h"

#if OES_LOGIC_BLOCK_SIZE <= 16
__extension__ typedef uint16_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 32
__extension__ typedef uint32_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 64
__extension__ typedef uint64_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 128
__extension__ typedef __uint128_t m_block;
#endif

#include <cstring>

class MBLOCK {
protected:
    m_block *data;
    size_t len;
public:
    // Costruttore di default
    MBLOCK() : data(nullptr), len(0) {}

    // Costruttore con opzione per prendere ownership o copiare
    // Se takeOwnership = true, prende ownership del puntatore d
    // Se takeOwnership = false (default), copia i dati
    MBLOCK(m_block *d, size_t l, bool takeOwnership = false) : data(nullptr), len(l) {
        if (takeOwnership) {
            data = d; // prende ownership
        } else {
            data = new m_block[l]; // copia
            std::memcpy(data, d, l * sizeof(m_block));
        }
    }

    // Distruttore
    ~MBLOCK() {
        delete[] data;
    }

    // Disabilita copia per evitare double-free
    MBLOCK(const MBLOCK &) = delete;

    MBLOCK &operator=(const MBLOCK &) = delete;

    // Abilita move semantics
    MBLOCK(MBLOCK &&other) noexcept
        : data(other.data), len(other.len) {
        other.data = nullptr;
        other.len = 0;
    }

    MBLOCK &operator=(MBLOCK &&other) noexcept {
        if (this != &other) {
            delete[] data;
            data = other.data;
            len = other.len;
            other.data = nullptr;
            other.len = 0;
        }
        return *this;
    }

    // Clona l'oggetto: chiama new internamente
    [[nodiscard]] MBLOCK *clone() const {
        auto data_copy = new m_block[len];
        memcpy(data_copy, data, len * sizeof(m_block));
        auto *tmp = new MBLOCK(data_copy, len);
        delete[] data_copy;
        return tmp;
    }

    /**
    * Update block with new data transferring ownership
    * If data is nullptr, the block is cleared but still allocated
    */
    void update(m_block *data, size_t len) {
        if (!this->isNull()) {
            delete[] this->data;
        }
        // Take ownership of new data
        this->data = data;
        this->len = len;
    }

    // Controlla se è "null"
    [[nodiscard]] bool isNull() const {
        return data == nullptr && len == 0;
    }

    // Ritorna un blocco null statico
    static MBLOCK null() {
        return {};
    }

    // Getter
    [[nodiscard]] size_t getLen() const {
        return len;
    }

    [[nodiscard]] size_t getBytesLen() const;

    [[nodiscard]] m_block* getData() const {
        auto data = new m_block[len];
        memcpy(data, data, len * sizeof(m_block));
        return data;
    }

    // ========== BLOCK ACCESS ==========

    // Set a single block at specified position
    // Returns true if successful, false if position out of bounds
    bool setBlock(size_t pos, m_block value);

    // Get a single block at specified position
    // Returns the block value if successful, 0 if position out of bounds
    [[nodiscard]] m_block getBlock(size_t pos) const;

    // ========== ROTAZIONE VETTORE DI BLOCCHI ==========

    // Rotate right vector of blocks
    void rotr(size_t i);

    // Rotate left vector of blocks
    void rotl(size_t i);

    // ========== OPERAZIONI XOR ==========

    // XOR operation with another MBLOCK
    void xor_with(const MBLOCK &other, bool alternate = false);

    // ========== BIT MANIPULATION ==========

    // Toggle specific bit at position
    void toggleBit(size_t pos, int bitN);

    // ========== PADDING ==========

    // Create padded version from current block
    [[nodiscard]] MBLOCK* add_padding_outer(size_t outLen, m_block pad) const;

    // Get padding length (requires external dependencies: toByte_raw and OESException)
    [[nodiscard]] size_t get_padding_size_outer() const;

    // ========== MEMORY MANAGEMENT ==========

    // Create new MBLOCK from raw array (static factory)
    static MBLOCK* create(size_t len, m_block value = 0);

    // Concatenate two MBLOCKs (static factory)
    static MBLOCK* concat(const MBLOCK& a, const MBLOCK& b);

    // Extend current block
    void extend(size_t new_len, m_block fill);

    // Securely zero the data
    void secure_zero();

    // ========== CONVERSION METHODS ==========

    // Convert byte array to MBLOCK with padding (static factory)
    static MBLOCK* fromBytes(const void* data, size_t nByte);

    // Convert to byte array (raw, no padding removal)
    [[nodiscard]] std::pair<uint8_t*, size_t> toBytes_raw(size_t extraSize = 0) const;

    // Convert to byte array with padding removal
    [[nodiscard]] std::pair<uint8_t*, size_t> toBytes() const;

    // ========== DEBUG/UTILITY ==========

    // Dump block content for debugging (requires external dependencies: toByte_raw)
    void dump(bool printable = false) const;
};

#endif //LOCKBOX_M_BLOCK_H