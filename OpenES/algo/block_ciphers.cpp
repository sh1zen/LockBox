#include "block_ciphers.h"

#include <memory>

#include <OpenES/support/oesMath.h>
#include "key_management.h"
#include "core.h"
#include "prng.h"
#include "sphinix.h"

#define CIPHER_BLOCK_SIZE OES_NUM_OF_BLOCKS * 8;

// Helper function to get or create IV
inline MBLOCK *get_or_create_iv(const MBLOCK *iv, size_t blockSize, m_block seed) {
    // If a valid IV is provided, try to clone it
    if (iv && !iv->isNull() && iv->getLen() > 0) {
        MBLOCK *cloned = iv->clone();
        if (cloned->isNull()) {
            delete cloned;
            return nullptr;
        }

        // If the cloned IV is already large enough, return it as-is
        if (cloned->getLen() >= blockSize) {
            return cloned;
        }

        // Otherwise, expand it to the required block size
        MBLOCK *expanded = MBLOCK::create(blockSize, seed);
        if (!expanded) {
            delete cloned;
            return nullptr;
        }

        for (size_t i = 0; i < cloned->getLen(); ++i) {
            (void) expanded->setBlock(i, cloned->getBlock(i));
        }

        delete cloned;
        return expanded;
    }

    // No valid IV provided: create a new one using the seed
    return MBLOCK::create(blockSize, seed);
}

/**
 * OES Advanced Encryption Mode
 *
 * @param plain Plaintext to encrypt
 * @param key Master encryption key
 * @param session Pointer to session counter (updated on return)
 * @return Ciphertext, or nullptr on error
 */
MBLOCK *oes_enc_adv(const MBLOCK *plain, const MBLOCK *key, size_t *session) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t ses = session ? *session : 0;

    const size_t plainLen = plain->getLen();
    const size_t cipherLen = closestMultiple(plainLen + 2, OES_NUM_OF_BLOCKS);

    auto prng = prng::PRNG(
        mBlock::rotr(prng::time_seed() ^ plainLen, ses) ^ cipherLen
    );

    // ========================================================================
    // PHASE 1: PREPROCESSING
    // ========================================================================

    std::unique_ptr<MBLOCK> data(plain->add_padding_outer(cipherLen, 0));
    if (!data) return nullptr;

    (void) data->setBlock(cipherLen - 2, prng.next());
    data->rotr(2);

    // ========================================================================
    // PHASE 2: PRE-CIPHER DIFFUSION
    // ========================================================================

    global_diffuse(data.get(), ses);
    correlate_data(data.get(), ses);

    // ========================================================================
    // PHASE 3: SPHINX WIDE-BLOCK ENCRYPTION (ONE SHOT)
    // ========================================================================

    auto sessionKeys = PBKDF(*key, cipherLen, 1,
                             static_cast<m_block>(ses), 16);
    if (sessionKeys.empty() || !sessionKeys[0]) {
        cleanup_pbkdf_keys(sessionKeys);
        return nullptr;
    }

    std::unique_ptr<MBLOCK> enc(SPHINX::encrypt(data.get(), sessionKeys[0]));
    cleanup_pbkdf_keys(sessionKeys);

    if (!enc || enc->isNull()) return nullptr;

    data = std::move(enc);
    ++ses;

    // ========================================================================
    // PHASE 4: POST-CIPHER MIXING
    // ========================================================================

    correlate_data(data.get(), ses);
    global_diffuse(data.get(), ses);

    if (session) *session = ses;
    return data.release();
}

/**
 * OES Advanced Decryption Mode
 *
 * @param cipher Ciphertext to decrypt
 * @param key Master decryption key (same as encryption)
 * @param session Pointer to session counter (updated on return)
 * @return Plaintext, or nullptr on error
 */
MBLOCK *oes_dec_adv(const MBLOCK *cipher, const MBLOCK *key, size_t *session) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    size_t ses = session ? *session : 0;
    const size_t initialSession = ses;
    const size_t postSession = ses + 1;

    std::unique_ptr<MBLOCK> data(cipher->clone());
    if (!data) return nullptr;

    // ========================================================================
    // PHASE 4 INVERSE: UNDO POST-CIPHER MIXING
    // ========================================================================

    global_diffuse_inv(data.get(), postSession);
    uncorrelate_data(data.get(), postSession);

    // ========================================================================
    // PHASE 3 INVERSE: SPHINX WIDE-BLOCK DECRYPTION
    // ========================================================================

    auto sessionKeys = PBKDF(*key, cipherLen, 1,
                             static_cast<m_block>(initialSession), 16);
    if (sessionKeys.empty() || !sessionKeys[0]) {
        cleanup_pbkdf_keys(sessionKeys);
        return nullptr;
    }

    std::unique_ptr<MBLOCK> dec(SPHINX::decrypt(data.get(), sessionKeys[0]));
    cleanup_pbkdf_keys(sessionKeys);

    if (!dec || dec->isNull()) return nullptr;

    data = std::move(dec);

    // ========================================================================
    // PHASE 2 INVERSE: UNDO PRE-CIPHER DIFFUSION
    // ========================================================================

    uncorrelate_data(data.get(), initialSession);
    global_diffuse_inv(data.get(), initialSession);

    // ========================================================================
    // PHASE 1 INVERSE: UNDO PREPROCESSING
    // ========================================================================

    data->rotl(2);

    const uint32_t padding = data->get_padding_size_outer();
    const size_t plainLen =
            (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(plainLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < plainLen; ++i) {
        (void) result->setBlock(i, data->getBlock(i));
    }

    if (session) *session = postSession;
    return result;
}


// ============================================================================
// CKE MODE - Chained Key Expansion
// ============================================================================
// Proprietary mode where the encryption key evolves based on ciphertext.
// Each block uses a different derived key, providing forward secrecy properties.
//
// Security: High - key evolution prevents pattern analysis
// Parallelizable: No (sequential dependency)
// Error propagation: Full (one corrupted block affects all subsequent)

MBLOCK *oes_enc_cke(const MBLOCK *plain, const MBLOCK *key, m_block seed) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t plainLen = plain->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;
    const size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Pad plaintext
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Allocate cipher output
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    // Chain state evolves with each encrypted block
    m_block chainState = seed;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Derive block-specific key from chain state
        std::unique_ptr<MBLOCK> blockKey(key_expansion(key, blockSize, chainState, 10));
        if (!blockKey || blockKey->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Derive XOR mask from rotated chain state
        std::unique_ptr<MBLOCK> xorMask(key_expansion(key, blockSize,
                                                      mBlock::rotr(chainState, 5), 10));
        if (!xorMask || xorMask->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Extract current plaintext block
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
        if (!blockData) {
            delete cipher;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) blockData->setBlock(j, paddedPlain->getBlock(i + j));
        }

        // Encrypt block using SPHINX
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt(blockData.get(), blockKey.get()));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Apply XOR mask and store
        for (size_t j = 0; j < blockSize; ++j) {
            m_block encValue = encBlock->getBlock(j) ^ xorMask->getBlock(j);
            (void) cipher->setBlock(i + j, encValue);
        }

        // Evolve chain state using last ciphertext block
        chainState = cipher->getBlock(i + blockSize - 1);
    }

    return cipher;
}

MBLOCK *oes_dec_cke(const MBLOCK *cipher, const MBLOCK *key, m_block seed) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;

    // Allocate plaintext buffer
    std::unique_ptr<MBLOCK> plain(MBLOCK::create(cipherLen, 0));
    if (!plain) return nullptr;

    // Chain state starts with seed
    m_block chainState = seed;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Derive same keys as encryption
        std::unique_ptr<MBLOCK> blockKey(key_expansion(key, blockSize, chainState, 10));
        if (!blockKey || blockKey->isNull()) {
            return nullptr;
        }

        std::unique_ptr<MBLOCK> xorMask(key_expansion(key, blockSize,
                                                      mBlock::rotr(chainState, 5), 10));
        if (!xorMask || xorMask->isNull()) {
            return nullptr;
        }

        // Extract current ciphertext block
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
        if (!blockData) {
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) blockData->setBlock(j, cipher->getBlock(i + j));
        }

        // Save next chain state BEFORE modifying blockData
        m_block nextChainState = cipher->getBlock(i + blockSize - 1);

        // Remove XOR mask
        for (size_t j = 0; j < blockSize; ++j) {
            (void) blockData->setBlock(j, blockData->getBlock(j) ^ xorMask->getBlock(j));
        }

        // Decrypt using SPHINX
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(blockData.get(), blockKey.get()));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // Store decrypted block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) plain->setBlock(i + j, decBlock->getBlock(j));
        }

        // Evolve chain state
        chainState = nextChainState;
    }

    // Remove padding and create result
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        (void) result->setBlock(i, plain->getBlock(i));
    }

    return result;
}

// ============================================================================
// CTR MODE - Counter Mode
// ============================================================================
// Stream cipher mode - encrypts counter values and XORs with plaintext.
// Identical encryption/decryption operation.
//
// Security: High (with unique nonce per message)
// Parallelizable: Yes (fully)
// Error propagation: None (bit errors stay localized)

MBLOCK *oes_enc_ctr(const MBLOCK *plain, const MBLOCK *key, m_block seed, m_block *counter) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t plainLen = plain->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;
    const size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Pad plaintext
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Allocate cipher output
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    // Initialize nonce/counter block
    std::unique_ptr<MBLOCK> nonceBlock(MBLOCK::create(blockSize, seed));
    if (!nonceBlock) {
        delete cipher;
        return nullptr;
    }

    // Set initial counter value in last position
    m_block ctr = counter ? *counter : 0;
    (void) nonceBlock->setBlock(blockSize - 1, ctr);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt the nonce/counter block
        std::unique_ptr<MBLOCK> keystream(SPHINX::encrypt(nonceBlock.get(), key));
        if (!keystream || keystream->isNull()) {
            delete cipher;
            return nullptr;
        }

        // XOR plaintext with keystream
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) cipher->setBlock(i + j, paddedPlain->getBlock(i + j) ^ keystream->getBlock(j));
        }

        // Increment counter
        ctr++;
        (void) nonceBlock->setBlock(blockSize - 1, ctr);
    }

    // Update external counter if provided
    if (counter) *counter = ctr;

    return cipher;
}

MBLOCK *oes_dec_ctr(const MBLOCK *cipher, const MBLOCK *key, m_block seed, m_block *counter) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;

    // Allocate plaintext buffer
    std::unique_ptr<MBLOCK> plain(MBLOCK::create(cipherLen, 0));
    if (!plain) return nullptr;

    // Initialize nonce/counter block (same as encryption)
    std::unique_ptr<MBLOCK> nonceBlock(MBLOCK::create(blockSize, seed));
    if (!nonceBlock) return nullptr;

    m_block ctr = counter ? *counter : 0;
    (void) nonceBlock->setBlock(blockSize - 1, ctr);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt nonce/counter (same operation as encryption)
        std::unique_ptr<MBLOCK> keystream(SPHINX::encrypt(nonceBlock.get(), key));
        if (!keystream || keystream->isNull()) {
            return nullptr;
        }

        // XOR ciphertext with keystream to recover plaintext
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) plain->setBlock(i + j, cipher->getBlock(i + j) ^ keystream->getBlock(j));
        }

        // Increment counter
        ctr++;
        (void) nonceBlock->setBlock(blockSize - 1, ctr);
    }

    if (counter) *counter = ctr;

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        (void) result->setBlock(i, plain->getBlock(i));
    }

    return result;
}

// ============================================================================
// CBC MODE - Cipher Block Chaining
// ============================================================================
// Classic chaining mode - each block depends on all previous blocks.
//
// Security: High (with random IV per message)
// Parallelizable: Decryption only
// Error propagation: Limited (affects current + next block)
MBLOCK *oes_enc_cbc(const MBLOCK *plain, const MBLOCK *key, MBLOCK **iv) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t plainLen = plain->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;
    const size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Pad plaintext
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Allocate cipher output
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    // Get or create IV
    std::unique_ptr<MBLOCK> prevBlock(
        get_or_create_iv(iv ? *iv : nullptr, blockSize, REPLICATE_BITS(0x4569)));
    if (!prevBlock) {
        delete cipher;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // XOR plaintext with previous ciphertext (or IV)
        std::unique_ptr<MBLOCK> xorBlock(MBLOCK::create(blockSize, 0));
        if (!xorBlock) {
            delete cipher;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) xorBlock->setBlock(j, paddedPlain->getBlock(i + j) ^ prevBlock->getBlock(j));
        }

        // Encrypt XORed block
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt(xorBlock.get(), key));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Store ciphertext and update previous block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            m_block encValue = encBlock->getBlock(j);
            (void) cipher->setBlock(i + j, encValue);
            (void) prevBlock->setBlock(j, encValue);
        }
    }

    // Update IV for potential chained operations
    if (iv) {
        delete *iv;
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; ++j) {
                (void) (*iv)->setBlock(j, cipher->getBlock(cipherLen - blockSize + j));
            }
        }
    }

    return cipher;
}

MBLOCK *oes_dec_cbc(const MBLOCK *cipher, const MBLOCK *key, MBLOCK **iv) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;

    // Allocate plaintext buffer
    std::unique_ptr<MBLOCK> plain(MBLOCK::create(cipherLen, 0));
    if (!plain) return nullptr;

    // Get or create IV
    std::unique_ptr<MBLOCK> prevBlock(
        get_or_create_iv(iv ? *iv : nullptr, blockSize, REPLICATE_BITS(0x4569)));
    if (!prevBlock) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract current ciphertext block
        std::unique_ptr<MBLOCK> cipherBlock(MBLOCK::create(blockSize, 0));
        if (!cipherBlock) return nullptr;

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) cipherBlock->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(cipherBlock.get(), key));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // XOR with previous ciphertext (or IV) to get plaintext
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) plain->setBlock(i + j, decBlock->getBlock(j) ^ prevBlock->getBlock(j));
        }

        // Update previous block pointer
        for (size_t j = 0; j < blockSize; ++j) {
            (void) prevBlock->setBlock(j, cipher->getBlock(i + j));
        }
    }

    // Update IV
    if (iv) {
        delete *iv;
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; ++j) {
                (void) (*iv)->setBlock(j, cipher->getBlock(cipherLen - blockSize + j));
            }
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        (void) result->setBlock(i, plain->getBlock(i));
    }

    return result;
}

// ============================================================================
// ECB MODE - Electronic CodeBook
// ============================================================================
// Simplest mode - each block encrypted independently.
// NOT RECOMMENDED for data with patterns (e.g., images).
//
// Security: Low (pattern preservation)
// Parallelizable: Yes (fully)
// Error propagation: None
MBLOCK *oes_enc_ecb(const MBLOCK *plain, const MBLOCK *key) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t plainLen = plain->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;
    const size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Pad plaintext
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Allocate cipher output
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
        if (!blockData) {
            delete cipher;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) blockData->setBlock(j, paddedPlain->getBlock(i + j));
        }

        // Encrypt block
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt(blockData.get(), key));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Store encrypted block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) cipher->setBlock(i + j, encBlock->getBlock(j));
        }
    }

    return cipher;
}

MBLOCK *oes_dec_ecb(const MBLOCK *cipher, const MBLOCK *key) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    constexpr size_t blockSize = CIPHER_BLOCK_SIZE;

    // Allocate plaintext buffer
    std::unique_ptr<MBLOCK> plain(MBLOCK::create(cipherLen, 0));
    if (!plain) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
        if (!blockData) return nullptr;

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) blockData->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(blockData.get(), key));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // Store decrypted block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            (void) plain->setBlock(i + j, decBlock->getBlock(j));
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        (void) result->setBlock(i, plain->getBlock(i));
    }

    return result;
}
