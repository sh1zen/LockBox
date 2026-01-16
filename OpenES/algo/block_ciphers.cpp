#include <memory>

#include <OpenES/support/oesMath.h>
#include "key_management.h"
#include "block_ciphers.h"
#include "core.h"
#include "defines.h"
#include "m_block.h"
#include "random.h"
#include "raw-layer.h"
#include "sphinix.h"

// Helper function to get or create IV
inline MBLOCK *get_or_create_iv(MBLOCK *iv, size_t blockSize, m_block seed) {
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
            expanded->setBlock(i, cloned->getBlock(i));
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

    const size_t plainLen = plain->getLen();
    const size_t cipherLen = closestMultiple(plainLen + 2, OES_NUM_OF_BLOCK);
    size_t ses = session ? *session : 0;

    // ========================================================================
    // PHASE 1: PREPROCESSING
    // ========================================================================

    // 1.1 Create padded buffer
    std::unique_ptr<MBLOCK> data(plain->add_padding_outer(cipherLen, 0));
    if (!data) return nullptr;

    // 1.2 Inject random block for semantic security
    data->setBlock(cipherLen - 2, OES_RNG().next64());

    // 1.3 Positional rotation
    data->rotr(2);

    // ========================================================================
    // PHASE 2: PRE-CIPHER DIFFUSION
    // ========================================================================

    // 2.1 Global diffusion - spreads random block entropy everywhere
    global_diffuse(data.get(), ses);

    // 2.2 Correlation layer - creates inter-block dependencies
    correlate_data(data.get(), ses);

    // ========================================================================
    // PHASE 3: SPHINX WIDE-BLOCK ENCRYPTION
    // ========================================================================

    m_block *blocks = data->getDataRef();

    for (size_t i = 0; i < cipherLen; i += OES_NUM_OF_BLOCK) {
        const size_t blockCount = std::min(static_cast<size_t>(OES_NUM_OF_BLOCK), cipherLen - i);

        // 3.1 Derive session-specific keys using PBKDF
        auto sessionKeys = PBKDF(*key, OES_NUM_OF_BLOCK, 1, static_cast<m_block>(ses), 16);
        if (sessionKeys.empty() || !sessionKeys[0]) {
            cleanup_pbkdf_keys(sessionKeys);
            return nullptr;
        }

        // 3.2 Create block for SPHINX encryption
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockCount, 0));
        if (!blockData) {
            cleanup_pbkdf_keys(sessionKeys);
            return nullptr;
        }

        for (size_t j = 0; j < blockCount; ++j) {
            blockData->setBlock(j, blocks[i + j]);
        }

        // 3.3 Apply SPHINX wide-block encryption
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt(blockData.get(), sessionKeys[0]));
        cleanup_pbkdf_keys(sessionKeys);

        if (!encBlock || encBlock->isNull()) return nullptr;

        // 3.4 Copy encrypted data back
        for (size_t j = 0; j < blockCount; ++j) {
            blocks[i + j] = encBlock->getBlock(j);
        }

        ++ses;
    }

    // ========================================================================
    // PHASE 4: POST-CIPHER MIXING
    // ========================================================================

    // 4.1 Second correlation pass on ciphertext
    correlate_data(data.get(), ses);

    // 4.2 Final global diffusion
    global_diffuse(data.get(), ses);

    // ========================================================================
    // FINALIZE
    // ========================================================================

    if (session) *session = ses;

    return data.release();
}

// ============================================================================
// MAIN DECRYPTION FUNCTION
// ============================================================================

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

    // Calculate session after SPHINX encryption phase
    const size_t numChunks = (cipherLen + OES_NUM_OF_BLOCK - 1) / OES_NUM_OF_BLOCK;
    const size_t postSession = ses + numChunks;

    // Clone ciphertext for processing
    std::unique_ptr<MBLOCK> data(cipher->clone());
    if (!data) return nullptr;

    m_block *blocks = data->getDataRef();

    // ========================================================================
    // PHASE 4 INVERSE: UNDO POST-CIPHER MIXING
    // ========================================================================

    // 4.2 Inverse final global diffusion
    global_diffuse_inv(data.get(), postSession);

    // 4.1 Inverse second correlation
    uncorrelate_data(data.get(), postSession);

    // ========================================================================
    // PHASE 3 INVERSE: SPHINX DECRYPTION
    // ========================================================================

    // Process blocks in forward order with correct session
    size_t currentSession = initialSession;

    for (size_t i = 0; i < cipherLen; i += OES_NUM_OF_BLOCK) {
        const size_t blockCount = std::min(static_cast<size_t>(OES_NUM_OF_BLOCK), cipherLen - i);

        // Derive same session keys as encryption using PBKDF
        auto sessionKeys = PBKDF(*key, OES_NUM_OF_BLOCK, 1, static_cast<m_block>(currentSession), 16);
        if (sessionKeys.empty() || !sessionKeys[0]) {
            cleanup_pbkdf_keys(sessionKeys);
            return nullptr;
        }

        // Create block for SPHINX decryption
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockCount, 0));
        if (!blockData) {
            cleanup_pbkdf_keys(sessionKeys);
            return nullptr;
        }

        for (size_t j = 0; j < blockCount; ++j) {
            blockData->setBlock(j, blocks[i + j]);
        }

        // Apply SPHINX decryption
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(blockData.get(), sessionKeys[0]));
        cleanup_pbkdf_keys(sessionKeys);

        if (!decBlock || decBlock->isNull()) return nullptr;

        // Copy decrypted data back
        for (size_t j = 0; j < blockCount; ++j) {
            blocks[i + j] = decBlock->getBlock(j);
        }

        ++currentSession;
    }

    // ========================================================================
    // PHASE 2 INVERSE: UNDO PRE-CIPHER DIFFUSION
    // ========================================================================

    // 2.2 Inverse correlation
    uncorrelate_data(data.get(), initialSession);

    // 2.1 Inverse global diffusion
    global_diffuse_inv(data.get(), initialSession);

    // ========================================================================
    // PHASE 1 INVERSE: UNDO PREPROCESSING
    // ========================================================================

    // 1.3 Reverse positional rotation
    data->rotl(2);

    // 1.1 Remove padding (random block is discarded with padding)
    const uint32_t padding = data->get_padding_size_outer();
    const size_t plainLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    // ========================================================================
    // FINALIZE
    // ========================================================================

    MBLOCK *result = MBLOCK::create(plainLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < plainLen; ++i) {
        result->setBlock(i, data->getBlock(i));
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;
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
            blockData->setBlock(j, paddedPlain->getBlock(i + j));
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
            cipher->setBlock(i + j, encValue);
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;

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
            blockData->setBlock(j, cipher->getBlock(i + j));
        }

        // Save next chain state BEFORE modifying blockData
        m_block nextChainState = cipher->getBlock(i + blockSize - 1);

        // Remove XOR mask
        for (size_t j = 0; j < blockSize; ++j) {
            blockData->setBlock(j, blockData->getBlock(j) ^ xorMask->getBlock(j));
        }

        // Decrypt using SPHINX
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(blockData.get(), blockKey.get()));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // Store decrypted block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, decBlock->getBlock(j));
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
        result->setBlock(i, plain->getBlock(i));
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;
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
    nonceBlock->setBlock(blockSize - 1, ctr);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt the nonce/counter block
        std::unique_ptr<MBLOCK> keystream(SPHINX::encrypt(nonceBlock.get(), key));
        if (!keystream || keystream->isNull()) {
            delete cipher;
            return nullptr;
        }

        // XOR plaintext with keystream
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            cipher->setBlock(i + j, paddedPlain->getBlock(i + j) ^ keystream->getBlock(j));
        }

        // Increment counter
        ctr++;
        nonceBlock->setBlock(blockSize - 1, ctr);
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;

    // Allocate plaintext buffer
    std::unique_ptr<MBLOCK> plain(MBLOCK::create(cipherLen, 0));
    if (!plain) return nullptr;

    // Initialize nonce/counter block (same as encryption)
    std::unique_ptr<MBLOCK> nonceBlock(MBLOCK::create(blockSize, seed));
    if (!nonceBlock) return nullptr;

    m_block ctr = counter ? *counter : 0;
    nonceBlock->setBlock(blockSize - 1, ctr);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt nonce/counter (same operation as encryption)
        std::unique_ptr<MBLOCK> keystream(SPHINX::encrypt(nonceBlock.get(), key));
        if (!keystream || keystream->isNull()) {
            return nullptr;
        }

        // XOR ciphertext with keystream to recover plaintext
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, cipher->getBlock(i + j) ^ keystream->getBlock(j));
        }

        // Increment counter
        ctr++;
        nonceBlock->setBlock(blockSize - 1, ctr);
    }

    if (counter) *counter = ctr;

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        result->setBlock(i, plain->getBlock(i));
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;
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
            xorBlock->setBlock(j, paddedPlain->getBlock(i + j) ^ prevBlock->getBlock(j));
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
            cipher->setBlock(i + j, encValue);
            prevBlock->setBlock(j, encValue);
        }
    }

    // Update IV for potential chained operations
    if (iv) {
        delete *iv;
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; ++j) {
                (*iv)->setBlock(j, cipher->getBlock(cipherLen - blockSize + j));
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;

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
            cipherBlock->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(cipherBlock.get(), key));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // XOR with previous ciphertext (or IV) to get plaintext
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, decBlock->getBlock(j) ^ prevBlock->getBlock(j));
        }

        // Update previous block pointer
        for (size_t j = 0; j < blockSize; ++j) {
            prevBlock->setBlock(j, cipher->getBlock(i + j));
        }
    }

    // Update IV
    if (iv) {
        delete *iv;
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; ++j) {
                (*iv)->setBlock(j, cipher->getBlock(cipherLen - blockSize + j));
            }
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        result->setBlock(i, plain->getBlock(i));
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
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;
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
            blockData->setBlock(j, paddedPlain->getBlock(i + j));
        }

        // Encrypt block
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt(blockData.get(), key));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Store encrypted block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            cipher->setBlock(i + j, encBlock->getBlock(j));
        }
    }

    return cipher;
}

MBLOCK *oes_dec_ecb(const MBLOCK *cipher, const MBLOCK *key) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    constexpr size_t blockSize = OES_NUM_OF_BLOCK;

    // Allocate plaintext buffer
    std::unique_ptr<MBLOCK> plain(MBLOCK::create(cipherLen, 0));
    if (!plain) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block
        std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
        if (!blockData) return nullptr;

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            blockData->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(blockData.get(), key));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // Store decrypted block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, decBlock->getBlock(j));
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;

    for (size_t i = 0; i < outLen; ++i) {
        result->setBlock(i, plain->getBlock(i));
    }

    return result;
}
