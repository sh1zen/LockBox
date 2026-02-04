#include "block_ciphers.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <memory>

#include <OpenES/support/oesMath.h>
#include "key_management.h"
#include "core.h"
#include "prng.h"
#include "sphinix.h"

#define CIPHER_BLOCK_SIZE OES_NUM_OF_BLOCKS * OES_MEM_SIZE;

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

        std::memcpy(expanded->getDataRef(), cloned->getDataRef(), cloned->getLen() * sizeof(m_block));

        delete cloned;
        return expanded;
    }

    // No valid IV provided: create a new one using the seed
    return MBLOCK::create(blockSize, seed);
}

/**
 * OES Advanced Encryption Mode - DEBUG VERSION
 *
 * @param plain Plaintext to encrypt
 * @param key Master encryption key
 * @param session Pointer to session counter (updated on return)
 * @return Ciphertext, or nullptr on error
 */
MBLOCK *oes_enc_adv(const MBLOCK *plain, const MBLOCK *key, size_t *session) {
    if (!plain || plain->isNull()) {
        std::cerr << "[DEBUG] oes_enc_adv: plain is null or empty\n";
        return nullptr;
    }
    if (!key || key->isNull()) {
        std::cerr << "[DEBUG] oes_enc_adv: key is null or empty\n";
        return nullptr;
    }

    size_t ses = session ? *session : 0;
    const size_t plainLen = plain->getLen();
    const size_t cipherLen = closestMultiple(plainLen + 2, OES_NUM_OF_BLOCKS);

    auto prng = prng::PRNG(
        mBlock::rotr(prng::time_seed() ^ plainLen, ses) ^ cipherLen
    );

    // PHASE 1: PREPROCESSING
    std::unique_ptr<MBLOCK> data(plain->add_padding_outer(cipherLen, 0));
    if (!data || data->isNull()) {
        std::cerr << "[DEBUG] FAILED: add_padding_outer returned null or empty\n";
        return nullptr;
    }
    (void) data->setBlock(cipherLen - 2, prng.next());
    data->rotr(2);

    // PHASE 2: PRE-CIPHER DIFFUSION
    try {
        global_diffuse(data.get(), ses);
        correlate_data(data.get(), ses);
    } catch (const std::exception &e) {
        std::cerr << "[DEBUG] FAILED: pre-cipher diffusion: " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[DEBUG] FAILED: pre-cipher diffusion unknown exception\n";
        return nullptr;
    }

    // PHASE 3 & 4: SESSION KEY DERIVATION + SPHINX ENCRYPTION
    // key_scheduler provides session-dependent key material via hash + diffusion.
    // SPHINX's internal sponge-based key schedule then provides full non-linear
    // key expansion and per-round derivation. This replaces the former PBKDF(16)
    // which redundantly iterated 16× over HMAC for what is already a strong key.
    std::unique_ptr<MBLOCK> sessionKey(key_scheduler(key, OES_NUM_OF_BLOCKS, ses));
    if (!sessionKey || sessionKey->isNull()) {
        std::cerr << "[DEBUG] FAILED: key_scheduler returned invalid key\n";
        return nullptr;
    }

    MBLOCK *enc = nullptr;
    try {
        enc = SPHINX::encrypt(data.get(), sessionKey.get());
    } catch (const std::exception &e) {
        std::cerr << "[DEBUG] FAILED: SPHINX::encrypt exception: " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[DEBUG] FAILED: SPHINX::encrypt unknown exception\n";
        return nullptr;
    }

    if (!enc || enc->isNull()) {
        std::cerr << "[DEBUG] FAILED: SPHINX::encrypt returned null or empty\n";
        delete enc;
        return nullptr;
    }
    data.reset(enc);

    ++ses;

    // PHASE 5: POST-CIPHER MIXING
    try {
        correlate_data(data.get(), ses);
        global_diffuse(data.get(), ses);
    } catch (const std::exception &e) {
        std::cerr << "[DEBUG] FAILED: post-cipher mixing: " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[DEBUG] FAILED: post-cipher mixing unknown exception\n";
        return nullptr;
    }

    if (session) *session = ses;
    return data.release();
}

MBLOCK *oes_dec_adv(const MBLOCK *cipher, const MBLOCK *key, size_t *session) {
    if (!cipher || cipher->isNull()) {
        std::cerr << "[DEBUG] oes_dec_adv: cipher is null or empty\n";
        return nullptr;
    }
    if (!key || key->isNull()) {
        std::cerr << "[DEBUG] oes_dec_adv: key is null or empty\n";
        return nullptr;
    }

    const size_t cipherLen = cipher->getLen();
    const size_t ses = session ? *session : 0;

    std::unique_ptr<MBLOCK> data(cipher->clone());
    if (!data) {
        std::cerr << "[DEBUG] oes_dec_adv: clone failed\n";
        return nullptr;
    }

    // PHASE 5 INVERSE: undo post-cipher mixing
    try {
        global_diffuse_inv(data.get(), ses + 1);
        uncorrelate_data(data.get(), ses + 1);
    } catch (const std::exception &e) {
        std::cerr << "[DEBUG] FAILED: undo post-cipher: " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[DEBUG] FAILED: undo post-cipher unknown exception\n";
        return nullptr;
    }

    // PHASE 4 INVERSE: SPHINX DECRYPTION
    // Use the same lightweight key derivation as encryption.
    std::unique_ptr<MBLOCK> sessionKey(key_scheduler(key, OES_NUM_OF_BLOCKS, ses));
    if (!sessionKey || sessionKey->isNull()) {
        std::cerr << "[DEBUG] FAILED: key_scheduler returned invalid key\n";
        return nullptr;
    }

    MBLOCK *dec = nullptr;
    try {
        dec = SPHINX::decrypt(data.get(), sessionKey.get());
    } catch (const std::exception &e) {
        std::cerr << "[DEBUG] FAILED: SPHINX::decrypt exception: " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[DEBUG] FAILED: SPHINX::decrypt unknown exception\n";
        return nullptr;
    }

    if (!dec || dec->isNull()) {
        std::cerr << "[DEBUG] FAILED: SPHINX::decrypt returned null or empty\n";
        delete dec;
        return nullptr;
    }
    data.reset(dec);

    // PHASE 2 INVERSE: undo pre-cipher diffusion
    try {
        uncorrelate_data(data.get(), ses);
        global_diffuse_inv(data.get(), ses);
    } catch (const std::exception &e) {
        std::cerr << "[DEBUG] FAILED: undo pre-cipher: " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[DEBUG] FAILED: undo pre-cipher unknown exception\n";
        return nullptr;
    }

    // PHASE 1 INVERSE: undo preprocessing
    data->rotl(2);

    const uint32_t padding = data->get_padding_size_outer();
    const size_t plainLen = (cipherLen > padding) ? cipherLen - padding : 0;

    // Alloca result e copia con memcpy tramite accesso diretto
    auto *result = new MBLOCK(plainLen);
    if (plainLen > 0) {
        std::memcpy(result->getDataRef(), &(*data)[0], plainLen * sizeof(m_block));
    }

    if (session) *session = ses + 1;
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
    const m_block *paddedData = paddedPlain->getDataRef();
    m_block *cipherData = cipher->getDataRef();

    // Chain state evolves with each encrypted block
    m_block chainState = seed;
    std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
    if (!blockData) {
        delete cipher;
        return nullptr;
    }
    m_block *blockDataRef = blockData->getDataRef();

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
        std::memcpy(blockDataRef, paddedData + i, blockSize * sizeof(m_block));

        // Encrypt block using SPHINX
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt(blockData.get(), blockKey.get()));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Apply XOR mask and store
        const m_block *encData = encBlock->getDataRef();
        const m_block *xorData = xorMask->getDataRef();
        for (size_t j = 0; j < blockSize; ++j) {
            cipherData[i + j] = encData[j] ^ xorData[j];
        }

        // Evolve chain state using last ciphertext block
        chainState = cipherData[i + blockSize - 1];
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
    m_block *plainData = plain->getDataRef();

    // Chain state starts with seed
    m_block chainState = seed;

    std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
    if (!blockData) {
        return nullptr;
    }
    m_block *blockDataRef = blockData->getDataRef();

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
        const size_t chunk = std::min(blockSize, cipherLen - i);
        for (size_t j = 0; j < chunk; ++j) {
            blockDataRef[j] = (*cipher)[i + j];
        }
        if (chunk < blockSize) {
            std::memset(blockDataRef + chunk, 0, (blockSize - chunk) * sizeof(m_block));
        }

        // Save next chain state BEFORE modifying blockData
        m_block nextChainState = cipher->getBlock(i + blockSize - 1);

        // Remove XOR mask
        const m_block *xorData = xorMask->getDataRef();
        for (size_t j = 0; j < blockSize; ++j) {
            blockDataRef[j] ^= xorData[j];
        }

        // Decrypt using SPHINX
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt(blockData.get(), blockKey.get()));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // Store decrypted block
        const m_block *decData = decBlock->getDataRef();
        for (size_t j = 0; j < chunk; ++j) {
            plainData[i + j] = decData[j];
        }

        // Evolve chain state
        chainState = nextChainState;
    }

    // Remove padding and create result
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;
    if (outLen > 0) {
        std::memcpy(result->getDataRef(), plainData, outLen * sizeof(m_block));
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
    const m_block *paddedData = paddedPlain->getDataRef();
    m_block *cipherData = cipher->getDataRef();

    // Initialize nonce/counter block
    std::unique_ptr<MBLOCK> nonceBlock(MBLOCK::create(blockSize, seed));
    if (!nonceBlock) {
        delete cipher;
        return nullptr;
    }

    // Set initial counter value in last position
    m_block ctr = counter ? *counter : 0;
    m_block *nonceData = nonceBlock->getDataRef();
    nonceData[blockSize - 1] = ctr;
    auto ctx = SPHINX::create_context(key, blockSize);
    if (!ctx) {
        delete cipher;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt the nonce/counter block
        std::unique_ptr<MBLOCK> keystream(SPHINX::encrypt_with_context(nonceBlock.get(), *ctx));
        if (!keystream || keystream->isNull()) {
            delete cipher;
            return nullptr;
        }

        // XOR plaintext with keystream
        const m_block *keyData = keystream->getDataRef();
        for (size_t j = 0; j < blockSize; ++j) {
            cipherData[i + j] = paddedData[i + j] ^ keyData[j];
        }

        // Increment counter
        ctr++;
        nonceData[blockSize - 1] = ctr;
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
    m_block *plainData = plain->getDataRef();

    // Initialize nonce/counter block (same as encryption)
    std::unique_ptr<MBLOCK> nonceBlock(MBLOCK::create(blockSize, seed));
    if (!nonceBlock) return nullptr;

    m_block ctr = counter ? *counter : 0;
    m_block *nonceData = nonceBlock->getDataRef();
    nonceData[blockSize - 1] = ctr;
    auto ctx = SPHINX::create_context(key, blockSize);
    if (!ctx) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt nonce/counter (same operation as encryption)
        std::unique_ptr<MBLOCK> keystream(SPHINX::encrypt_with_context(nonceBlock.get(), *ctx));
        if (!keystream || keystream->isNull()) {
            return nullptr;
        }

        // XOR ciphertext with keystream to recover plaintext
        const size_t chunk = std::min(blockSize, cipherLen - i);
        const m_block *keyData = keystream->getDataRef();
        for (size_t j = 0; j < chunk; ++j) {
            plainData[i + j] = (*cipher)[i + j] ^ keyData[j];
        }

        // Increment counter
        ctr++;
        nonceData[blockSize - 1] = ctr;
    }

    if (counter) *counter = ctr;

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;
    if (outLen > 0) {
        std::memcpy(result->getDataRef(), plainData, outLen * sizeof(m_block));
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
    const m_block *paddedData = paddedPlain->getDataRef();
    m_block *cipherData = cipher->getDataRef();

    // Get or create IV
    std::unique_ptr<MBLOCK> prevBlock(
        get_or_create_iv(iv ? *iv : nullptr, blockSize, REPLICATE_BITS(0x4569)));
    if (!prevBlock) {
        delete cipher;
        return nullptr;
    }

    m_block *prevData = prevBlock->getDataRef();
    std::unique_ptr<MBLOCK> xorBlock(MBLOCK::create(blockSize, 0));
    if (!xorBlock) {
        delete cipher;
        return nullptr;
    }
    m_block *xorData = xorBlock->getDataRef();
    auto ctx = SPHINX::create_context(key, blockSize);
    if (!ctx) {
        delete cipher;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // XOR plaintext with previous ciphertext (or IV)
        for (size_t j = 0; j < blockSize; ++j) {
            xorData[j] = paddedData[i + j] ^ prevData[j];
        }

        // Encrypt XORed block
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt_with_context(xorBlock.get(), *ctx));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Store ciphertext and update previous block
        const m_block *encData = encBlock->getDataRef();
        for (size_t j = 0; j < blockSize; ++j) {
            const m_block encValue = encData[j];
            cipherData[i + j] = encValue;
            prevData[j] = encValue;
        }
    }

    // Update IV for potential chained operations
    if (iv) {
        delete *iv;
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            std::memcpy((*iv)->getDataRef(), cipherData + (cipherLen - blockSize), blockSize * sizeof(m_block));
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
    m_block *plainData = plain->getDataRef();

    // Get or create IV
    std::unique_ptr<MBLOCK> prevBlock(
        get_or_create_iv(iv ? *iv : nullptr, blockSize, REPLICATE_BITS(0x4569)));
    if (!prevBlock) return nullptr;
    m_block *prevData = prevBlock->getDataRef();
    std::unique_ptr<MBLOCK> cipherBlock(MBLOCK::create(blockSize, 0));
    if (!cipherBlock) return nullptr;
    m_block *cipherBlockData = cipherBlock->getDataRef();
    auto ctx = SPHINX::create_context(key, blockSize);
    if (!ctx) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract current ciphertext block
        const size_t chunk = std::min(blockSize, cipherLen - i);
        for (size_t j = 0; j < chunk; ++j) {
            cipherBlockData[j] = (*cipher)[i + j];
        }
        if (chunk < blockSize) {
            std::memset(cipherBlockData + chunk, 0, (blockSize - chunk) * sizeof(m_block));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt_with_context(cipherBlock.get(), *ctx));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // XOR with previous ciphertext (or IV) to get plaintext
        const m_block *decData = decBlock->getDataRef();
        for (size_t j = 0; j < chunk; ++j) {
            plainData[i + j] = decData[j] ^ prevData[j];
        }

        // Update previous block pointer
        for (size_t j = 0; j < blockSize; ++j) {
            prevData[j] = cipher->getBlock(i + j);
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
    if (outLen > 0) {
        std::memcpy(result->getDataRef(), plainData, outLen * sizeof(m_block));
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
    const m_block *paddedData = paddedPlain->getDataRef();
    m_block *cipherData = cipher->getDataRef();
    std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
    if (!blockData) {
        delete cipher;
        return nullptr;
    }
    m_block *blockDataRef = blockData->getDataRef();
    auto ctx = SPHINX::create_context(key, blockSize);
    if (!ctx) {
        delete cipher;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block
        std::memcpy(blockDataRef, paddedData + i, blockSize * sizeof(m_block));

        // Encrypt block
        std::unique_ptr<MBLOCK> encBlock(SPHINX::encrypt_with_context(blockData.get(), *ctx));
        if (!encBlock || encBlock->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Store encrypted block
        std::memcpy(cipherData + i, encBlock->getDataRef(), blockSize * sizeof(m_block));
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
    m_block *plainData = plain->getDataRef();
    std::unique_ptr<MBLOCK> blockData(MBLOCK::create(blockSize, 0));
    if (!blockData) return nullptr;
    m_block *blockDataRef = blockData->getDataRef();
    auto ctx = SPHINX::create_context(key, blockSize);
    if (!ctx) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block
        const size_t chunk = std::min(blockSize, cipherLen - i);
        for (size_t j = 0; j < chunk; ++j) {
            blockDataRef[j] = (*cipher)[i + j];
        }
        if (chunk < blockSize) {
            std::memset(blockDataRef + chunk, 0, (blockSize - chunk) * sizeof(m_block));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decBlock(SPHINX::decrypt_with_context(blockData.get(), *ctx));
        if (!decBlock || decBlock->isNull()) {
            return nullptr;
        }

        // Store decrypted block
        const m_block *decData = decBlock->getDataRef();
        for (size_t j = 0; j < chunk; ++j) {
            plainData[i + j] = decData[j];
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) return nullptr;
    if (outLen > 0) {
        std::memcpy(result->getDataRef(), plainData, outLen * sizeof(m_block));
    }

    return result;
}
