#include <iostream>
#include <vector>

#include <OpenES/support/oesMath.h>
#include "core.h"
#include "key_management.h"
#include "block_ciphers.h"
#include "defines.h"
#include "m_block.h"
#include "raw-layer.h"

// Helper function to get or create IV
static MBLOCK *get_or_create_iv(MBLOCK *iv, size_t blockSize, m_block defaultValue) {
    if (!iv || iv->isNull()) {
        // Create new IV with default value
        return MBLOCK::create(blockSize, defaultValue);
    }

    const auto iv_clone = iv->clone();

    // Clone and extend if necessary
    if (iv_clone->getLen() < blockSize) {
        iv_clone->extend(blockSize, defaultValue);
    }

    return iv_clone;
}

/**
 * Advanced encryption with PBKDF-based round keys
 */
MBLOCK *oes_enc_adv(const MBLOCK *plain, const MBLOCK *key, size_t *session) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t plainLen = plain->getLen();
    size_t cipherLen = closestMultiple(plainLen + 2,OES_NUM_OF_BLOCK);
    size_t roundSession = session ? *session : 0;

    // Create padded version
    MBLOCK *cipher = plain->add_padding_outer(cipherLen, 0);
    if (!cipher) {
        return nullptr;
    }

    //todo add randomdata at cipherLen - 2
    /*
    #include <chrono>
    auto now = std::chrono::system_clock::now();

    cipher->setBlock(cipherLen - 2, 0);
    */


    for (size_t i = 0; i < cipherLen; i += OES_NUM_OF_BLOCK) {
        // Generate round keys using new PBKDF
        std::vector<MBLOCK *> roundKeys = PBKDF(*key, OES_NUM_OF_BLOCK, 2, roundSession, 2);

        if (roundKeys.empty() || roundKeys.size() != 2 ||
            !roundKeys[0] || roundKeys[0]->isNull() ||
            !roundKeys[1] || roundKeys[1]->isNull()) {
            cleanup_pbkdf_keys(roundKeys);
            delete cipher;
            return nullptr;
        }

        // Create a sub-block for the current block
        MBLOCK *blockData = MBLOCK::create(OES_NUM_OF_BLOCK, 0);
        if (!blockData) {
            cleanup_pbkdf_keys(roundKeys);
            delete cipher;
            return nullptr;
        }

        // Copy current block
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            blockData->setBlock(j, cipher->getBlock(i + j));
        }

        // XOR with first round key (TUTTI i byte, non solo i pari)
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            m_block value = blockData->getBlock(j) ^ roundKeys[0]->getBlock(j);
            blockData->setBlock(j, value);
        }

        // Correlate data
        correlate_data(blockData, roundSession);

        // XOR with second round key (TUTTI i byte, non solo i pari)
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            m_block value = blockData->getBlock(j) ^ roundKeys[1]->getBlock(j);
            blockData->setBlock(j, value);
        }

        // Copy back to cipher
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            cipher->setBlock(i + j, blockData->getBlock(j));
        }

        delete blockData;
        cleanup_pbkdf_keys(roundKeys);
        roundSession++;
    }

    if (session) {
        *session = roundSession;
    }

    return cipher;
}

MBLOCK *oes_dec_adv(const MBLOCK *cipher, const MBLOCK *key, size_t *session) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t cipherLen = cipher->getLen();
    size_t roundSession = session ? *session : 0;

    // Create plain MBLOCK as a clone of cipher
    MBLOCK *plain = cipher->clone();

    for (size_t i = 0; i < cipherLen; i += OES_NUM_OF_BLOCK) {
        // Generate round keys using new PBKDF
        std::vector<MBLOCK *> roundKeys = PBKDF(*key, OES_NUM_OF_BLOCK, 2, roundSession, 2);

        if (roundKeys.empty() || roundKeys.size() != 2 ||
            !roundKeys[0] || roundKeys[0]->isNull() ||
            !roundKeys[1] || roundKeys[1]->isNull()) {
            cleanup_pbkdf_keys(roundKeys);
            delete plain;
            return nullptr;
        }

        // Create a sub-block for the current block
        MBLOCK *blockData = MBLOCK::create(OES_NUM_OF_BLOCK, 0);
        if (!blockData) {
            cleanup_pbkdf_keys(roundKeys);
            delete plain;
            return nullptr;
        }

        // Copy current block
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            blockData->setBlock(j, plain->getBlock(i + j));
        }

        // XOR with second round key (TUTTI i byte, non solo i pari)
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            m_block value = blockData->getBlock(j) ^ roundKeys[1]->getBlock(j);
            blockData->setBlock(j, value);
        }

        // Uncorrelate data
        uncorrelate_data(blockData, roundSession);

        // XOR with first round key (TUTTI i byte, non solo i pari)
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            m_block value = blockData->getBlock(j) ^ roundKeys[0]->getBlock(j);
            blockData->setBlock(j, value);
        }

        // Copy back to plain
        for (size_t j = 0; j < OES_NUM_OF_BLOCK; j++) {
            plain->setBlock(i + j, blockData->getBlock(j));
        }

        delete blockData;
        cleanup_pbkdf_keys(roundKeys);
        roundSession++;
    }

    if (session) {
        *session = roundSession;
    }

    // Remove padding
    size_t padding = plain->get_padding_size_outer();
    size_t outLen = cipherLen - padding;

    // Create output with correct length
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < outLen; i++) {
        result->setBlock(i, plain->getBlock(i));
    }

    delete plain;
    return result;
}

/**
 * Cipher key expansion (rounded)
 */
MBLOCK *oes_enc_cke(const MBLOCK *plain, const MBLOCK *key, m_block seed) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t plainLen = plain->getLen();

    MBLOCK *keyExpanded = key_expansion(key, plainLen, seed, 10);
    if (!keyExpanded || keyExpanded->isNull()) {
        if (keyExpanded) delete keyExpanded;
        return nullptr;
    }

    MBLOCK *xorKey = key_expansion(key, plainLen, mBlock_rotr(seed, 5), 10);
    if (!xorKey || xorKey->isNull()) {
        delete keyExpanded;
        delete xorKey;
        return nullptr;
    }

    // Encrypt using raw_enc
    MBLOCK *cipherBlock = raw_enc(plain, keyExpanded);
    if (!cipherBlock || cipherBlock->isNull()) {
        delete keyExpanded;
        delete xorKey;
        if (cipherBlock) delete cipherBlock;
        return nullptr;
    }

    // XOR with xorKey (alternate)
    for (size_t i = 0; i < plainLen; i++) {
        if (i % 2 == 0) {
            m_block value = cipherBlock->getBlock(i) ^ xorKey->getBlock(i);
            cipherBlock->setBlock(i, value);
        }
    }

    delete keyExpanded;
    delete xorKey;

    return cipherBlock;
}

MBLOCK *oes_dec_cke(const MBLOCK *cipher, const MBLOCK *key, m_block seed) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t cipherLen = cipher->getLen();

    MBLOCK *keyExpanded = key_expansion(key, cipherLen, seed, 10);
    if (!keyExpanded || keyExpanded->isNull()) {
        if (keyExpanded) delete keyExpanded;
        return nullptr;
    }

    MBLOCK *xorKey = key_expansion(key, cipherLen, mBlock_rotr(seed, 5), 10);
    if (!xorKey || xorKey->isNull()) {
        delete keyExpanded;
        if (xorKey) delete xorKey;
        return nullptr;
    }

    // Clone cipher and XOR with xorKey
    MBLOCK *cipherCopy = cipher->clone();

    // XOR with xorKey (alternate)
    for (size_t i = 0; i < cipherLen; i++) {
        if (i % 2 == 0) {
            m_block value = cipherCopy->getBlock(i) ^ xorKey->getBlock(i);
            cipherCopy->setBlock(i, value);
        }
    }

    // Decrypt using raw_dec
    MBLOCK *plainBlock = raw_dec(cipherCopy, keyExpanded);

    delete cipherCopy;
    delete keyExpanded;
    delete xorKey;

    return plainBlock;
}

/**
 * Counter mode encryption
 */
MBLOCK *oes_enc_ctr(const MBLOCK *plain, const MBLOCK *key, m_block seed, m_block *counter) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t plainLen = plain->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);
    size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Create padded version
    MBLOCK *paddedPlain = plain->add_padding_outer(cipherLen, 0);
    if (!paddedPlain) {
        return nullptr;
    }

    // Create cipher MBLOCK
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) {
        delete paddedPlain;
        return nullptr;
    }

    // Create nonce/counter block using MBLOCK::create
    MBLOCK *nonceCounterBlock = MBLOCK::create(blockSize, seed);
    if (!nonceCounterBlock) {
        delete cipher;
        delete paddedPlain;
        return nullptr;
    }

    // Set counter value
    nonceCounterBlock->setBlock(blockSize - 1, counter ? *counter : 0);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Create MBLOCK for nonce/counter
        MBLOCK *nonceCounter = MBLOCK::create(blockSize, 0);
        if (!nonceCounter) {
            delete cipher;
            delete paddedPlain;
            delete nonceCounterBlock;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            nonceCounter->setBlock(j, nonceCounterBlock->getBlock(j));
        }

        // Encrypt nonce/counter
        MBLOCK *encNonceCounter = raw_enc(nonceCounter, key);
        delete nonceCounter;

        if (!encNonceCounter || encNonceCounter->isNull()) {
            delete cipher;
            delete paddedPlain;
            delete nonceCounterBlock;
            if (encNonceCounter) delete encNonceCounter;
            return nullptr;
        }

        // XOR plain block with encrypted nonce
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; j++) {
            m_block plainValue = paddedPlain->getBlock(i + j);
            m_block encValue = encNonceCounter->getBlock(j);
            cipher->setBlock(i + j, plainValue ^ encValue);
        }

        delete encNonceCounter;

        // Increment counter
        m_block currentCounter = nonceCounterBlock->getBlock(blockSize - 1);
        nonceCounterBlock->setBlock(blockSize - 1, currentCounter + 1);
        if (counter) (*counter)++;
    }

    delete paddedPlain;
    delete nonceCounterBlock;

    return cipher;
}

MBLOCK *oes_dec_ctr(const MBLOCK *cipher, const MBLOCK *key, m_block seed, m_block *counter) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t cipherLen = cipher->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);

    // Create plain MBLOCK
    MBLOCK *plain = MBLOCK::create(cipherLen, 0);
    if (!plain) {
        return nullptr;
    }

    // Create nonce/counter block using MBLOCK::create
    MBLOCK *nonceCounterBlock = MBLOCK::create(blockSize, seed);
    if (!nonceCounterBlock) {
        delete plain;
        return nullptr;
    }

    // Set counter value
    nonceCounterBlock->setBlock(blockSize - 1, counter ? *counter : 0);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Create MBLOCK for nonce/counter
        MBLOCK *nonceCounter = MBLOCK::create(blockSize, 0);
        if (!nonceCounter) {
            delete plain;
            delete nonceCounterBlock;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            nonceCounter->setBlock(j, nonceCounterBlock->getBlock(j));
        }

        // Encrypt nonce/counter
        MBLOCK *encNonceCounter = raw_enc(nonceCounter, key);
        delete nonceCounter;

        if (!encNonceCounter || encNonceCounter->isNull()) {
            delete plain;
            delete nonceCounterBlock;
            if (encNonceCounter) delete encNonceCounter;
            return nullptr;
        }

        // XOR cipher block with encrypted nonce
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; j++) {
            m_block cipherValue = cipher->getBlock(i + j);
            m_block encValue = encNonceCounter->getBlock(j);
            plain->setBlock(i + j, cipherValue ^ encValue);
        }

        delete encNonceCounter;

        // Increment counter
        m_block currentCounter = nonceCounterBlock->getBlock(blockSize - 1);
        nonceCounterBlock->setBlock(blockSize - 1, currentCounter + 1);
        if (counter) (*counter)++;
    }

    delete nonceCounterBlock;

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = cipherLen - padding;

    // Create output with correct length
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < outLen; i++) {
        result->setBlock(i, plain->getBlock(i));
    }

    delete plain;
    return result;
}

/**
 * Cipher Block Chaining encryption
 */
MBLOCK *oes_enc_cbc(const MBLOCK *plain, const MBLOCK *key, MBLOCK **iv) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t plainLen = plain->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);
    size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Create padded version
    MBLOCK *paddedPlain = plain->add_padding_outer(cipherLen, 0);
    if (!paddedPlain) {
        return nullptr;
    }

    // Create cipher MBLOCK
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) {
        delete paddedPlain;
        return nullptr;
    }

    // Keep a reference to the previous cipher block (starts with IV)
    MBLOCK *prevBlock = get_or_create_iv(iv ? *iv : nullptr, blockSize, m_block(0x455e69f3));
    if (!prevBlock) {
        delete cipher;
        delete paddedPlain;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Create temp MBLOCK for XOR with previous block
        MBLOCK *temp = MBLOCK::create(blockSize, 0);
        if (!temp) {
            delete cipher;
            delete paddedPlain;
            delete prevBlock;
            return nullptr;
        }

        // XOR plaintext block with previous cipher block (or IV for first block)
        for (size_t j = 0; j < blockSize; j++) {
            temp->setBlock(j, paddedPlain->getBlock(i + j) ^ prevBlock->getBlock(j));
        }

        // Encrypt the XORed data
        MBLOCK *encdata = raw_enc(temp, key);
        delete temp;

        if (!encdata || encdata->isNull()) {
            delete cipher;
            delete paddedPlain;
            delete prevBlock;
            return nullptr;
        }

        // Copy encrypted data to cipher output
        for (size_t j = 0; j < blockSize; j++) {
            cipher->setBlock(i + j, encdata->getBlock(j));
        }

        // Update prevBlock with current encrypted block for next iteration
        for (size_t j = 0; j < blockSize; j++) {
            prevBlock->setBlock(j, encdata->getBlock(j));
        }

        delete encdata;
    }

    delete paddedPlain;
    delete prevBlock;

    // Update IV parameter with the last cipher block
    if (iv) {
        if (*iv) {
            delete *iv;
        }
        // Store the last cipher block as the new IV
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; j++) {
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

    size_t cipherLen = cipher->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);

    // Create plain MBLOCK
    MBLOCK *plain = MBLOCK::create(cipherLen, 0);
    if (!plain) {
        return nullptr;
    }

    // Keep a reference to the previous cipher block (starts with IV)
    MBLOCK *prevBlock = get_or_create_iv(iv ? *iv : nullptr, blockSize, m_block(0x455e69f3));
    if (!prevBlock) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Save current cipher block BEFORE decryption
        MBLOCK *currentCipherBlock = MBLOCK::create(blockSize, 0);
        if (!currentCipherBlock) {
            delete plain;
            delete prevBlock;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            currentCipherBlock->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt the cipher block
        MBLOCK *decData = raw_dec(currentCipherBlock, key);
        if (!decData || decData->isNull()) {
            delete plain;
            delete prevBlock;
            delete currentCipherBlock;
            return nullptr;
        }

        // XOR with previous cipher block (or IV for first block)
        for (size_t j = 0; j < blockSize; j++) {
            plain->setBlock(i + j, decData->getBlock(j) ^ prevBlock->getBlock(j));
        }

        delete decData;

        // Update prevBlock with current cipher block for next iteration
        for (size_t j = 0; j < blockSize; j++) {
            prevBlock->setBlock(j, currentCipherBlock->getBlock(j));
        }

        delete currentCipherBlock;
    }

    delete prevBlock;

    // Update IV parameter with the last cipher block
    if (iv) {
        if (*iv) {
            delete *iv;
        }
        // Store the last cipher block as the new IV
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; j++) {
                (*iv)->setBlock(j, cipher->getBlock(cipherLen - blockSize + j));
            }
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = cipherLen - padding;

    // Create output with correct length
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < outLen; i++) {
        result->setBlock(i, plain->getBlock(i));
    }

    delete plain;
    return result;
}

/**
 * Electronic CodeBook encryption
 */
MBLOCK *oes_enc_ecb(const MBLOCK *plain, const MBLOCK *key) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t plainLen = plain->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);
    size_t cipherLen = closestMultiple(plainLen + 1, blockSize);

    // Create padded version
    MBLOCK *paddedPlain = plain->add_padding_outer(cipherLen, 0);
    if (!paddedPlain) {
        return nullptr;
    }

    // Create cipher MBLOCK
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) {
        delete paddedPlain;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block as MBLOCK
        MBLOCK *blockData = MBLOCK::create(blockSize, 0);
        if (!blockData) {
            delete cipher;
            delete paddedPlain;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            blockData->setBlock(j, paddedPlain->getBlock(i + j));
        }

        MBLOCK *encdata = raw_enc(blockData, key);
        delete blockData;

        if (!encdata || encdata->isNull()) {
            delete cipher;
            delete paddedPlain;
            if (encdata) delete encdata;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            cipher->setBlock(i + j, encdata->getBlock(j));
        }

        delete encdata;
    }

    delete paddedPlain;

    return cipher;
}

MBLOCK *oes_dec_ecb(const MBLOCK *cipher, const MBLOCK *key) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t cipherLen = cipher->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);

    // Create plain MBLOCK
    MBLOCK *plain = MBLOCK::create(cipherLen, 0);
    if (!plain) {
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Extract block as MBLOCK
        MBLOCK *blockData = MBLOCK::create(blockSize, 0);
        if (!blockData) {
            delete plain;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            blockData->setBlock(j, cipher->getBlock(i + j));
        }

        MBLOCK *decData = raw_dec(blockData, key);
        delete blockData;

        if (!decData || decData->isNull()) {
            delete plain;
            if (decData) delete decData;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize; j++) {
            plain->setBlock(i + j, decData->getBlock(j));
        }

        delete decData;
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = cipherLen - padding;

    // Create output with correct length
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < outLen; i++) {
        result->setBlock(i, plain->getBlock(i));
    }

    delete plain;
    return result;
}
