#include <cstdlib>
#include <cstring>
#include <iostream>

#include <OpenES/support/oesMath.h>
#include <OpenES/support/support.h>
#include "core.h"
#include "key_managment.h"
#include "block_ciphers.h"
#include "converter.h"

#include "defines.h"

/**
 * Helper function to safely update an IV block
 * Takes ownership of newData
 */
static void update_iv(OES_BLOCK *iv, m_block *newData, size_t newLen) {
    if (!iv) {
        // No IV pointer - just free the data
        if (newData) {
            secure_memzero(newData, newLen * sizeof(m_block));
            free(newData);
        }
        return;
    }

    if (*iv) {
        // Free old IV data
        if ((*iv)->data) {
            secure_memzero((*iv)->data, (*iv)->len * sizeof(m_block));
            free((*iv)->data);
        }
        // Reuse existing structure
        (*iv)->data = newData;
        (*iv)->len = newLen;
    } else {
        // Allocate new IV structure
        *iv = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
        if (*iv) {
            (*iv)->data = newData;
            (*iv)->len = newLen;
        } else {
            // Allocation failed - free the data
            if (newData) {
                secure_memzero(newData, newLen * sizeof(m_block));
                free(newData);
            }
        }
    }
}

/**
 * Helper to get IV data, creating default if needed
 * Returns a COPY of the IV data (caller must free)
 */
static m_block* get_iv_copy(OES_BLOCK *iv, size_t blockSize, m_block defaultValue) {
    if (iv && *iv && (*iv)->data && (*iv)->len >= blockSize) {
        return mBlock_clone(nullptr, (*iv)->data, blockSize);
    }
    return mBlock_create(blockSize, defaultValue);
}

/**
 * Advanced encryption with PBKDF-based round keys
 */
OES_BLOCK oes_enc_adv(OES_BLOCK plain, OES_KEY key, size_t *session) {
    if (!plain || !plain->data || !key || !key->string) {
        return nullptr;
    }

    size_t cipherLen = closestMultiple(plain->len, OES_BLOCK_SIZE);
    size_t roundSession = session ? *session : 0;

    auto cipher = static_cast<m_block *>(malloc(cipherLen * sizeof(m_block)));
    if (!cipher) {
        return nullptr;
    }

    m_block *data2process = mBlock_padding_einer(plain->data, plain->len, cipherLen, 0);
    if (!data2process) {
        free(cipher);
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += OES_BLOCK_SIZE) {
        m_block **roundKey = PBKDF(key->string, key->len, OES_BLOCK_SIZE, 2, roundSession, 2);
        if (!roundKey || !roundKey[0] || !roundKey[1]) {
            cleanup_pbkdf_keys(roundKey, 2, OES_BLOCK_SIZE);
            secure_memzero(cipher, i * sizeof(m_block));
            free(cipher);
            secure_memzero(data2process, cipherLen * sizeof(m_block));
            free(data2process);
            return nullptr;
        }

        memcpy(&(cipher[i]), &data2process[i], OES_BLOCK_SIZE * sizeof(m_block));
        mBlock_xor(&(cipher[i]), roundKey[0], OES_BLOCK_SIZE, true);
        correlate_data(&(cipher[i]), OES_BLOCK_SIZE, roundSession);
        mBlock_xor(&(cipher[i]), roundKey[1], OES_BLOCK_SIZE, true);

        // Cleanup round keys
        cleanup_pbkdf_keys(roundKey, 2, OES_BLOCK_SIZE);

        roundSession++;
    }

    secure_memzero(data2process, cipherLen * sizeof(m_block));
    free(data2process);

    if (session) {
        *session = roundSession;
    }

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(cipher, cipherLen * sizeof(m_block));
        free(cipher);
        return nullptr;
    }

    OES_block->len = cipherLen;
    OES_block->data = cipher;

    return OES_block;
}

OES_BLOCK oes_dec_adv(OES_BLOCK cipher, OES_KEY key, size_t *session) {
    if (!cipher || !cipher->data || !key || !key->string) {
        return nullptr;
    }

    size_t roundSession = session ? *session : 0;

    auto plain = static_cast<m_block *>(malloc(cipher->len * sizeof(m_block)));
    if (!plain) {
        return nullptr;
    }

    for (size_t i = 0; i < cipher->len; i += OES_BLOCK_SIZE) {
        m_block **roundKey = PBKDF(key->string, key->len, OES_BLOCK_SIZE, 2, roundSession, 2);
        if (!roundKey || !roundKey[0] || !roundKey[1]) {
            cleanup_pbkdf_keys(roundKey, 2, OES_BLOCK_SIZE);
            secure_memzero(plain, i * sizeof(m_block));
            free(plain);
            return nullptr;
        }

        memcpy(&(plain[i]), &cipher->data[i], OES_BLOCK_SIZE * sizeof(m_block));
        mBlock_xor(&(plain[i]), roundKey[1], OES_BLOCK_SIZE, true);
        uncorrelate_data(&(plain[i]), OES_BLOCK_SIZE, roundSession);
        mBlock_xor(&(plain[i]), roundKey[0], OES_BLOCK_SIZE, true);

        // Cleanup round keys
        cleanup_pbkdf_keys(roundKey, 2, OES_BLOCK_SIZE);

        roundSession++;
    }

    if (session) {
        *session = roundSession;
    }

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(plain, cipher->len * sizeof(m_block));
        free(plain);
        return nullptr;
    }

    OES_block->len = cipher->len - mBlock_get_padding_einer(cipher->data, cipher->len, false, 0);
    OES_block->data = plain;

    return OES_block;
}

/**
 * Cipher key expansion (rounded)
 */
OES_BLOCK oes_enc_cke(OES_BLOCK plain, OES_KEY key, m_block seed) {
    if (!plain || !plain->data || !key || !key->string) {
        return nullptr;
    }

    m_block *keyExpanded = key_expansion(key->string, key->len, plain->len, seed, 10);
    if (!keyExpanded) {
        return nullptr;
    }

    m_block *xorKey = key_expansion(key->string, key->len, plain->len, mBlock_rotr(seed, 5), 10);
    if (!xorKey) {
        secure_memzero(keyExpanded, plain->len * sizeof(m_block));
        free(keyExpanded);
        return nullptr;
    }

    m_block *cipher = raw_enc(plain->data, plain->len, keyExpanded);
    if (!cipher) {
        secure_memzero(keyExpanded, plain->len * sizeof(m_block));
        secure_memzero(xorKey, plain->len * sizeof(m_block));
        free(keyExpanded);
        free(xorKey);
        return nullptr;
    }

    mBlock_xor(cipher, xorKey, plain->len, true);

    // Cleanup sensitive data
    secure_memzero(keyExpanded, plain->len * sizeof(m_block));
    secure_memzero(xorKey, plain->len * sizeof(m_block));
    free(keyExpanded);
    free(xorKey);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(cipher, plain->len * sizeof(m_block));
        free(cipher);
        return nullptr;
    }

    OES_block->len = plain->len;
    OES_block->data = cipher;

    return OES_block;
}

OES_BLOCK oes_dec_cke(OES_BLOCK cipher, OES_KEY key, m_block seed) {
    if (!cipher || !cipher->data || !key || !key->string) {
        return nullptr;
    }

    m_block *keyExpanded = key_expansion(key->string, key->len, cipher->len, seed, 10);
    if (!keyExpanded) {
        return nullptr;
    }

    m_block *xorKey = key_expansion(key->string, key->len, cipher->len, mBlock_rotr(seed, 5), 10);
    if (!xorKey) {
        secure_memzero(keyExpanded, cipher->len * sizeof(m_block));
        free(keyExpanded);
        return nullptr;
    }

    // PRIMA: copia i dati del cipher per non modificare l'originale
    m_block *cipher_copy = static_cast<m_block*>(malloc(cipher->len * sizeof(m_block)));
    if (!cipher_copy) {
        secure_memzero(keyExpanded, cipher->len * sizeof(m_block));
        secure_memzero(xorKey, cipher->len * sizeof(m_block));
        free(keyExpanded);
        free(xorKey);
        return nullptr;
    }
    memcpy(cipher_copy, cipher->data, cipher->len * sizeof(m_block));

    // PRIMA: rimuovi lo XOR layer
    mBlock_xor(cipher_copy, xorKey, cipher->len, true);

    // POI: decrypt
    m_block *plain = raw_dec(cipher_copy, cipher->len, keyExpanded);

    // Cleanup della copia
    secure_memzero(cipher_copy, cipher->len * sizeof(m_block));
    free(cipher_copy);

    if (!plain) {
        secure_memzero(keyExpanded, cipher->len * sizeof(m_block));
        secure_memzero(xorKey, cipher->len * sizeof(m_block));
        free(keyExpanded);
        free(xorKey);
        return nullptr;
    }

    // Cleanup sensitive data
    secure_memzero(keyExpanded, cipher->len * sizeof(m_block));
    secure_memzero(xorKey, cipher->len * sizeof(m_block));
    free(keyExpanded);
    free(xorKey);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(plain, cipher->len * sizeof(m_block));
        free(plain);
        return nullptr;
    }

    OES_block->len = cipher->len;
    OES_block->data = plain;

    return OES_block;
}

/**
 * Counter mode encryption
 */
OES_BLOCK oes_enc_ctr(OES_BLOCK plain, OES_KEY key, m_block seed, m_block *counter) {
    if (!plain || !plain->data || !key || !key->string) {
        return nullptr;
    }

    size_t blockSize = MAX(key->len, OES_BLOCK_SIZE);
    size_t cipherLen = closestMultiple(plain->len, blockSize);

    auto cipher = static_cast<m_block *>(malloc(cipherLen * sizeof(m_block)));
    if (!cipher) {
        return nullptr;
    }

    m_block *data2process = mBlock_padding_einer(plain->data, plain->len, cipherLen, 0);
    if (!data2process) {
        free(cipher);
        return nullptr;
    }

    m_block *nonceCounter = mBlock_create(blockSize, seed);
    if (!nonceCounter) {
        free(cipher);
        secure_memzero(data2process, cipherLen * sizeof(m_block));
        free(data2process);
        return nullptr;
    }

    nonceCounter[blockSize - 1] = counter ? *counter : 0;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // CTR mode: encrypt the counter
        m_block *encNonceCounter = raw_enc(nonceCounter, blockSize, key->string);
        if (!encNonceCounter) {
            secure_memzero(cipher, i * sizeof(m_block));
            free(cipher);
            secure_memzero(data2process, cipherLen * sizeof(m_block));
            free(data2process);
            secure_memzero(nonceCounter, blockSize * sizeof(m_block));
            free(nonceCounter);
            return nullptr;
        }

        // Copy plaintext
        m_block *result = mBlock_clone(nullptr, &data2process[i], blockSize);
        if (!result) {
            secure_memzero(cipher, i * sizeof(m_block));
            free(cipher);
            secure_memzero(data2process, cipherLen * sizeof(m_block));
            free(data2process);
            secure_memzero(nonceCounter, blockSize * sizeof(m_block));
            free(nonceCounter);
            secure_memzero(encNonceCounter, blockSize * sizeof(m_block));
            free(encNonceCounter);
            return nullptr;
        }

        // XOR: result = plaintext XOR keystream
        mBlock_xor(result, encNonceCounter, blockSize, true);

        // Copy result to ciphertext
        memcpy(&(cipher[i]), result, blockSize * sizeof(m_block));

        // Free temporary buffers
        secure_memzero(result, blockSize * sizeof(m_block));
        free(result);
        secure_memzero(encNonceCounter, blockSize * sizeof(m_block));
        free(encNonceCounter);

        // Increment counter
        nonceCounter[blockSize - 1]++;
        if (counter) {
            (*counter)++;
        }
    }

    secure_memzero(data2process, cipherLen * sizeof(m_block));
    free(data2process);
    secure_memzero(nonceCounter, blockSize * sizeof(m_block));
    free(nonceCounter);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(cipher, cipherLen * sizeof(m_block));
        free(cipher);
        return nullptr;
    }

    OES_block->len = cipherLen;
    OES_block->data = cipher;

    return OES_block;
}

OES_BLOCK oes_dec_ctr(OES_BLOCK cipher, OES_KEY key, m_block seed, m_block *counter) {
    if (!cipher || !cipher->data || !key || !key->string) {
        return nullptr;
    }

    size_t blockSize = MAX(key->len, OES_BLOCK_SIZE);

    auto plain = static_cast<m_block *>(malloc(cipher->len * sizeof(m_block)));
    if (!plain) {
        return nullptr;
    }

    m_block *nonceCounter = mBlock_create(blockSize, seed);
    if (!nonceCounter) {
        free(plain);
        return nullptr;
    }

    nonceCounter[blockSize - 1] = counter ? *counter : 0;

    for (size_t i = 0; i < cipher->len; i += blockSize) {
        // CTR mode: encrypt the counter
        m_block *encNonceCounter = raw_enc(nonceCounter, blockSize, key->string);
        if (!encNonceCounter) {
            secure_memzero(plain, i * sizeof(m_block));
            free(plain);
            secure_memzero(nonceCounter, blockSize * sizeof(m_block));
            free(nonceCounter);
            return nullptr;
        }

        // Copy ciphertext
        m_block *result = mBlock_clone(nullptr, &(cipher->data[i]), blockSize);
        if (!result) {
            secure_memzero(plain, i * sizeof(m_block));
            free(plain);
            secure_memzero(nonceCounter, blockSize * sizeof(m_block));
            free(nonceCounter);
            secure_memzero(encNonceCounter, blockSize * sizeof(m_block));
            free(encNonceCounter);
            return nullptr;
        }

        // XOR: result = ciphertext XOR keystream
        mBlock_xor(result, encNonceCounter, blockSize, true);

        // Copy result to plaintext
        memcpy(&(plain[i]), result, blockSize * sizeof(m_block));

        // Free temporary buffers
        secure_memzero(result, blockSize * sizeof(m_block));
        free(result);
        secure_memzero(encNonceCounter, blockSize * sizeof(m_block));
        free(encNonceCounter);

        // Increment counter
        nonceCounter[blockSize - 1]++;
        if (counter) {
            (*counter)++;
        }
    }

    secure_memzero(nonceCounter, blockSize * sizeof(m_block));
    free(nonceCounter);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(plain, cipher->len * sizeof(m_block));
        free(plain);
        return nullptr;
    }

    OES_block->len = cipher->len - mBlock_get_padding_einer(cipher->data, cipher->len, false, 0);
    OES_block->data = plain;

    return OES_block;
}

/**
 * Cipher Block Chaining encryption
 */
OES_BLOCK oes_enc_cbc(OES_BLOCK plain, OES_KEY key, OES_BLOCK *iv) {
    if (!plain || !plain->data || !key || !key->string) {
        return nullptr;
    }

    size_t blockSize = MAX(key->len, OES_BLOCK_SIZE);
    size_t cipherLen = closestMultiple(plain->len, blockSize);

    auto cipher = static_cast<m_block *>(malloc(cipherLen * sizeof(m_block)));
    if (!cipher) {
        return nullptr;
    }

    auto *data2process = mBlock_padding_einer(plain->data, plain->len, cipherLen, 0);
    if (!data2process) {
        free(cipher);
        return nullptr;
    }

    // Get a working copy of the IV
    m_block *IV = get_iv_copy(iv, blockSize, m_block(0x455e69f3));
    if (!IV) {
        free(cipher);
        secure_memzero(data2process, cipherLen * sizeof(m_block));
        free(data2process);
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // CBC encryption: ciphertext = encrypt(plaintext XOR IV)

        // Create a copy of current plaintext block
        m_block *temp = mBlock_clone(nullptr, &data2process[i], blockSize);
        if (!temp) {
            secure_memzero(cipher, i * sizeof(m_block));
            free(cipher);
            secure_memzero(data2process, cipherLen * sizeof(m_block));
            free(data2process);
            secure_memzero(IV, blockSize * sizeof(m_block));
            free(IV);
            return nullptr;
        }

        // XOR: temp = temp XOR IV
        mBlock_xor(temp, IV, blockSize, true);

        // Encrypt the XOR result
        m_block *encdata = raw_enc(temp, blockSize, key->string);

        // Free temp (no longer needed)
        secure_memzero(temp, blockSize * sizeof(m_block));
        free(temp);

        if (!encdata) {
            secure_memzero(cipher, i * sizeof(m_block));
            free(cipher);
            secure_memzero(data2process, cipherLen * sizeof(m_block));
            free(data2process);
            secure_memzero(IV, blockSize * sizeof(m_block));
            free(IV);
            return nullptr;
        }

        // Copy ciphertext to output buffer
        memcpy(&(cipher[i]), encdata, blockSize * sizeof(m_block));

        // Update IV for next block: IV = ciphertext[i]
        // Copy encdata to IV (reuse encdata memory)
        secure_memzero(IV, blockSize * sizeof(m_block));
        memcpy(IV, encdata, blockSize * sizeof(m_block));

        secure_memzero(encdata, blockSize * sizeof(m_block));
        free(encdata);
    }

    secure_memzero(data2process, cipherLen * sizeof(m_block));
    free(data2process);

    // Update the caller's IV with the final state
    update_iv(iv, IV, blockSize);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(cipher, cipherLen * sizeof(m_block));
        free(cipher);
        return nullptr;
    }

    OES_block->len = cipherLen;
    OES_block->data = cipher;

    return OES_block;
}

OES_BLOCK oes_dec_cbc(OES_BLOCK cipher, OES_KEY key, OES_BLOCK *iv) {
    if (!cipher || !cipher->data || !key || !key->string) {
        return nullptr;
    }

    size_t blockSize = MAX(key->len, OES_BLOCK_SIZE);

    auto plainData = static_cast<m_block *>(malloc(cipher->len * sizeof(m_block)));
    if (!plainData) {
        return nullptr;
    }

    // Get a working copy of the IV
    m_block *IV = get_iv_copy(iv, blockSize, m_block(0x455e69f3));
    if (!IV) {
        free(plainData);
        return nullptr;
    }

    for (size_t i = 0; i < cipher->len; i += blockSize) {
        // Save ciphertext block before decryption (will become next IV)
        m_block *cipherCopy = mBlock_clone(nullptr, &(cipher->data[i]), blockSize);
        if (!cipherCopy) {
            secure_memzero(plainData, i * sizeof(m_block));
            free(plainData);
            secure_memzero(IV, blockSize * sizeof(m_block));
            free(IV);
            return nullptr;
        }

        // Decrypt the ciphertext block
        m_block *decData = raw_dec(cipherCopy, blockSize, key->string);
        if (!decData) {
            secure_memzero(plainData, i * sizeof(m_block));
            free(plainData);
            secure_memzero(IV, blockSize * sizeof(m_block));
            free(IV);
            free(cipherCopy);
            return nullptr;
        }

        // CBC decryption: plaintext = decrypt(ciphertext) XOR IV
        mBlock_xor(decData, IV, blockSize, true);

        // Copy result to plaintext buffer
        memcpy(&(plainData[i]), decData, blockSize * sizeof(m_block));

        // Free decrypted data
        secure_memzero(decData, blockSize * sizeof(m_block));
        free(decData);

        // Update IV for next block: IV = ciphertext[i]
        secure_memzero(IV, blockSize * sizeof(m_block));
        memcpy(IV, cipherCopy, blockSize * sizeof(m_block));

        free(cipherCopy);
    }

    // Update the caller's IV with the final state
    update_iv(iv, IV, blockSize);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(plainData, cipher->len * sizeof(m_block));
        free(plainData);
        return nullptr;
    }

    OES_block->len = cipher->len - mBlock_get_padding_einer(cipher->data, cipher->len, false, 0);
    OES_block->data = plainData;

    return OES_block;
}

/**
 * Electronic CodeBook encryption
 */
OES_BLOCK oes_enc_ecb(OES_BLOCK plain, OES_KEY key) {
    if (!plain || !plain->data || !key || !key->string) {
        return nullptr;
    }

    size_t blockSize = MAX(key->len, OES_BLOCK_SIZE);
    size_t cipherLen = closestMultiple(plain->len, blockSize);

    auto cipher = static_cast<m_block *>(malloc(cipherLen * sizeof(m_block)));
    if (!cipher) {
        return nullptr;
    }

    auto *data2process = mBlock_padding_einer(plain->data, plain->len, cipherLen, 0);
    if (!data2process) {
        free(cipher);
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        m_block *encdata = raw_enc(&data2process[i], blockSize, key->string);
        if (!encdata) {
            secure_memzero(cipher, i * sizeof(m_block));
            free(cipher);
            secure_memzero(data2process, cipherLen * sizeof(m_block));
            free(data2process);
            return nullptr;
        }

        memcpy(&(cipher[i]), encdata, blockSize * sizeof(m_block));

        secure_memzero(encdata, blockSize * sizeof(m_block));
        free(encdata);
    }

    secure_memzero(data2process, cipherLen * sizeof(m_block));
    free(data2process);

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(cipher, cipherLen * sizeof(m_block));
        free(cipher);
        return nullptr;
    }

    OES_block->len = cipherLen;
    OES_block->data = cipher;

    return OES_block;
}

OES_BLOCK oes_dec_ecb(OES_BLOCK cipher, OES_KEY key) {
    if (!cipher || !cipher->data || !key || !key->string) {
        return nullptr;
    }

    size_t blockSize = MAX(key->len, OES_BLOCK_SIZE);

    auto plainData = static_cast<m_block *>(malloc(cipher->len * sizeof(m_block)));
    if (!plainData) {
        return nullptr;
    }

    for (size_t i = 0; i < cipher->len; i += blockSize) {
        m_block *decData = raw_dec(&(cipher->data[i]), blockSize, key->string);
        if (!decData) {
            secure_memzero(plainData, i * sizeof(m_block));
            free(plainData);
            return nullptr;
        }

        memcpy(&(plainData[i]), decData, blockSize * sizeof(m_block));

        secure_memzero(decData, blockSize * sizeof(m_block));
        free(decData);
    }

    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(plainData, cipher->len * sizeof(m_block));
        free(plainData);
        return nullptr;
    }

    OES_block->data = plainData;
    OES_block->len = cipher->len - mBlock_get_padding_einer(cipher->data, cipher->len, false, 0);

    return OES_block;
}