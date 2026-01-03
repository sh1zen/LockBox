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
#include "utils.h"

// Helper function to get or create IV
static MBLOCK *get_or_create_iv(MBLOCK *iv, size_t blockSize, m_block defaultValue) {
    if (!iv || iv->isNull()) {
        // Se IV non esiste, creane uno nuovo con valore di default
        return MBLOCK::create(blockSize, defaultValue);
    }

    // Clona solo se necessario
    if (iv->getLen() >= blockSize) {
        return iv->clone();
    }

    // Altrimenti estendi in-place la copia
    MBLOCK *iv_copy = iv->clone();
    iv_copy->extend(blockSize, defaultValue);
    return iv_copy;
}

MBLOCK *oes_enc_adv(const MBLOCK *plain, const MBLOCK *key, size_t *session) {
    if (!plain || plain->isNull() || !key || key->isNull()) return nullptr;

    const size_t pLen = plain->getLen();
    const size_t cLen = closestMultiple(pLen + 2, OES_NUM_OF_BLOCK);
    size_t ses = session ? *session : 0;

    std::unique_ptr<MBLOCK> c(plain->add_padding_outer(cLen, 0));
    if (!c) return nullptr;

    // Inserisci random nel padding
    c->setBlock(cLen - 2, OES_RNG().next64());

    c->rotr(2);

    // NUOVO: Diffusione globale PRIMA della cifratura a blocchi
    global_diffuse(c.get(), ses);

    // Cifratura a blocchi (invariata)
    for (size_t i = 0; i < cLen; i += OES_NUM_OF_BLOCK) {
        const size_t bLen = std::min(static_cast<size_t>(OES_NUM_OF_BLOCK), cLen - i);

        auto rk = PBKDF(*key, OES_NUM_OF_BLOCK, 2, ses, 16);
        if (rk.size() != 2 || !rk[0] || !rk[1]) {
            cleanup_pbkdf_keys(rk);
            return nullptr;
        }

        for (size_t j = 0; j < bLen; ++j)
            c->setBlock(i + j, c->getBlock(i + j) ^ rk[0]->getBlock(j));

        correlate_data(c.get(), ses);

        for (size_t j = 0; j < bLen; ++j)
            c->setBlock(i + j, c->getBlock(i + j) ^ rk[1]->getBlock(j));

        cleanup_pbkdf_keys(rk);
        ++ses;
    }

    if (session) *session = ses;
    return c.release();
}

MBLOCK *oes_dec_adv(const MBLOCK *cipher, const MBLOCK *key, size_t *session) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) return nullptr;

    const size_t cLen = cipher->getLen();
    size_t ses = session ? *session : 0;
    const size_t originalSes = ses; // Salva per la diffusione inversa

    std::unique_ptr<MBLOCK> p(cipher->clone());
    if (!p) return nullptr;

    // Decifratura a blocchi (invariata)
    for (size_t i = 0; i < cLen; i += OES_NUM_OF_BLOCK) {
        const size_t bLen = std::min(static_cast<size_t>(OES_NUM_OF_BLOCK), cLen - i);

        auto rk = PBKDF(*key, OES_NUM_OF_BLOCK, 2, ses, 16);
        if (rk.size() != 2 || !rk[0] || !rk[1]) {
            cleanup_pbkdf_keys(rk);
            return nullptr;
        }

        for (size_t j = 0; j < bLen; ++j)
            p->setBlock(i + j, p->getBlock(i + j) ^ rk[1]->getBlock(j));

        uncorrelate_data(p.get(), ses);

        for (size_t j = 0; j < bLen; ++j)
            p->setBlock(i + j, p->getBlock(i + j) ^ rk[0]->getBlock(j));

        cleanup_pbkdf_keys(rk);
        ++ses;
    }

    // NUOVO: Diffusione globale inversa DOPO la decifratura a blocchi
    global_diffuse_inv(p.get(), originalSes);

    p->rotl(2);
    if (session) *session = ses;

    // Rimuovi padding
    const size_t pad = p->get_padding_size_outer();
    const size_t outLen = cLen - pad;

    MBLOCK *res = MBLOCK::create(outLen, 0);
    if (!res) return nullptr;

    for (size_t i = 0; i < outLen; ++i)
        res->setBlock(i, p->getBlock(i));

    return res;
}


/**
 * Cipher key expansion (rounded)
 */
MBLOCK *oes_enc_cke(const MBLOCK *plain, const MBLOCK *key, m_block seed) {
    if (!plain || plain->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t len = plain->getLen();

    // Espansione chiave
    std::unique_ptr<MBLOCK> keyExpanded(key_expansion(key, len, seed, 10));
    if (!keyExpanded || keyExpanded->isNull()) return nullptr;

    std::unique_ptr<MBLOCK> xorKey(key_expansion(key, len, mBlock::rotr(seed, 5), 10));
    if (!xorKey || xorKey->isNull()) return nullptr;

    // Cifratura
    std::unique_ptr<MBLOCK> cipherBlock(SPHINX::encrypt(plain, keyExpanded.get()));
    if (!cipherBlock || cipherBlock->isNull()) return nullptr;

    // XOR alternato direttamente sul risultato
    for (size_t i = 0; i < len; i += 1) {
        cipherBlock->setBlock(i, cipherBlock->getBlock(i) ^ xorKey->getBlock(i));
    }

    return cipherBlock.release();
}

MBLOCK *oes_dec_cke(const MBLOCK *cipher, const MBLOCK *key, m_block seed) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t len = cipher->getLen();

    std::unique_ptr<MBLOCK> keyExpanded(key_expansion(key, len, seed, 10));
    if (!keyExpanded || keyExpanded->isNull()) return nullptr;

    std::unique_ptr<MBLOCK> xorKey(key_expansion(key, len, mBlock::rotr(seed, 5), 10));
    if (!xorKey || xorKey->isNull()) return nullptr;

    // Clona cipher per XOR
    std::unique_ptr<MBLOCK> cipherCopy(cipher->clone());

    for (size_t i = 0; i < len; i += 1) {
        cipherCopy->setBlock(i, cipherCopy->getBlock(i) ^ xorKey->getBlock(i));
    }

    // Decrypt
    std::unique_ptr<MBLOCK> plainBlock(SPHINX::decrypt(cipherCopy.get(), keyExpanded.get()));

    return plainBlock.release();
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

    // Padded plaintext
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Cipher output
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    // Nonce/counter block
    const std::unique_ptr<MBLOCK> nonceCounterBlock(MBLOCK::create(blockSize, seed));
    if (!nonceCounterBlock) {
        delete cipher;
        return nullptr;
    }

    // Initialize counter
    nonceCounterBlock->setBlock(blockSize - 1, counter ? *counter : 0);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt nonce/counter
        std::unique_ptr<MBLOCK> encNonceCounter(SPHINX::encrypt(nonceCounterBlock.get(), key));
        if (!encNonceCounter || encNonceCounter->isNull()) {
            delete cipher;
            return nullptr;
        }

        // XOR plaintext block with encrypted nonce
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            cipher->setBlock(i + j, paddedPlain->getBlock(i + j) ^ encNonceCounter->getBlock(j));
        }

        // Increment counter
        m_block currentCounter = nonceCounterBlock->getBlock(blockSize - 1);
        nonceCounterBlock->setBlock(blockSize - 1, currentCounter + 1);
        if (counter) (*counter)++;
    }

    return cipher;
}


MBLOCK *oes_dec_ctr(const MBLOCK *cipher, const MBLOCK *key, m_block seed, m_block *counter) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t cipherLen = cipher->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);

    // Plaintext MBLOCK
    MBLOCK *plain = MBLOCK::create(cipherLen, 0);
    if (!plain) return nullptr;

    // Nonce/counter block
    std::unique_ptr<MBLOCK> nonceCounterBlock(MBLOCK::create(blockSize, seed));
    if (!nonceCounterBlock) {
        delete plain;
        return nullptr;
    }

    // Initialize counter
    nonceCounterBlock->setBlock(blockSize - 1, counter ? *counter : 0);

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Encrypt current nonce/counter block
        std::unique_ptr<MBLOCK> encNonceCounter(SPHINX::encrypt(nonceCounterBlock.get(), key));
        if (!encNonceCounter || encNonceCounter->isNull()) {
            delete plain;
            return nullptr;
        }

        // XOR cipher block with encrypted nonce
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, cipher->getBlock(i + j) ^ encNonceCounter->getBlock(j));
        }

        // Increment counter
        m_block currentCounter = nonceCounterBlock->getBlock(blockSize - 1);
        nonceCounterBlock->setBlock(blockSize - 1, currentCounter + 1);
        if (counter) (*counter)++;
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    // Create final result MBLOCK
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < outLen; ++i) {
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

    // Padded plaintext
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Cipher output
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    // Previous block starts with IV
    const std::unique_ptr<MBLOCK> prevBlock(get_or_create_iv(iv ? *iv : nullptr, blockSize, REPLICATE_BITS(0x4569)));
    if (!prevBlock) {
        delete cipher;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // XOR plaintext block with previous cipher block (or IV)
        MBLOCK *xorBlock = MBLOCK::create(blockSize, 0);
        if (!xorBlock) {
            delete cipher;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            xorBlock->setBlock(j, paddedPlain->getBlock(i + j) ^ prevBlock->getBlock(j));
        }

        // Encrypt the XORed block
        std::unique_ptr<MBLOCK> encData(SPHINX::encrypt(xorBlock, key));
        delete xorBlock;

        if (!encData || encData->isNull()) {
            delete cipher;
            return nullptr;
        }

        // Copy encrypted block to cipher
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            cipher->setBlock(i + j, encData->getBlock(j));
        }

        // Update prevBlock for next iteration
        for (size_t j = 0; j < blockSize; ++j) {
            prevBlock->setBlock(j, encData->getBlock(j));
        }
    }

    // Update IV with last cipher block
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

    size_t cipherLen = cipher->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);

    // Plaintext MBLOCK
    MBLOCK *plain = MBLOCK::create(cipherLen, 0);
    if (!plain) return nullptr;

    // Previous block starts with IV
    const std::unique_ptr<MBLOCK> prevBlock(get_or_create_iv(iv ? *iv : nullptr, blockSize, REPLICATE_BITS(0x4569)));
    if (!prevBlock) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Copy current cipher block
        MBLOCK *currentCipherBlock = MBLOCK::create(blockSize, 0);
        if (!currentCipherBlock) {
            delete plain;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            currentCipherBlock->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt block
        std::unique_ptr<MBLOCK> decData(SPHINX::decrypt(currentCipherBlock, key));
        delete currentCipherBlock;

        if (!decData || decData->isNull()) {
            delete plain;
            return nullptr;
        }

        // XOR with previous block
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, decData->getBlock(j) ^ prevBlock->getBlock(j));
        }

        // Update prevBlock to current cipher block for next iteration
        for (size_t j = 0; j < blockSize; ++j) {
            prevBlock->setBlock(j, cipher->getBlock(i + j));
        }
    }

    // Update IV with the last cipher block
    if (iv && *iv) {
        delete *iv;
        *iv = MBLOCK::create(blockSize, 0);
        if (*iv) {
            for (size_t j = 0; j < blockSize; ++j) {
                (*iv)->setBlock(j, cipher->getBlock(cipherLen - blockSize + j));
            }
        }
    }

    plain->dump();

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    // Create result MBLOCK
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    for (size_t i = 0; i < outLen; ++i) {
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

    // Create padded plain MBLOCK
    std::unique_ptr<MBLOCK> paddedPlain(plain->add_padding_outer(cipherLen, 0));
    if (!paddedPlain) return nullptr;

    // Create cipher MBLOCK
    MBLOCK *cipher = MBLOCK::create(cipherLen, 0);
    if (!cipher) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Create block for encryption
        MBLOCK *blockData = MBLOCK::create(blockSize, 0);
        if (!blockData) {
            delete cipher;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            blockData->setBlock(j, paddedPlain->getBlock(i + j));
        }

        // Encrypt block
        std::unique_ptr<MBLOCK> encData(SPHINX::encrypt(blockData, key));
        delete blockData;

        if (!encData || encData->isNull()) {
            delete cipher;
            return nullptr;
        }

        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            cipher->setBlock(i + j, encData->getBlock(j));
        }
    }

    return cipher;
}

MBLOCK *oes_dec_ecb(const MBLOCK *cipher, const MBLOCK *key) {
    if (!cipher || cipher->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t cipherLen = cipher->getLen();
    size_t keyLen = key->getLen();
    size_t blockSize = MAX(keyLen, OES_NUM_OF_BLOCK);

    // Create plain MBLOCK with ownership
    MBLOCK *plain = MBLOCK::create(cipherLen, 0);
    if (!plain) return nullptr;

    for (size_t i = 0; i < cipherLen; i += blockSize) {
        // Create block directly from cipher data without extra copies
        MBLOCK *blockData = MBLOCK::create(blockSize, 0);
        if (!blockData) {
            delete plain;
            return nullptr;
        }

        // Fill blockData from cipher
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            blockData->setBlock(j, cipher->getBlock(i + j));
        }

        // Decrypt block
        const std::unique_ptr<MBLOCK> decData(SPHINX::decrypt(blockData, key));
        delete blockData;

        if (!decData || decData->isNull()) {
            delete plain;
            return nullptr;
        }

        // Copy decrypted block into plain
        for (size_t j = 0; j < blockSize && (i + j) < cipherLen; ++j) {
            plain->setBlock(i + j, decData->getBlock(j));
        }
    }

    // Remove padding
    uint32_t padding = plain->get_padding_size_outer();
    size_t outLen = (cipherLen >= padding) ? cipherLen - padding : 0;

    // Create final result MBLOCK
    MBLOCK *result = MBLOCK::create(outLen, 0);
    if (!result) {
        delete plain;
        return nullptr;
    }

    // Copy only necessary blocks
    for (size_t i = 0; i < outLen; ++i) {
        result->setBlock(i, plain->getBlock(i));
    }

    delete plain;
    return result;
}
