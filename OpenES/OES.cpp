#include <cstdio>
#include <cstring>
#include <utility>

#include "asymmetric.h"
#include "block_ciphers.h"
#include "m_block.h"
#include "hashing.h"
#include "key_management.h"
#include "oes-exception.h"
#include "OES.h"

#include <memory>

OES::OES() = default;

OES::~OES() {
    if (oKey) {
        oKey->secure_zero();
        delete oKey;
        oKey = nullptr;
    }
    if (wKey) {
        wKey->secure_zero();
        delete wKey;
        wKey = nullptr;
    }
    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
        plainBlock = nullptr;
    }
    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
        cipherBlock = nullptr;
    }
    if (IV) {
        IV->secure_zero();
        delete IV;
        IV = nullptr;
    }
}

OES::OES(OES &&other) noexcept
    : oKey(other.oKey)
      , wKey(other.wKey)
      , plainBlock(other.plainBlock)
      , cipherBlock(other.cipherBlock)
      , IV(other.IV)
      , ctrCounter(other.ctrCounter)
      , ckeStreamData(other.ckeStreamData)
      , advSession(other.advSession)
      , streamMode(other.streamMode) {
    other.oKey = nullptr;
    other.wKey = nullptr;
    other.plainBlock = nullptr;
    other.cipherBlock = nullptr;
    other.IV = nullptr;
}

OES &OES::operator=(OES &&other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        if (oKey) {
            oKey->secure_zero();
            delete oKey;
        }
        if (wKey) {
            wKey->secure_zero();
            delete wKey;
        }
        if (plainBlock) {
            plainBlock->secure_zero();
            delete plainBlock;
        }
        if (cipherBlock) {
            cipherBlock->secure_zero();
            delete cipherBlock;
        }
        if (IV) {
            IV->secure_zero();
            delete IV;
        }

        // Transfer ownership
        this->oKey = other.oKey;
        this->wKey = other.wKey;
        this->plainBlock = other.plainBlock;
        this->cipherBlock = other.cipherBlock;
        this->IV = other.IV;
        this->ctrCounter = other.ctrCounter;
        this->ckeStreamData = other.ckeStreamData;
        this->advSession = other.advSession;
        this->streamMode = other.streamMode;

        other.oKey = nullptr;
        other.wKey = nullptr;
        other.plainBlock = nullptr;
        other.cipherBlock = nullptr;
        other.IV = nullptr;
    }
    return *this;
}

void OES::resetBlocks() {
    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
        cipherBlock = nullptr;
    }
    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
        plainBlock = nullptr;
    }
}

void OES::resetStreamState() {
    this->ctrCounter = 0;
    this->ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);
    this->advSession = 0;
    this->resetIV();
}

void OES::resetIV() {
    if (IV) {
        IV->secure_zero();
        delete IV;
        IV = nullptr;
    }
}


void OES::setIV(const m_block *iv, size_t len) {
    this->resetIV();

    if (!iv || len == 0) {
        return;
    }

    auto ivData = new m_block[len];
    std::memcpy(ivData, iv, len * sizeof(m_block));

    this->streamMode = true;

    this->IV = new MBLOCK(ivData, len, true);
}

void OES::setCtrCounter(m_block counter) {
    this->ctrCounter = counter;
}

void OES::setCkeStreamData(m_block data) {
    this->ckeStreamData = data;
}

OES *OES::hash(size_t hashLen) {
    if (!this->plainBlock || this->plainBlock->isNull()) {
        return this;
    }

    if (!this->streamMode) {
        this->resetIV();
    }

    MBLOCK *hash_result = oes_raw_hash(this->plainBlock, hashLen, &this->IV);
    if (!hash_result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = hash_result;

    return this;
}

OES *OES::hmac(size_t hmacLen) {
    if (!this->wKey || this->wKey->isNull() || !this->plainBlock || this->plainBlock->isNull()) {
        return this;
    }

    MBLOCK *hmac_result = oes_raw_hmac(this->wKey, this->plainBlock, hmacLen);

    if (!hmac_result) {
        throw OESException("Invalid hmac generation");
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = hmac_result;

    return this;
}

OES *OES::enc_ecb() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    MBLOCK *result = oes_enc_ecb(this->plainBlock, this->wKey);
    if (!result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = result;

    return this;
}

OES *OES::dec_ecb() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    MBLOCK *result = oes_dec_ecb(this->cipherBlock, this->wKey);
    if (!result) {
        return this;
    }

    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
    }
    this->plainBlock = result;

    return this;
}

OES *OES::enc_cbc() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->resetIV();
    }

    MBLOCK *result = oes_enc_cbc(this->plainBlock, this->wKey, &this->IV);
    if (!result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = result;

    return this;
}

OES *OES::dec_cbc() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->resetIV();
    }

    MBLOCK *result = oes_dec_cbc(this->cipherBlock, this->wKey, &this->IV);
    if (!result) {
        return this;
    }

    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
    }
    this->plainBlock = result;

    return this;
}

OES *OES::enc_ctr() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->ctrCounter = 0;
    }

    MBLOCK *result = oes_enc_ctr(this->plainBlock, this->wKey, m_block(0xa54ff53a), &this->ctrCounter);
    if (!result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = result;

    return this;
}

OES *OES::dec_ctr() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->ctrCounter = 0;
    }

    MBLOCK *result = oes_dec_ctr(this->cipherBlock, this->wKey, m_block(0xa54ff53a), &this->ctrCounter);
    if (!result) {
        return this;
    }

    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
    }
    this->plainBlock = result;

    return this;
}

OES *OES::enc_cke() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);
    }

    MBLOCK *result = oes_enc_cke(this->plainBlock, this->wKey, this->ckeStreamData);
    if (!result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = result;

    if (this->streamMode  && !this->cipherBlock->isNull() && this->cipherBlock->getLen() > 0) {
        this->ckeStreamData = this->cipherBlock->getBlock(this->cipherBlock->getLen() - 1);
    }

    return this;
}

OES *OES::dec_cke() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);
    }

    m_block nextStreamData = this->ckeStreamData;
    if (this->streamMode && !this->cipherBlock->isNull() && this->cipherBlock->getLen() > 0) {
        nextStreamData = this->cipherBlock->getBlock(this->cipherBlock->getLen() - 1);
    }

    MBLOCK *result = oes_dec_cke(this->cipherBlock, this->wKey, this->ckeStreamData);
    if (!result) {
        return this;
    }

    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
    }
    this->plainBlock = result;

    if (this->streamMode) {
        this->ckeStreamData = nextStreamData;
    }

    return this;
}

OES *OES::enc_adv() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->advSession = 0;
    }

    MBLOCK *result = oes_enc_adv(this->plainBlock, this->wKey, &this->advSession);
    if (!result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = result;

    return this;
}

OES *OES::dec_adv() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    if (!this->streamMode) {
        this->advSession = 0;
    }

    MBLOCK *result = oes_dec_adv(this->cipherBlock, this->wKey, &this->advSession);
    if (!result) {
        return this;
    }

    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
    }
    this->plainBlock = result;

    return this;
}

OES *OES::swap() {
    MBLOCK *temp = this->cipherBlock;
    this->cipherBlock = this->plainBlock;
    this->plainBlock = temp;
    return this;
}

OES *OES::asymmetric() {
    if (!this->plainBlock || this->plainBlock->isNull() || !this->wKey || this->wKey->isNull()) {
        return this;
    }

    MBLOCK *result = oes_asymmetric(this->plainBlock, this->wKey, 0);

    if (!result) {
        return this;
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
    }
    this->cipherBlock = result;

    return this;
}

OES *OES::dump(const bool printable) {
    if (this->oKey && !this->oKey->isNull()) {
        printf("originalKey::");
        this->oKey->dump(printable);
    }
    if (this->wKey && !this->wKey->isNull()) {
        printf("workingKey::");
        this->wKey->dump(false);
    }
    if (this->plainBlock && !this->plainBlock->isNull()) {
        printf("PlainBlock [%llu]::", this->plainBlock->getBytesLen());
        this->plainBlock->dump(printable);
    }
    if (this->cipherBlock && !this->cipherBlock->isNull()) {
        printf("CipherBlock::");
        this->cipherBlock->dump(false);
    }
    puts("");

    return this;
}

void OES::set_key(char *keyString) {
    if (!keyString) {
        return;
    }

    size_t keyStrLen = strlen(keyString);
    if (keyStrLen == 0) {
        return;
    }

    // Clean up old keys
    if (oKey) {
        oKey->secure_zero();
        delete oKey;
        oKey = nullptr;
    }

    // Create new key from string
    MBLOCK *key_block = MBLOCK::fromBytes(keyString, keyStrLen);
    if (!key_block) {
        return;
    }

    this->oKey = key_block;

    // Clone to working key
    if (wKey) {
        wKey->secure_zero();
        delete wKey;
        wKey = nullptr;
    }

    this->wKey = this->oKey->clone();
}

void OES::deriveWKey(const char *keySalt, size_t length) {
    if (!keySalt || !this->oKey || this->oKey->isNull() || length == 0) {
        return;
    }

    size_t saltLen = strlen(keySalt);
    if (saltLen == 0) {
        return;
    }

    MBLOCK *keySaltBlock = MBLOCK::fromBytes(keySalt, saltLen);
    if (!keySaltBlock || keySaltBlock->isNull()) {
        delete keySaltBlock;
        return;
    }

    if (this->wKey) {
        this->wKey->secure_zero();
        delete this->wKey;
        this->wKey = nullptr;
    }

    this->wKey = oes_raw_hmac(this->oKey, keySaltBlock, length);

    delete keySaltBlock;
}

void OES::extendWKey(size_t strength, m_block salt) {
    if (!this->oKey || this->oKey->isNull() || strength == 0) {
        return;
    }

    if (this->wKey) {
        this->wKey->secure_zero();
        delete this->wKey;
        this->wKey = nullptr;
    }

    this->wKey = key_expansion(this->oKey, strength, salt, 1);
}

OES *OES::load_data_raw(void *data, size_t length) {
    if (!data || length == 0) {
        throw OESException("Invalid data passed");
    }

    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
        plainBlock = nullptr;
    }
    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
        cipherBlock = nullptr;
    }

    this->plainBlock = MBLOCK::fromBytes(data, length);

    return this;
}

OES *OES::load_cipher_data_raw(void *data, size_t length) {
    if (!data || length == 0) {
        throw OESException("Invalid cipher data passed");
    }

    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
        cipherBlock = nullptr;
    }
    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
        plainBlock = nullptr;
    }

    this->cipherBlock = MBLOCK::fromBytes(data, length);

    return this;
}

OES *OES::load_cipher_block(MBLOCK *data, bool take_ownership) {
    if (!data || data->isNull() || data->getLen() == 0) {
        throw OESException("Invalid cipher block data passed");
    }

    // Pulisci i blocchi esistenti
    if (cipherBlock) {
        cipherBlock->secure_zero();
        delete cipherBlock;
        cipherBlock = nullptr;
    }
    if (plainBlock) {
        plainBlock->secure_zero();
        delete plainBlock;
        plainBlock = nullptr;
    }

    if (take_ownership) {
        this->cipherBlock = data;
    } else {
        this->cipherBlock = data->clone();
    }

    return this;
}

std::pair<void *, size_t> OES::get_data() {
    if (!this->plainBlock || this->plainBlock->isNull()) {
        return std::make_pair(nullptr, 0);
    }
    return this->plainBlock->toBytes();
}
