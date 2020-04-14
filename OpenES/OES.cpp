#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <utility>

#include "OES.h"
#include "oes_common.h"
#include "block-interface.h"
#include "block_ciphers.h"
#include "converter.h"
#include "defines.h"
#include "hashing.h"
#include "key_managment.h"
#include "oes-exception.h"
#include "support.h"


OES::OES() {
    this->oKey = static_cast<OES_KEY>(malloc(sizeof(oeskey)));
    if (this->oKey) {
        this->oKey->string = nullptr;
        this->oKey->len = 0;
    }

    this->wKey = static_cast<OES_KEY>(malloc(sizeof(oeskey)));
    if (this->wKey) {
        this->wKey->string = nullptr;
        this->wKey->len = 0;
    }

    // All other members are initialized in class definition
}

OES::~OES() {
    unset_cipher(&this->wKey);
    unset_cipher(&this->oKey);
    unset_block(&this->plainBlock);
    unset_block(&this->cipherBlock);
    unset_block(&this->IV);
}

// Move constructor
OES::OES(OES&& other) noexcept
    : oKey(other.oKey)
    , wKey(other.wKey)
    , plainBlock(other.plainBlock)
    , cipherBlock(other.cipherBlock)
    , IV(other.IV)
    , ctrCounter(other.ctrCounter)
    , ckeStreamData(other.ckeStreamData)
    , advSession(other.advSession)
    , streamMode(other.streamMode)
{
    // Null out the source to prevent double-free
    other.oKey = nullptr;
    other.wKey = nullptr;
    other.plainBlock = nullptr;
    other.cipherBlock = nullptr;
    other.IV = nullptr;
}

// Move assignment operator
OES& OES::operator=(OES&& other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        unset_cipher(&this->wKey);
        unset_cipher(&this->oKey);
        unset_block(&this->plainBlock);
        unset_block(&this->cipherBlock);
        unset_block(&this->IV);

        // Move resources from other
        this->oKey = other.oKey;
        this->wKey = other.wKey;
        this->plainBlock = other.plainBlock;
        this->cipherBlock = other.cipherBlock;
        this->IV = other.IV;
        this->ctrCounter = other.ctrCounter;
        this->ckeStreamData = other.ckeStreamData;
        this->advSession = other.advSession;
        this->streamMode = other.streamMode;

        // Null out the source
        other.oKey = nullptr;
        other.wKey = nullptr;
        other.plainBlock = nullptr;
        other.cipherBlock = nullptr;
        other.IV = nullptr;
    }
    return *this;
}

void OES::resetBlocks() {
    update_block(&(this->cipherBlock), nullptr, 0);
    update_block(&(this->plainBlock), nullptr, 0);
}

void OES::resetStreamState() {
    this->ctrCounter = 0;
    this->ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);
    this->advSession = 0;

    this->resetIV();
}

void OES::resetIV() {
    unset_block(&this->IV);
}

void OES::setIV(const m_block *iv, size_t len) {
    // Reset any existing IV first
    this->resetIV();

    if (!iv || len == 0) {
        return;
    }

    // Allocate the IV block structure
    this->IV = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!this->IV) {
        return;
    }

    // Allocate and copy the IV data
    this->IV->data = static_cast<m_block*>(malloc(len * sizeof(m_block)));
    if (!this->IV->data) {
        free(this->IV);
        this->IV = nullptr;
        return;
    }

    memcpy(this->IV->data, iv, len * sizeof(m_block));
    this->IV->len = len;
}

void OES::setCtrCounter(m_block counter) {
    this->ctrCounter = counter;
}

void OES::setCkeStreamData(m_block data) {
    this->ckeStreamData = data;
}

OES *OES::hash(size_t hashLen) {
    if (!this->plainBlock || !this->plainBlock->data) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente l'IV
    if (!this->streamMode) {
        this->resetIV();
    }

    m_block *hash_result = oes_raw_hash(this->plainBlock->data, this->plainBlock->len, hashLen, &this->IV);
    if (!hash_result) {
        return this;
    }

    update_block(&(this->cipherBlock), hash_result, hashLen);

    return this;
}

OES *OES::hmac(size_t hmacLen) {
    if (!this->wKey || !this->wKey->string || !this->plainBlock || !this->plainBlock->data) {
        return this;
    }

    m_block *hmac_result = oes_raw_hmac(
        this->wKey->string,
        this->wKey->len,
        this->plainBlock->data,
        this->plainBlock->len,
        hmacLen
    );

    if (!hmac_result) {
        throw OESException("Invalid hmac generation");
    }

    update_block(&this->cipherBlock, hmac_result, hmacLen);

    return this;
}

OES *OES::enc_ecb() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    OES_BLOCK result = oes_enc_ecb(this->plainBlock, this->wKey);
    if (!result) {
        return this;
    }

    move_block(&(this->cipherBlock), result);

    return this;
}

OES *OES::dec_ecb() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    OES_BLOCK result = oes_dec_ecb(this->cipherBlock, this->wKey);
    if (!result) {
        return this;
    }

    move_block(&(this->plainBlock), result);

    return this;
}

OES *OES::enc_cbc() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente l'IV
    if (!this->streamMode) {
        this->resetIV();
    }

    // Pass a pointer to IV - oes_enc_cbc will update it with the new IV state
    OES_BLOCK result = oes_enc_cbc(this->plainBlock, this->wKey, &this->IV);
    if (!result) {
        return this;
    }

    move_block(&(this->cipherBlock), result);

    return this;
}

OES *OES::dec_cbc() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente l'IV
    if (!this->streamMode) {
        this->resetIV();
    }

    // Pass a pointer to IV - oes_dec_cbc will update it with the new IV state
    OES_BLOCK result = oes_dec_cbc(this->cipherBlock, this->wKey, &this->IV);
    if (!result) {
        return this;
    }

    move_block(&(this->plainBlock), result);

    return this;
}

OES *OES::enc_ctr() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente il counter
    if (!this->streamMode) {
        this->ctrCounter = 0;
    }

    OES_BLOCK result = oes_enc_ctr(this->plainBlock, this->wKey, m_block(0xa54ff53a), &this->ctrCounter);
    if (!result) {
        return this;
    }

    move_block(&(this->cipherBlock), result);

    return this;
}

OES *OES::dec_ctr() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente il counter
    if (!this->streamMode) {
        this->ctrCounter = 0;
    }

    OES_BLOCK result = oes_dec_ctr(this->cipherBlock, this->wKey, m_block(0xa54ff53a), &this->ctrCounter);
    if (!result) {
        return this;
    }

    move_block(&(this->plainBlock), result);

    return this;
}

OES *OES::enc_cke() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente il stream data
    if (!this->streamMode) {
        this->ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);
    }

    OES_BLOCK result = oes_enc_cke(this->plainBlock, this->wKey, this->ckeStreamData);
    if (!result) {
        return this;
    }

    move_block(&(this->cipherBlock), result);

    if (this->streamMode && this->cipherBlock && this->cipherBlock->data && this->cipherBlock->len > 0) {
        this->ckeStreamData = this->cipherBlock->data[this->cipherBlock->len - 1];
    }

    return this;
}

OES *OES::dec_cke() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente il stream data
    if (!this->streamMode) {
        this->ckeStreamData = m_block(DEFAULT_CKE_STREAM_INITIALIZER);
    }

    // In stream mode, salva l'ultimo blocco del ciphertext PRIMA della decifratura
    // perché sarà il ckeStreamData per il prossimo chunk
    m_block nextStreamData = this->ckeStreamData;
    if (this->streamMode && this->cipherBlock->data && this->cipherBlock->len > 0) {
        nextStreamData = this->cipherBlock->data[this->cipherBlock->len - 1];
    }

    OES_BLOCK result = oes_dec_cke(this->cipherBlock, this->wKey, this->ckeStreamData);
    if (!result) {
        return this;
    }

    move_block(&(this->plainBlock), result);

    // Aggiorna ckeStreamData per il prossimo chunk
    if (this->streamMode) {
        this->ckeStreamData = nextStreamData;
    }

    return this;
}

OES *OES::enc_adv() {
    if (!this->plainBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente la session
    if (!this->streamMode) {
        this->advSession = 0;
    }

    OES_BLOCK result = oes_enc_adv(this->plainBlock, this->wKey, &this->advSession);
    if (!result) {
        return this;
    }

    move_block(&(this->cipherBlock), result);

    return this;
}

OES *OES::dec_adv() {
    if (!this->cipherBlock || !this->wKey) {
        return this;
    }

    // Se non in streamMode, resetta automaticamente la session
    if (!this->streamMode) {
        this->advSession = 0;
    }

    const OES_BLOCK result = oes_dec_adv(this->cipherBlock, this->wKey, &this->advSession);
    if (!result) {
        return this;
    }

    move_block(&(this->plainBlock), result);

    return this;
}

OES *OES::swap() {
    swap_pointers(reinterpret_cast<void **>(&this->cipherBlock), reinterpret_cast<void **>(&this->plainBlock));
    return this;
}

OES *OES::asymmetric() {
    if (!this->plainBlock || !this->plainBlock->data || !this->wKey || !this->wKey->string) {
        return this;
    }

    OES_BLOCK result = oes_asymmetric(
        this->plainBlock->data,
        this->plainBlock->len,
        this->wKey->string,
        this->wKey->len,
        0
    );

    if (!result) {
        return this;
    }

    move_block(&(this->cipherBlock), result);

    return this;
}

std::pair<void *, size_t> OES::exportBlock(OES_BLOCK block, int mode) {
    if (!block || !block->data) {
        return std::make_pair(nullptr, 0);
    }

    switch (mode) {
        case OES_EXPORT_HEX: {
            auto result = oes_export_block_to_hex_string(block);
            return std::make_pair(result.first, result.second);
        }

        case OES_EXPORT_UINT8:
            return toBytes(block->data, block->len);

        case OES_EXPORT_CHAR: {
            auto result = oes_export_block_to_string(block);
            return std::make_pair(result.first, result.second);
        }

        case OES_EXPORT_BASE64: {
            auto result = oes_export_block_to_base64(block);
            return std::make_pair(result.first, result.second);
        }

        case OES_EXPORT_RAW:
        default: {
            // Crea una copia della memoria invece di restituire il puntatore interno
            size_t byteSize = block->len * sizeof(m_block);
            m_block *copy = static_cast<m_block *>(malloc(byteSize));
            if (!copy) {
                return std::make_pair(nullptr, 0);
            }
            std::memcpy(copy, block->data, byteSize);
            return std::make_pair(copy, block->len);
        }
    }
}

OES *OES::dump(bool printable) {
    if (this->oKey && this->oKey->string) {
        printf("originalKey::");
        mBlock_dump(this->oKey->string, this->oKey->len, printable);
    }
    if (this->wKey && this->wKey->string) {
        printf("workingKey::");
        mBlock_dump(this->wKey->string, this->wKey->len, printable);
    }
    if (this->plainBlock && this->plainBlock->data) {
        printf("PlainBlock::");
        mBlock_dump(this->plainBlock->data, this->plainBlock->len, printable);
    }
    if (this->cipherBlock && this->cipherBlock->data) {
        printf("CipherBlock::");
        mBlock_dump(this->cipherBlock->data, this->cipherBlock->len, printable);
    }
    puts("");

    return this;
}

void OES::set_key(char *keyString) {
    if (!keyString || !this->oKey || !this->wKey) {
        return;
    }

    size_t keyStrLen = strlen(keyString);
    if (keyStrLen == 0) {
        return;
    }

    // Clean up old key
    if (this->oKey->string) {
        secure_memzero(this->oKey->string, this->oKey->len * sizeof(m_block));
        free(this->oKey->string);
        this->oKey->string = nullptr;
        this->oKey->len = 0;
    }

    OES_BLOCK key_block = toOESBlock(keyString, keyStrLen);
    if (!key_block) {
        return;
    }

    this->oKey->string = key_block->data;
    this->oKey->len = key_block->len;

    // Free just the structure, not the data (ownership transferred)
    free(key_block);

    // Update working key
    if (this->wKey->string) {
        secure_memzero(this->wKey->string, this->wKey->len * sizeof(m_block));
        free(this->wKey->string);
        this->wKey->string = nullptr;
        this->wKey->len = 0;
    }

    // Clone the original key to working key
    this->wKey->string = static_cast<m_block*>(malloc(this->oKey->len * sizeof(m_block)));
    if (this->wKey->string) {
        memcpy(this->wKey->string, this->oKey->string, this->oKey->len * sizeof(m_block));
        this->wKey->len = this->oKey->len;
    }
}

void OES::deriveWKey(const char *keySalt, size_t length) {
    if (!keySalt || !this->oKey || !this->oKey->string || !this->wKey || length == 0) {
        return;
    }

    size_t saltLen = strlen(keySalt);
    if (saltLen == 0) {
        return;
    }

    OES_BLOCK keySaltBlock = toOESBlock(const_cast<char *>(keySalt), saltLen);
    if (!keySaltBlock) {
        return;
    }

    if (this->wKey->string) {
        secure_memzero(this->wKey->string, this->wKey->len * sizeof(m_block));
        free(this->wKey->string);
        this->wKey->string = nullptr;
        this->wKey->len = 0;
    }

    this->wKey->string = oes_raw_hmac(
        this->oKey->string,
        this->oKey->len,
        keySaltBlock->data,
        keySaltBlock->len,
        length
    );

    if (this->wKey->string) {
        this->wKey->len = length;
    }

    unset_block(&keySaltBlock);
}

void OES::extendWKey(size_t strength, m_block salt) {
    if (!this->oKey || !this->oKey->string || !this->wKey || strength == 0) {
        return;
    }

    if (this->wKey->string) {
        secure_memzero(this->wKey->string, this->wKey->len * sizeof(m_block));
        free(this->wKey->string);
        this->wKey->string = nullptr;
        this->wKey->len = 0;
    }

    this->wKey->string = key_expansion(this->oKey->string, this->oKey->len, strength, salt, 1);

    if (this->wKey->string) {
        this->wKey->len = strength;
    }
}

OES *OES::load_data(void *data, size_t length) {
    if (!data || length == 0) {
        throw OESException("Invalid data passed");
    }

    // Clear existing blocks
    unset_block(&(this->plainBlock));
    update_block(&(this->cipherBlock), nullptr, 0);

    this->plainBlock = toOESBlock(data, length);

    return this;
}

OES *OES::load_cipher_data(void *data, size_t length) {
    if (!data || length == 0) {
        throw OESException("Invalid cipher data passed");
    }

    // Clear existing blocks
    unset_block(&(this->cipherBlock));
    update_block(&(this->plainBlock), nullptr, 0);

    this->cipherBlock = toOESBlock(data, length);

    return this;
}

OES *OES::load_cipher_block(m_block *data, size_t blockCount) {
    if (!data || blockCount == 0) {
        throw OESException("Invalid cipher block data passed");
    }

    // Clear existing blocks
    unset_block(&(this->cipherBlock));
    update_block(&(this->plainBlock), nullptr, 0);

    // Allocate and copy the block data directly
    this->cipherBlock = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!this->cipherBlock) {
        throw OESException("Failed to allocate cipher block");
    }

    this->cipherBlock->data = static_cast<m_block*>(malloc(blockCount * sizeof(m_block)));
    if (!this->cipherBlock->data) {
        free(this->cipherBlock);
        this->cipherBlock = nullptr;
        throw OESException("Failed to allocate cipher block data");
    }

    std::memcpy(this->cipherBlock->data, data, blockCount * sizeof(m_block));
    this->cipherBlock->len = blockCount;

    return this;
}

std::pair<void*, size_t> OES::get_data() {
    if (!this->plainBlock || !this->plainBlock->data) {
        return std::make_pair(nullptr, 0);
    }
    return toBytes(this->plainBlock->data, this->plainBlock->len);
}