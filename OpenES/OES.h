#ifndef LOCKBOX_OES_H
#define LOCKBOX_OES_H

#include "m_block.h"

#define DEFAULT_CKE_STREAM_INITIALIZER 0x3C46C64A

class OES {
protected:
    MBLOCK* oKey = nullptr;
    MBLOCK* wKey = nullptr;

    MBLOCK* plainBlock = nullptr;
    MBLOCK* cipherBlock = nullptr;
    MBLOCK* IV = nullptr;

    m_block ctrCounter = 0;
    m_block ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);
    size_t advSession = 0;

    void resetIV();

public:
    bool streamMode = false;

    OES();
    ~OES();

    OES(const OES &) = delete;
    OES &operator=(const OES &) = delete;

    OES(OES &&other) noexcept;
    OES &operator=(OES &&other) noexcept;

    void set_key(char *keyString);

    void deriveWKey(const char *keySalt, size_t length = 10);

    void extendWKey(size_t strength = 16, m_block salt = static_cast<m_block>(MASK_TO_BLOCK_SIZE(0x451a569e, 0x451a569e)));

    OES *load_data_raw(void *data, size_t length = 0);

    OES *load_cipher_data_raw(void *data, size_t length);

    OES *load_cipher_block(MBLOCK* data, bool take_ownership = false);

    std::pair<void *, size_t> get_data();

    void resetBlocks();

    void resetStreamState();

    void setIV(const m_block *iv, size_t len);

    void setCtrCounter(m_block counter);

    void setCkeStreamData(m_block data);

    OES *hash(size_t hashLen = 16);

    OES *hmac(size_t hmacLen = 16);

    OES *enc_ecb();

    OES *dec_ecb();

    OES *enc_cbc();

    OES *dec_cbc();

    OES *enc_ctr();

    OES *dec_ctr();

    OES *enc_cke();

    OES *dec_cke();

    OES *enc_adv();

    OES *dec_adv();

    OES *asymmetric();

    OES *swap();

    OES *dump(bool printable = false);

    [[nodiscard]] MBLOCK *get_cipherBlock() const {
        return cipherBlock ? cipherBlock->clone() : nullptr;
    }

    [[nodiscard]] MBLOCK *get_plainBlock() const {
        return plainBlock ? plainBlock->clone() : nullptr;
    }

#ifdef DEBUG
    [[nodiscard]] MBLOCK *get_oKey() const { return oKey ? oKey->clone() : nullptr; }
    [[nodiscard]] MBLOCK *get_wKey() const { return wKey ? wKey->clone() : nullptr; }
#endif
};

#endif // LOCKBOX_OES_H
