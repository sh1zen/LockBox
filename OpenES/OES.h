#ifndef LOCKBOX_OES_H
#define LOCKBOX_OES_H

#include "oes_common.h"

#define DEFAULT_CKE_STREAM_INITIALIZER 0x3C46C64A

class OES {

protected:

    // original key
    OES_KEY oKey = nullptr;
    // active working key
    OES_KEY wKey = nullptr;

    OES_BLOCK plainBlock = nullptr;
    OES_BLOCK cipherBlock = nullptr;

    // Stream state variables
    // IV is an OES_BLOCK that holds the initialization vector
    OES_BLOCK IV = nullptr;

    // Counter for CTR mode
    m_block ctrCounter = 0;

    // Stream data for CKE mode
    m_block ckeStreamData = static_cast<m_block>(DEFAULT_CKE_STREAM_INITIALIZER);

    // Session counter for ADV mode
    size_t advSession = 0;

    // Internal helper to reset IV
    void resetIV();

public:

    // Stream mode flag - when true, state is preserved between operations
    bool streamMode = false;

    // Constructor
    OES();

    // Destructor
    ~OES();

    // Non-copyable to prevent double-free issues
    OES(const OES&) = delete;
    OES& operator=(const OES&) = delete;

    // Movable
    OES(OES&& other) noexcept;
    OES& operator=(OES&& other) noexcept;

    void set_key(char *keyString);

    void deriveWKey(const char *keySalt, size_t length = 10);

    void extendWKey(size_t strength = 16, m_block salt = m_block(0x451a569e));

    OES *load_data(void *data, size_t length = 0);

    /**
     * Load cipher data (for decryption operations)
     * @param data Raw cipher data buffer
     * @param length Length in bytes
     */
    OES *load_cipher_data(void *data, size_t length);

    /**
     * Load cipher block data directly (for decryption operations)
     * @param data Array of m_block values
     * @param blockCount Number of m_block elements
     */
    OES *load_cipher_block(m_block *data, size_t blockCount);

    std::pair<void *, size_t> get_data();

    void resetBlocks();

    void resetStreamState();

    /**
     * Set a custom IV from an array of m_block values
     * @param iv Array of m_block values (ownership is NOT transferred - data is copied)
     * @param len Number of m_block elements in the array
     */
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

    static std::pair<void *, size_t> exportBlock(OES_BLOCK block, int mode = OES_EXPORT_RAW);

    OES_BLOCK get_cipherBlock() const { return this->cipherBlock; }
    OES_BLOCK get_plainBlock() const { return this->plainBlock; }

#ifdef DEBUG
    OES_KEY get_oKey() const { return this->oKey; }
    OES_KEY get_wKey() const { return this->wKey; }
#endif
};

#endif //LOCKBOX_OES_H