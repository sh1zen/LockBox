#ifndef LOCKBOX_BLOCK_CIPHERS_H
#define LOCKBOX_BLOCK_CIPHERS_H

#include "oes_common.h"

/**
 * CBC (Cipher Block Chaining) encryption
 * @param plain Plaintext block to encrypt
 * @param key Encryption key
 * @param iv Pointer to IV block. If nullptr or *iv is nullptr, default IV is used.
 *           After encryption, *iv is updated to contain the new IV state (for stream mode).
 *           The caller retains ownership but the data inside may be replaced.
 * @return New OES_BLOCK containing ciphertext (caller must free), or nullptr on error
 */
OES_BLOCK oes_enc_cbc(OES_BLOCK plain, OES_KEY key, OES_BLOCK *iv = nullptr);

/**
 * CBC (Cipher Block Chaining) decryption
 * @param cipher Ciphertext block to decrypt
 * @param key Decryption key
 * @param iv Pointer to IV block. If nullptr or *iv is nullptr, default IV is used.
 *           After decryption, *iv is updated to contain the new IV state (for stream mode).
 *           The caller retains ownership but the data inside may be replaced.
 * @return New OES_BLOCK containing plaintext (caller must free), or nullptr on error
 */
OES_BLOCK oes_dec_cbc(OES_BLOCK cipher, OES_KEY key, OES_BLOCK *iv = nullptr);

/**
 * ECB (Electronic CodeBook) encryption
 * @param plain Plaintext block to encrypt
 * @param key Encryption key
 * @return New OES_BLOCK containing ciphertext (caller must free), or nullptr on error
 */
OES_BLOCK oes_enc_ecb(OES_BLOCK plain, OES_KEY key);

/**
 * ECB (Electronic CodeBook) decryption
 * @param cipher Ciphertext block to decrypt
 * @param key Decryption key
 * @return New OES_BLOCK containing plaintext (caller must free), or nullptr on error
 */
OES_BLOCK oes_dec_ecb(OES_BLOCK cipher, OES_KEY key);

/**
 * CTR (Counter) mode encryption
 * @param plain Plaintext block to encrypt
 * @param key Encryption key
 * @param seed Initial seed/nonce value
 * @param counter Pointer to counter value. Updated after encryption for stream mode.
 * @return New OES_BLOCK containing ciphertext (caller must free), or nullptr on error
 */
OES_BLOCK oes_enc_ctr(OES_BLOCK plain, OES_KEY key, m_block seed, m_block *counter = nullptr);

/**
 * CTR (Counter) mode decryption
 * @param cipher Ciphertext block to decrypt
 * @param key Decryption key
 * @param seed Initial seed/nonce value
 * @param counter Pointer to counter value. Updated after decryption for stream mode.
 * @return New OES_BLOCK containing plaintext (caller must free), or nullptr on error
 */
OES_BLOCK oes_dec_ctr(OES_BLOCK cipher, OES_KEY key, m_block seed, m_block *counter = nullptr);

/**
 * CKE (Cipher Key Expansion) encryption
 * @param plain Plaintext block to encrypt
 * @param key Encryption key
 * @param seed Seed for key expansion
 * @return New OES_BLOCK containing ciphertext (caller must free), or nullptr on error
 */
OES_BLOCK oes_enc_cke(OES_BLOCK plain, OES_KEY key, m_block seed = static_cast<m_block>(0x3C46C64A));

/**
 * CKE (Cipher Key Expansion) decryption
 * @param cipher Ciphertext block to decrypt
 * @param key Decryption key
 * @param seed Seed for key expansion
 * @return New OES_BLOCK containing plaintext (caller must free), or nullptr on error
 */
OES_BLOCK oes_dec_cke(OES_BLOCK cipher, OES_KEY key, m_block seed = static_cast<m_block>(0x3C46C64A));

/**
 * ADV (Advanced) encryption with PBKDF-based round keys
 * @param plain Plaintext block to encrypt
 * @param key Encryption key
 * @param session Pointer to session counter. Updated after encryption for stream mode.
 * @return New OES_BLOCK containing ciphertext (caller must free), or nullptr on error
 */
OES_BLOCK oes_enc_adv(OES_BLOCK plain, OES_KEY key, size_t *session = nullptr);

/**
 * ADV (Advanced) decryption with PBKDF-based round keys
 * @param cipher Ciphertext block to decrypt
 * @param key Decryption key
 * @param session Pointer to session counter. Updated after decryption for stream mode.
 * @return New OES_BLOCK containing plaintext (caller must free), or nullptr on error
 */
OES_BLOCK oes_dec_adv(OES_BLOCK cipher, OES_KEY key, size_t *session = nullptr);

/**
 * Asymmetric encryption/operation
 * @param data Input data
 * @param dataLen Length of input data
 * @param key Key data
 * @param keyLen Length of key
 * @param seed Seed value
 * @return New OES_BLOCK containing result (caller must free), or nullptr on error
 */
OES_BLOCK oes_asymmetric(const m_block *data, size_t dataLen, const m_block *key, size_t keyLen, m_block seed);

#endif //LOCKBOX_BLOCK_CIPHERS_H