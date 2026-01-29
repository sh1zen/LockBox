#pragma once

#include "m_block.h"

/**
 * CBC (Cipher Block Chaining) encryption
 * @param plain Plaintext MBLOCK to encrypt
 * @param key Encryption key MBLOCK
 * @param iv Pointer to IV MBLOCK. If nullptr or *iv is nullptr, default IV is used.
 *           After encryption, *iv is updated to contain the new IV state (for stream mode).
 *           The caller retains ownership but the data inside may be replaced.
 * @return New MBLOCK* containing ciphertext (caller must delete), or nullptr on error
 */
MBLOCK* oes_enc_cbc(const MBLOCK* plain, const MBLOCK* key, MBLOCK** iv = nullptr);

/**
 * CBC (Cipher Block Chaining) decryption
 * @param cipher Ciphertext MBLOCK to decrypt
 * @param key Decryption key MBLOCK
 * @param iv Pointer to IV MBLOCK. If nullptr or *iv is nullptr, default IV is used.
 *           After decryption, *iv is updated to contain the new IV state (for stream mode).
 *           The caller retains ownership but the data inside may be replaced.
 * @return New MBLOCK* containing plaintext (caller must delete), or nullptr on error
 */
MBLOCK* oes_dec_cbc(const MBLOCK* cipher, const MBLOCK* key, MBLOCK** iv = nullptr);

/**
 * ECB (Electronic CodeBook) encryption
 * @param plain Plaintext MBLOCK to encrypt
 * @param key Encryption key MBLOCK
 * @return New MBLOCK* containing ciphertext (caller must delete), or nullptr on error
 */
MBLOCK* oes_enc_ecb(const MBLOCK* plain, const MBLOCK* key);

/**
 * ECB (Electronic CodeBook) decryption
 * @param cipher Ciphertext MBLOCK to decrypt
 * @param key Decryption key MBLOCK
 * @return New MBLOCK* containing plaintext (caller must delete), or nullptr on error
 */
MBLOCK* oes_dec_ecb(const MBLOCK* cipher, const MBLOCK* key);

/**
 * CTR (Counter) mode encryption
 * @param plain Plaintext MBLOCK to encrypt
 * @param key Encryption key MBLOCK
 * @param seed Initial seed/nonce value
 * @param counter Pointer to counter value. Updated after encryption for stream mode.
 * @return New MBLOCK* containing ciphertext (caller must delete), or nullptr on error
 */
MBLOCK* oes_enc_ctr(const MBLOCK* plain, const MBLOCK* key, m_block seed, m_block* counter = nullptr);

/**
 * CTR (Counter) mode decryption
 * @param cipher Ciphertext MBLOCK to decrypt
 * @param key Decryption key MBLOCK
 * @param seed Initial seed/nonce value
 * @param counter Pointer to counter value. Updated after decryption for stream mode.
 * @return New MBLOCK* containing plaintext (caller must delete), or nullptr on error
 */
MBLOCK* oes_dec_ctr(const MBLOCK* cipher, const MBLOCK* key, m_block seed, m_block* counter = nullptr);

/**
 * CKE (Cipher Key Expansion) encryption
 * @param plain Plaintext MBLOCK to encrypt
 * @param key Encryption key MBLOCK
 * @param seed Seed for key expansion
 * @return New MBLOCK* containing ciphertext (caller must delete), or nullptr on error
 */
MBLOCK* oes_enc_cke(const MBLOCK* plain, const MBLOCK* key, m_block seed = static_cast<m_block>(0x3C46C64A));

/**
 * CKE (Cipher Key Expansion) decryption
 * @param cipher Ciphertext MBLOCK to decrypt
 * @param key Decryption key MBLOCK
 * @param seed Seed for key expansion
 * @return New MBLOCK* containing plaintext (caller must delete), or nullptr on error
 */
MBLOCK* oes_dec_cke(const MBLOCK* cipher, const MBLOCK* key, m_block seed = static_cast<m_block>(0x3C46C64A));

/**
 * ADV (Advanced) encryption with PBKDF-based round keys
 * @param plain Plaintext MBLOCK to encrypt
 * @param key Encryption key MBLOCK
 * @param session Pointer to session counter. Updated after encryption for stream mode.
 * @return New MBLOCK* containing ciphertext (caller must delete), or nullptr on error
 */
MBLOCK* oes_enc_adv(const MBLOCK* plain, const MBLOCK* key, size_t* session = nullptr);

/**
 * ADV (Advanced) decryption with PBKDF-based round keys
 * @param cipher Ciphertext MBLOCK to decrypt
 * @param key Decryption key MBLOCK
 * @param session Pointer to session counter. Updated after decryption for stream mode.
 * @return New MBLOCK* containing plaintext (caller must delete), or nullptr on error
 */
MBLOCK* oes_dec_adv(const MBLOCK* cipher, const MBLOCK* key, size_t* session = nullptr);
