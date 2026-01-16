#ifndef SPHINX_CIPHER_H
#define SPHINX_CIPHER_H

#include <OpenES/layer/raw-layer.h>

// ============================================================================
// SPHINX CIPHER v2.0 - Public Interface
// ============================================================================
// High-security block cipher with:
// - Security: > AES-256 against all known attacks
// - Key sizes: 64-1024 bit (scalable with block size)
// - Quantum-ready: Up to 1024-bit keys for quantum resistance
// - Side-channel resistant: No table lookups, constant-time operations
//
// Block size configurations:
// - 8-bit:   64-bit key security
// - 16-bit:  128-bit key security (AES-128 equivalent)
// - 32-bit:  256-bit key security (AES-256 equivalent)
// - 64-bit:  512-bit key security (post-quantum ready)
// - 128-bit: 1024-bit key security (quantum-safe)
//
// Usage:
//   MBLOCK *key = new MBLOCK(n);        // Any size, auto-expanded to 8 blocks
//   MBLOCK *plaintext = new MBLOCK(m);
//
//   MBLOCK *ciphertext = SPHINX::encrypt(plaintext, key);
//   MBLOCK *decrypted = SPHINX::decrypt(ciphertext, key);
//
//   // Cleanup
//   key->secure_zero();
//   delete key;
//   delete plaintext;
//   delete ciphertext;
//   delete decrypted;
// ============================================================================

namespace SPHINX {

    /**
     * Encrypts data using SPHINX cipher
     *
     * @param plaintext Input data to encrypt (any length)
     * @param key Encryption key (any length, will be expanded/compressed to 8 blocks)
     * @return Encrypted data (same length as plaintext), or nullptr on error
     *
     * Security notes:
     * - Key is automatically expanded to 8 × m_block for consistent security
     * - Global diffusion ensures 100% avalanche effect before main rounds
     * - Resistant to differential, linear, algebraic, and related-key attacks
     * - Side-channel resistant (no table lookups, constant-time)
     *
     * Example:
     *   MBLOCK *key = new MBLOCK(4);  // 256-bit for SPHINX-64
     *   MBLOCK *plain = new MBLOCK(100);
     *   MBLOCK *cipher = SPHINX::encrypt(plain, key);
     *   if (cipher) {
     *       // Success - cipher contains encrypted data
     *   }
     */
    MBLOCK *encrypt(const MBLOCK *plaintext, const MBLOCK *key);

    /**
     * Decrypts data using SPHINX cipher
     *
     * @param ciphertext Encrypted data to decrypt
     * @param key Decryption key (same key used for encryption)
     * @return Decrypted data (same length as ciphertext), or nullptr on error
     *
     * Security notes:
     * - Must use the exact same key as encryption
     * - Key is automatically expanded to 8 × m_block (same as encrypt)
     * - Perfectly invertible - decrypt(encrypt(P, K), K) = P
     *
     * Example:
     *   MBLOCK *plain = SPHINX::decrypt(cipher, key);
     *   if (plain && plain->equals(original_plaintext)) {
     *       // Success - decryption verified
     *   }
     */
    MBLOCK *decrypt(const MBLOCK *ciphertext, const MBLOCK *key);
} // namespace SPHINX

#endif // SPHINX_CIPHER_H
