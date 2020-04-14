#ifndef ASYMMETRIC_H
#define ASYMMETRIC_H

#include "oes_common.h"

/**
 * Generate public/private key pair for asymmetric encryption
 * Uses simplified RSA-like algorithm
 *
 * @param p First prime number
 * @param q Second prime number
 * @param publicKey Output array [n, e] where n is modulus, e is public exponent
 * @param privateKey Output array [n, d] where n is modulus, d is private exponent
 * @return true if successful, false otherwise
 *
 * Example:
 *   m_block publicKey[2];
 *   m_block privateKey[2];
 *   oes_generate_keypair(61, 53, publicKey, privateKey);
 */
bool oes_generate_keypair(m_block p, m_block q, m_block* publicKey, m_block* privateKey);

/**
 * Asymmetric encryption/decryption
 * For each data block: result = (data^exponent) mod modulus
 *
 * @param data Input data array
 * @param dataLen Length of data array
 * @param key Key array [modulus, exponent]
 * @param keyLen Length of key array (must be >= 2)
 * @param seed Optional seed for additional randomization
 * @return Encrypted/decrypted OES_BLOCK (caller must free with unset_block)
 *
 * Note: For encryption, use public key. For decryption, use private key.
 */
OES_BLOCK oes_asymmetric(const m_block* data, size_t dataLen, const m_block* key, size_t keyLen, m_block seed);

/**
 * Encrypt data using public key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param plaintext Input plaintext block
 * @param publicKey Public key [modulus, public_exponent]
 * @param seed Optional seed value
 * @return Encrypted OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_public_encrypt(OES_BLOCK plaintext, const m_block* publicKey, m_block seed);

/**
 * Decrypt data using private key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param ciphertext Input ciphertext block
 * @param privateKey Private key [modulus, private_exponent]
 * @param seed Optional seed value (must match encryption seed)
 * @return Decrypted OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_private_decrypt(OES_BLOCK ciphertext, const m_block* privateKey, m_block seed);

/**
 * Sign data using private key
 * Creates a digital signature by encrypting with private key
 *
 * @param data Data to sign
 * @param privateKey Private key [modulus, private_exponent]
 * @return Signature OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_sign(OES_BLOCK data, const m_block* privateKey);

/**
 * Verify signature using public key
 * Verifies that the signature was created with the matching private key
 *
 * @param data Original data
 * @param signature Signature to verify
 * @param publicKey Public key [modulus, public_exponent]
 * @return true if signature is valid, false otherwise
 */
bool oes_verify(OES_BLOCK data, OES_BLOCK signature, const m_block* publicKey);

/**
 * Hybrid encryption: encrypt data with symmetric key, then encrypt key with public key
 * Combines speed of symmetric encryption with security of asymmetric encryption
 *
 * @param plaintext Data to encrypt
 * @param publicKey Public key for asymmetric encryption
 * @param symmetricKey Symmetric key to use (will be encrypted)
 * @param symmetricKeyLen Length of symmetric key
 * @return Encrypted OES_BLOCK containing [encrypted_key_len, encrypted_key, encrypted_data]
 *         (caller must free with unset_block)
 */
OES_BLOCK oes_hybrid_encrypt(OES_BLOCK plaintext, const m_block* publicKey,
                             const m_block* symmetricKey, size_t symmetricKeyLen);

/**
 * Hybrid decryption: decrypt symmetric key with private key, then decrypt data
 * Counterpart to oes_hybrid_encrypt
 *
 * @param ciphertext Encrypted data from oes_hybrid_encrypt
 * @param privateKey Private key for asymmetric decryption
 * @param symmetricKeyLen Expected length of symmetric key
 * @return Decrypted OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_hybrid_decrypt(OES_BLOCK ciphertext, const m_block* privateKey, size_t symmetricKeyLen);

#endif // ASYMMETRIC_H