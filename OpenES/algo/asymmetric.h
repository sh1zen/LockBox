#pragma once

#include "m_block.h"

/**
 * Generate public/private key pair for asymmetric encryption
 * Uses simplified RSA-like algorithm
 *
 * @param p First prime number
 * @param q Second prime number
 * @param publicKey Output MBLOCK* [n, e] where n is modulus, e is public exponent
 * @param privateKey Output MBLOCK* [n, d] where n is modulus, d is private exponent
 * @return true if successful, false otherwise
 *
 * Example:
 *   MBLOCK* publicKey;
 *   MBLOCK* privateKey;
 *   oes_generate_keypair(61, 53, &publicKey, &privateKey);
 *   // Use keys...
 *   delete publicKey;
 *   delete privateKey;
 */
bool oes_generate_keypair(m_block p, m_block q, MBLOCK **publicKey, MBLOCK **privateKey);

/**
 * Asymmetric encryption/decryption
 * For each data block: result = (data^exponent) mod modulus
 *
 * @param data Input MBLOCK
 * @param key Key MBLOCK [modulus, exponent]
 * @param seed Optional seed for additional randomization
 * @return Encrypted/decrypted MBLOCK* (caller must delete)
 *
 * Note: For encryption, use public key. For decryption, use private key.
 */
MBLOCK *oes_asymmetric(const MBLOCK *data, const MBLOCK *key, m_block seed);

/**
 * Encrypt data using public key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param plaintext Input plaintext MBLOCK
 * @param publicKey Public key MBLOCK [modulus, public_exponent]
 * @param seed Optional seed value
 * @return Encrypted MBLOCK* (caller must delete)
 *
 * Example:
 *   MBLOCK* plaintext = MBLOCK::fromBytes("Hello", 5);
 *   MBLOCK* encrypted = oes_public_encrypt(plaintext, publicKey, 0);
 *   // Use encrypted...
 *   delete plaintext;
 *   delete encrypted;
 */
MBLOCK *oes_public_encrypt(const MBLOCK *plaintext, const MBLOCK *publicKey, m_block seed);

/**
 * Decrypt data using private key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param ciphertext Input ciphertext MBLOCK
 * @param privateKey Private key MBLOCK [modulus, private_exponent]
 * @param seed Optional seed value (must match encryption seed)
 * @return Decrypted MBLOCK* (caller must delete)
 *
 * Example:
 *   MBLOCK* decrypted = oes_private_decrypt(ciphertext, privateKey, 0);
 *   auto [bytes, len] = decrypted->toBytes();
 *   // Use bytes...
 *   delete[] bytes;
 *   delete decrypted;
 */
MBLOCK *oes_private_decrypt(const MBLOCK *ciphertext, const MBLOCK *privateKey, m_block seed);

/**
 * Sign data using private key
 * Creates a digital signature by encrypting with private key
 *
 * @param data Data to sign
 * @param privateKey Private key MBLOCK [modulus, private_exponent]
 * @return Signature MBLOCK* (caller must delete)
 *
 * Example:
 *   MBLOCK* data = MBLOCK::fromBytes("message", 7);
 *   MBLOCK* signature = oes_sign(data, privateKey);
 *   // Use signature...
 *   delete data;
 *   delete signature;
 */
MBLOCK *oes_sign(const MBLOCK *data, const MBLOCK *privateKey);

/**
 * Verify signature using public key
 * Verifies that the signature was created with the matching private key
 *
 * @param data Original data
 * @param signature Signature to verify
 * @param publicKey Public key MBLOCK [modulus, public_exponent]
 * @return true if signature is valid, false otherwise
 *
 * Example:
 *   MBLOCK* data = MBLOCK::fromBytes("message", 7);
 *   MBLOCK* signature = oes_sign(data, privateKey);
 *   bool valid = oes_verify(data, signature, publicKey);
 *   delete data;
 *   delete signature;
 */
bool oes_verify(const MBLOCK *data, const MBLOCK *signature, const MBLOCK *publicKey);

/**
 * Hybrid encryption: encrypt data with symmetric key, then encrypt key with public key
 * Combines speed of symmetric encryption with security of asymmetric encryption
 *
 * @param plaintext Data to encrypt
 * @param publicKey Public key for asymmetric encryption
 * @param symmetricKey Symmetric key MBLOCK to use (will be encrypted)
 * @return Encrypted MBLOCK* containing [encrypted_key_len, encrypted_key, encrypted_data]
 *         (caller must delete)
 *
 * Example:
 *   MBLOCK* plaintext = MBLOCK::fromBytes("secret data", 11);
 *   MBLOCK* symKey = MBLOCK::create(4, 0x12345678);
 *   MBLOCK* encrypted = oes_hybrid_encrypt(plaintext, publicKey, symKey);
 *   // Use encrypted...
 *   delete plaintext;
 *   delete symKey;
 *   delete encrypted;
 */
MBLOCK *oes_hybrid_encrypt(const MBLOCK *plaintext, const MBLOCK *publicKey, const MBLOCK *symmetricKey);

/**
 * Hybrid decryption: decrypt symmetric key with private key, then decrypt data
 * Counterpart to oes_hybrid_encrypt
 *
 * @param ciphertext Encrypted data from oes_hybrid_encrypt
 * @param privateKey Private key for asymmetric decryption
 * @return Decrypted MBLOCK* (caller must delete)
 *
 * Example:
 *   MBLOCK* decrypted = oes_hybrid_decrypt(ciphertext, privateKey);
 *   auto [bytes, len] = decrypted->toBytes();
 *   // Use bytes...
 *   delete[] bytes;
 *   delete decrypted;
 */
MBLOCK *oes_hybrid_decrypt(const MBLOCK *ciphertext, const MBLOCK *privateKey);
