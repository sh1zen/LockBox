#include <cstdlib>
#include <iostream>
#include <cstring>

#include "asymmetric.h"
#include <OpenES/support/support.h>

#include "oes_common.h"

/**
 * Modular exponentiation: (base^exp) mod modulus
 * Uses the square-and-multiply algorithm for efficiency
 *
 * @param base Base value
 * @param exp Exponent
 * @param modulus Modulus
 * @return (base^exp) mod modulus
 */
static m_block mod_exp(m_block base, m_block exp, m_block modulus) {
    if (modulus == 1) {
        return 0;
    }

    m_block result = 1;
    base = base % modulus;

    while (exp > 0) {
        // If exp is odd, multiply base with result
        if (exp & 1) {
            result = (result * base) % modulus;
        }

        // exp must be even now
        exp = exp >> 1; // exp = exp / 2
        base = (base * base) % modulus;
    }

    return result;
}

/**
 * Extended Euclidean Algorithm
 * Computes gcd(a, b) and coefficients x, y such that ax + by = gcd(a,b)
 *
 * @param a First number
 * @param b Second number
 * @param x Pointer to store x coefficient
 * @param y Pointer to store y coefficient
 * @return gcd(a, b)
 */
static m_block extended_gcd(m_block a, m_block b, m_block* x, m_block* y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }

    m_block x1, y1;
    m_block gcd = extended_gcd(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

/**
 * Compute modular multiplicative inverse
 * Returns x such that (a * x) mod m = 1
 *
 * @param a Number to invert
 * @param m Modulus
 * @return Modular inverse, or 0 if it doesn't exist
 */
static m_block mod_inverse(m_block a, m_block m) {
    m_block x, y;
    m_block gcd = extended_gcd(a, m, &x, &y);

    if (gcd != 1) {
        return 0; // Modular inverse doesn't exist
    }

    // Make x positive
    m_block result = (x % m + m) % m;
    return result;
}

/**
 * Generate public/private key pair for asymmetric encryption
 * Uses simplified RSA-like algorithm
 *
 * @param p First prime number
 * @param q Second prime number
 * @param publicKey Output array [n, e] where n is modulus, e is public exponent
 * @param privateKey Output array [n, d] where n is modulus, d is private exponent
 * @return true if successful, false otherwise
 */
bool oes_generate_keypair(m_block p, m_block q, m_block* publicKey, m_block* privateKey) {
    if (!publicKey || !privateKey) {
        return false;
    }

    // Compute n = p * q
    m_block n = p * q;

    // Compute Euler's totient: φ(n) = (p-1)(q-1)
    m_block phi = (p - 1) * (q - 1);

    // Choose e (public exponent) - commonly 65537 or just use a smaller value
    m_block e = 65537;
    if (e >= phi) {
        e = 3; // Fallback to smaller value
    }

    // Ensure gcd(e, phi) = 1
    m_block x, y;
    while (extended_gcd(e, phi, &x, &y) != 1) {
        e += 2; // Try next odd number
        if (e >= phi) {
            return false;
        }
    }

    // Compute d (private exponent) = e^(-1) mod φ(n)
    m_block d = mod_inverse(e, phi);
    if (d == 0) {
        return false;
    }

    // Public key: (n, e)
    publicKey[0] = n;
    publicKey[1] = e;

    // Private key: (n, d)
    privateKey[0] = n;
    privateKey[1] = d;

    return true;
}

/**
 * Asymmetric encryption/decryption
 * For each data block: encrypted = (data^exp) mod modulus
 *
 * @param data Input data array
 * @param dataLen Length of data array
 * @param key Key array [modulus, exponent]
 * @param keyLen Length of key array (must be >= 2)
 * @param seed Optional seed for additional randomization (currently unused)
 * @return Encrypted/decrypted OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_asymmetric(const m_block* data, size_t dataLen, const m_block* key, size_t keyLen, m_block seed) {
    // Input validation
    if (!data || dataLen == 0 || !key || keyLen < 2) {
        return nullptr;
    }

    m_block modulus = key[0];
    m_block exponent = key[1];

    // Validate modulus
    if (modulus <= 1) {
        return nullptr;
    }

    // Allocate output buffer
    auto encodedData = static_cast<m_block*>(malloc(dataLen * sizeof(m_block)));
    if (!encodedData) {
        return nullptr;
    }

    // Apply modular exponentiation to each block
    for (size_t i = 0; i < dataLen; i++) {
        // Ensure data block is less than modulus
        m_block block = data[i] % modulus;

        // Apply transformation: block^exponent mod modulus
        encodedData[i] = mod_exp(block, exponent, modulus);

        // Optional: XOR with seed-derived value for additional entropy
        if (seed != 0) {
            m_block seedValue = mod_exp(seed + i, exponent, modulus);
            encodedData[i] ^= seedValue;
        }
    }

    // Create output block
    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(encodedData, dataLen * sizeof(m_block));
        free(encodedData);
        return nullptr;
    }

    OES_block->len = dataLen;
    OES_block->data = encodedData;

    return OES_block;
}

/**
 * Encrypt data using public key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param plaintext Input plaintext block
 * @param publicKey Public key [modulus, public_exponent]
 * @param seed Optional seed value
 * @return Encrypted OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_public_encrypt(OES_BLOCK plaintext, const m_block* publicKey, m_block seed) {
    if (!plaintext || !plaintext->data || !publicKey) {
        return nullptr;
    }

    return oes_asymmetric(plaintext->data, plaintext->len, publicKey, 2, seed);
}

/**
 * Decrypt data using private key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param ciphertext Input ciphertext block
 * @param privateKey Private key [modulus, private_exponent]
 * @param seed Optional seed value (must match encryption seed)
 * @return Decrypted OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_private_decrypt(OES_BLOCK ciphertext, const m_block* privateKey, m_block seed) {
    if (!ciphertext || !ciphertext->data || !privateKey) {
        return nullptr;
    }

    return oes_asymmetric(ciphertext->data, ciphertext->len, privateKey, 2, seed);
}

/**
 * Sign data using private key
 *
 * @param data Data to sign
 * @param privateKey Private key [modulus, private_exponent]
 * @return Signature OES_BLOCK (caller must free with unset_block)
 */
OES_BLOCK oes_sign(OES_BLOCK data, const m_block* privateKey) {
    if (!data || !data->data || !privateKey) {
        return nullptr;
    }

    // For signing, we typically hash the data first
    // Here we'll just sign the data directly for simplicity
    return oes_asymmetric(data->data, data->len, privateKey, 2, 0);
}

/**
 * Verify signature using public key
 *
 * @param data Original data
 * @param signature Signature to verify
 * @param publicKey Public key [modulus, public_exponent]
 * @return true if signature is valid, false otherwise
 */
bool oes_verify(OES_BLOCK data, OES_BLOCK signature, const m_block* publicKey) {
    if (!data || !data->data || !signature || !signature->data || !publicKey) {
        return false;
    }

    // Decrypt signature
    OES_BLOCK decrypted = oes_asymmetric(signature->data, signature->len, publicKey, 2, 0);
    if (!decrypted) {
        return false;
    }

    // Compare with original data
    bool valid = true;
    if (decrypted->len != data->len) {
        valid = false;
    } else {
        for (size_t i = 0; i < data->len; i++) {
            if (decrypted->data[i] != data->data[i]) {
                valid = false;
                break;
            }
        }
    }

    // Cleanup
    unset_block(&decrypted);

    return valid;
}

/**
 * Hybrid encryption: encrypt data with symmetric key, then encrypt key with public key
 *
 * @param plaintext Data to encrypt
 * @param publicKey Public key for asymmetric encryption
 * @param symmetricKey Symmetric key to use (will be encrypted)
 * @param symmetricKeyLen Length of symmetric key
 * @return Encrypted OES_BLOCK containing [encrypted_key_len, encrypted_key, encrypted_data]
 */
OES_BLOCK oes_hybrid_encrypt(OES_BLOCK plaintext, const m_block* publicKey,
                             const m_block* symmetricKey, size_t symmetricKeyLen) {
    if (!plaintext || !plaintext->data || !publicKey || !symmetricKey || symmetricKeyLen == 0) {
        return nullptr;
    }

    // Encrypt the symmetric key with public key
    OES_BLOCK encryptedKey = oes_asymmetric(symmetricKey, symmetricKeyLen, publicKey, 2, 0);
    if (!encryptedKey) {
        return nullptr;
    }

    // Encrypt data with symmetric key (using XOR for simplicity)
    auto encryptedData = static_cast<m_block*>(malloc(plaintext->len * sizeof(m_block)));
    if (!encryptedData) {
        unset_block(&encryptedKey);
        return nullptr;
    }

    for (size_t i = 0; i < plaintext->len; i++) {
        encryptedData[i] = plaintext->data[i] ^ symmetricKey[i % symmetricKeyLen];
    }

    // Combine: [key_length, encrypted_key, encrypted_data]
    size_t totalLen = 1 + encryptedKey->len + plaintext->len;
    auto combined = static_cast<m_block*>(malloc(totalLen * sizeof(m_block)));
    if (!combined) {
        unset_block(&encryptedKey);
        secure_memzero(encryptedData, plaintext->len * sizeof(m_block));
        free(encryptedData);
        return nullptr;
    }

    combined[0] = encryptedKey->len; // Store key length
    memcpy(&combined[1], encryptedKey->data, encryptedKey->len * sizeof(m_block));
    memcpy(&combined[1 + encryptedKey->len], encryptedData, plaintext->len * sizeof(m_block));

    // Cleanup
    unset_block(&encryptedKey);
    secure_memzero(encryptedData, plaintext->len * sizeof(m_block));
    free(encryptedData);

    // Create output block
    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(combined, totalLen * sizeof(m_block));
        free(combined);
        return nullptr;
    }

    OES_block->len = totalLen;
    OES_block->data = combined;

    return OES_block;
}

/**
 * Hybrid decryption: decrypt symmetric key with private key, then decrypt data
 *
 * @param ciphertext Encrypted data from oes_hybrid_encrypt
 * @param privateKey Private key for asymmetric decryption
 * @param symmetricKeyLen Expected length of symmetric key
 * @return Decrypted OES_BLOCK
 */
OES_BLOCK oes_hybrid_decrypt(OES_BLOCK ciphertext, const m_block* privateKey, size_t symmetricKeyLen) {
    if (!ciphertext || !ciphertext->data || !privateKey || ciphertext->len < 2) {
        return nullptr;
    }

    // Extract encrypted key length
    size_t encKeyLen = ciphertext->data[0];
    if (encKeyLen == 0 || 1 + encKeyLen >= ciphertext->len) {
        return nullptr;
    }

    // Decrypt the symmetric key
    OES_BLOCK decryptedKey = oes_asymmetric(&ciphertext->data[1], encKeyLen, privateKey, 2, 0);
    if (!decryptedKey || decryptedKey->len != symmetricKeyLen) {
        if (decryptedKey) {
            unset_block(&decryptedKey);
        }
        return nullptr;
    }

    // Decrypt data
    size_t dataLen = ciphertext->len - 1 - encKeyLen;
    auto decryptedData = static_cast<m_block*>(malloc(dataLen * sizeof(m_block)));
    if (!decryptedData) {
        unset_block(&decryptedKey);
        return nullptr;
    }

    for (size_t i = 0; i < dataLen; i++) {
        decryptedData[i] = ciphertext->data[1 + encKeyLen + i] ^ decryptedKey->data[i % symmetricKeyLen];
    }

    // Cleanup key
    unset_block(&decryptedKey);

    // Create output block
    auto OES_block = static_cast<OES_BLOCK>(malloc(sizeof(oesblock)));
    if (!OES_block) {
        secure_memzero(decryptedData, dataLen * sizeof(m_block));
        free(decryptedData);
        return nullptr;
    }

    OES_block->len = dataLen;
    OES_block->data = decryptedData;

    return OES_block;
}