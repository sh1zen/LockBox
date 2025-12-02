#include <cstdlib>
#include <iostream>
#include <cstring>

#include "asymmetric.h"
#include "m_block.h"

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
static m_block extended_gcd(m_block a, m_block b, m_block *x, m_block *y) {
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
 * @param publicKey Output MBLOCK* [n, e] where n is modulus, e is public exponent
 * @param privateKey Output MBLOCK* [n, d] where n is modulus, d is private exponent
 * @return true if successful, false otherwise
 */
bool oes_generate_keypair(m_block p, m_block q, MBLOCK** publicKey, MBLOCK** privateKey) {
    if (!publicKey || !privateKey) {
        return false;
    }

    // Compute n = p * q
    m_block n = p * q;

    // Compute Euler's totient: φ(n) = (p-1)(q-1)
    m_block phi = (p - 1) * (q - 1);

    // Choose e (public exponent) - commonly 65537 or just use a smaller value
    m_block e = (m_block)65537;
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

    // Create public key: (n, e)
    auto pubKeyData = new m_block[2];
    pubKeyData[0] = n;
    pubKeyData[1] = e;
    *publicKey = new MBLOCK(pubKeyData, 2, true);

    // Create private key: (n, d)
    auto privKeyData = new m_block[2];
    privKeyData[0] = n;
    privKeyData[1] = d;
    *privateKey = new MBLOCK(privKeyData, 2, true);

    return true;
}

/**
 * Asymmetric encryption/decryption
 * For each data block: encrypted = (data^exp) mod modulus
 *
 * @param data Input MBLOCK
 * @param key Key MBLOCK [modulus, exponent]
 * @param seed Optional seed for additional randomization
 * @return Encrypted/decrypted MBLOCK* (caller must delete)
 */
MBLOCK* oes_asymmetric(const MBLOCK* data, const MBLOCK* key, m_block seed) {
    // Input validation
    if (!data || data->isNull() || !key || key->isNull() || key->getLen() < 2) {
        return nullptr;
    }

    m_block modulus = key->getBlock(0);
    m_block exponent = key->getBlock(1);

    // Validate modulus
    if (modulus <= 1) {
        return nullptr;
    }

    size_t dataLen = data->getLen();

    // Allocate output buffer
    auto encodedData = new m_block[dataLen];

    // Apply modular exponentiation to each block
    for (size_t i = 0; i < dataLen; i++) {
        // Ensure data block is less than modulus
        m_block block = data->getBlock(i) % modulus;

        // Apply transformation: block^exponent mod modulus
        encodedData[i] = mod_exp(block, exponent, modulus);

        // Optional: XOR with seed-derived value for additional entropy
        if (seed != 0) {
            m_block seedValue = mod_exp(seed + i, exponent, modulus);
            encodedData[i] ^= seedValue;
        }
    }

    return new MBLOCK(encodedData, dataLen, true);
}

/**
 * Encrypt data using public key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param plaintext Input plaintext MBLOCK
 * @param publicKey Public key MBLOCK [modulus, public_exponent]
 * @param seed Optional seed value
 * @return Encrypted MBLOCK* (caller must delete)
 */
MBLOCK* oes_public_encrypt(const MBLOCK* plaintext, const MBLOCK* publicKey, m_block seed) {
    if (!plaintext || plaintext->isNull() || !publicKey) {
        return nullptr;
    }
    return oes_asymmetric(plaintext, publicKey, seed);
}

/**
 * Decrypt data using private key
 * Wrapper around oes_asymmetric for clarity
 *
 * @param ciphertext Input ciphertext MBLOCK
 * @param privateKey Private key MBLOCK [modulus, private_exponent]
 * @param seed Optional seed value (must match encryption seed)
 * @return Decrypted MBLOCK* (caller must delete)
 */
MBLOCK* oes_private_decrypt(const MBLOCK* ciphertext, const MBLOCK* privateKey, m_block seed) {
    if (!ciphertext || ciphertext->isNull() || !privateKey) {
        return nullptr;
    }
    return oes_asymmetric(ciphertext, privateKey, seed);
}

/**
 * Sign data using private key
 *
 * @param data Data to sign
 * @param privateKey Private key MBLOCK [modulus, private_exponent]
 * @return Signature MBLOCK* (caller must delete)
 */
MBLOCK* oes_sign(const MBLOCK* data, const MBLOCK* privateKey) {
    if (!data || data->isNull() || !privateKey) {
        return nullptr;
    }
    return oes_asymmetric(data, privateKey, 0);
}

/**
 * Verify signature using public key
 *
 * @param data Original data
 * @param signature Signature to verify
 * @param publicKey Public key MBLOCK [modulus, public_exponent]
 * @return true if signature is valid, false otherwise
 */
bool oes_verify(const MBLOCK* data, const MBLOCK* signature, const MBLOCK* publicKey) {
    if (!data || data->isNull() || !signature || signature->isNull() || !publicKey) {
        return false;
    }

    MBLOCK* decrypted = oes_asymmetric(signature, publicKey, 0);
    if (!decrypted || decrypted->isNull()) {
        delete decrypted;
        return false;
    }

    bool valid = true;
    if (decrypted->getLen() != data->getLen()) {
        valid = false;
    } else {
        for (size_t i = 0; i < data->getLen(); i++) {
            if (decrypted->getBlock(i) != data->getBlock(i)) {
                valid = false;
                break;
            }
        }
    }

    delete decrypted;
    return valid;
}

/**
 * Hybrid encryption: encrypt data with symmetric key, then encrypt key with public key
 *
 * @param plaintext Data to encrypt
 * @param publicKey Public key for asymmetric encryption
 * @param symmetricKey Symmetric key to use (will be encrypted)
 * @return Encrypted MBLOCK* containing [encrypted_key_len, encrypted_key, encrypted_data]
 */
MBLOCK* oes_hybrid_encrypt(const MBLOCK* plaintext, const MBLOCK* publicKey, const MBLOCK* symmetricKey) {
    if (!plaintext || plaintext->isNull() || !publicKey || !symmetricKey || symmetricKey->isNull()) {
        return nullptr;
    }

    // Encrypt the symmetric key with public key
    MBLOCK* encryptedKey = oes_asymmetric(symmetricKey, publicKey, 0);
    if (!encryptedKey || encryptedKey->isNull()) {
        delete encryptedKey;
        return nullptr;
    }

    // Encrypt data with symmetric key (simple XOR)
    size_t plaintextLen = plaintext->getLen();
    size_t symKeyLen = symmetricKey->getLen();
    auto encryptedData = new m_block[plaintextLen];

    for (size_t i = 0; i < plaintextLen; i++) {
        encryptedData[i] = plaintext->getBlock(i) ^ symmetricKey->getBlock(i % symKeyLen);
    }

    // Combine: [encrypted_key_len, encrypted_key, encrypted_data]
    size_t encKeyLen = encryptedKey->getLen();
    size_t totalLen = 1 + encKeyLen + plaintextLen;
    auto combined = new m_block[totalLen];

    combined[0] = encKeyLen;
    for (size_t i = 0; i < encKeyLen; i++) {
        combined[1 + i] = encryptedKey->getBlock(i);
    }
    std::memcpy(&combined[1 + encKeyLen], encryptedData, plaintextLen * sizeof(m_block));

    delete[] encryptedData;
    delete encryptedKey;

    return new MBLOCK(combined, totalLen, true);
}

/**
 * Hybrid decryption: decrypt symmetric key with private key, then decrypt data
 *
 * @param ciphertext Encrypted data from oes_hybrid_encrypt
 * @param privateKey Private key for asymmetric decryption
 * @return Decrypted MBLOCK*
 */
MBLOCK* oes_hybrid_decrypt(const MBLOCK* ciphertext, const MBLOCK* privateKey) {
    if (!ciphertext || ciphertext->isNull() || !privateKey || ciphertext->getLen() < 2) {
        return nullptr;
    }

    // Extract encrypted key length
    size_t encKeyLen = ciphertext->getBlock(0);
    if (encKeyLen == 0 || 1 + encKeyLen >= ciphertext->getLen()) {
        return nullptr;
    }

    // Extract encrypted key
    auto encKeyData = new m_block[encKeyLen];
    for (size_t i = 0; i < encKeyLen; i++) {
        encKeyData[i] = ciphertext->getBlock(1 + i);
    }
    MBLOCK encryptedKey(encKeyData, encKeyLen, true);

    // Decrypt the symmetric key
    MBLOCK* decryptedKey = oes_asymmetric(&encryptedKey, privateKey, 0);
    if (!decryptedKey || decryptedKey->isNull()) {
        delete decryptedKey;
        return nullptr;
    }

    // Decrypt data with symmetric key
    size_t dataLen = ciphertext->getLen() - 1 - encKeyLen;
    auto decryptedData = new m_block[dataLen];

    size_t symKeyLen = decryptedKey->getLen();
    for (size_t i = 0; i < dataLen; i++) {
        decryptedData[i] = ciphertext->getBlock(1 + encKeyLen + i) ^ decryptedKey->getBlock(i % symKeyLen);
    }

    delete decryptedKey;

    return new MBLOCK(decryptedData, dataLen, true);
}