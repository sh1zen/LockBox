#include <malloc.h>
#include <cstring>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/support/support.h>
#include "hashing.h"
#include "oes-utils.h"
#include "key_managment.h"
#include "oes_common.h"

// Forward declarations for clarity
static m_block compute_next_salt(m_block current_salt, size_t count);

/**
 * Password-Based Key Derivation Function
 * Generates multiple derived keys from a master key
 *
 * @param key Input key material
 * @param keyLen Length of input key in m_block units
 * @param outLen Desired output length per derived key in m_block units
 * @param count Number of derived keys to generate
 * @param salt Initial salt value
 * @param iterations Number of PBKDF iterations
 * @return Array of derived keys (caller must free with cleanup_pbkdf_keys)
 */
m_block** PBKDF(const m_block* key, size_t keyLen, size_t outLen,
                size_t count, m_block salt, size_t iterations) {
    // Input validation
    if (!key || keyLen == 0 || outLen == 0 || count == 0) {
        return nullptr;
    }

    // Allocate array of pointers
    auto** w = static_cast<m_block**>(calloc(count, sizeof(m_block*)));
    if (!w) {
        return nullptr;
    }

    // Generate each derived key
    for (size_t i = 0; i < count; i++) {
        m_block* expanded = key_expansion(key, keyLen, outLen, salt, iterations);
        if (!expanded) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                if (w[j]) {
                    secure_memzero(w[j], outLen * sizeof(m_block));
                    free(w[j]);
                }
            }
            free(w);
            return nullptr;
        }

        // Allocate space for the result
        w[i] = static_cast<m_block*>(malloc(outLen * sizeof(m_block)));
        if (!w[i]) {
            secure_memzero(expanded, outLen * sizeof(m_block));
            free(expanded);
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                if (w[j]) {
                    secure_memzero(w[j], outLen * sizeof(m_block));
                    free(w[j]);
                }
            }
            free(w);
            return nullptr;
        }

        // Copy expanded key
        memcpy(w[i], expanded, outLen * sizeof(m_block));

        // XOR with salt (assuming salt is a single m_block)
        for (size_t j = 0; j < outLen; j++) {
            w[i][j] ^= salt;
        }

        // Clean up intermediate value
        secure_memzero(expanded, outLen * sizeof(m_block));
        free(expanded);

        // Update salt for next iteration
        salt = compute_next_salt(salt, count);
    }

    return w;
}

/**
 * Compute next salt value using bit rotations
 */
static m_block compute_next_salt(m_block current_salt, size_t count) {
    m_block salt_count = current_salt + static_cast<m_block>(count);
    return mBlock_rotr(count, 7) ^ mBlock_rotr(salt_count, 18);
}

/**
 * Helper function to cleanup PBKDF result
 *
 * @param roundKey Array of key pointers to free
 * @param count Number of keys in array
 * @param keyLen Length of each key in m_block units
 */
void cleanup_pbkdf_keys(m_block** roundKey, size_t count, size_t keyLen) {
    if (!roundKey) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (roundKey[i]) {
            secure_memzero(roundKey[i], keyLen * sizeof(m_block));
            free(roundKey[i]);
            roundKey[i] = nullptr;
        }
    }
    free(roundKey);
}

/**
 * Key expansion using PBKDF2-like construction
 *
 * @param key Input key material
 * @param keyLen Length of input key in m_block units
 * @param outLen Desired output length in m_block units
 * @param salt Salt value for key derivation
 * @param iterations Number of iterations (min 1)
 * @return Derived key material (caller must securely free)
 */
m_block* key_expansion(const m_block* key, const size_t keyLen,
                       const size_t outLen, const m_block salt,
                       uint16_t iterations) {
    // Input validation
    if (!key || keyLen == 0 || outLen == 0) {
        return nullptr;
    }

    // Ensure at least one iteration
    if (iterations == 0) {
        iterations = 1;
    }

    // Allocate and zero-initialize output
    m_block* out = mBlock_create(outLen);
    if (!out) {
        return nullptr;
    }
    secure_memzero(out, outLen * sizeof(m_block));

    // Prepare salt||counter structure
    m_block counterSalt[2];
    counterSalt[0] = salt;

    // PBKDF2-style iteration
    for (uint32_t i = 1; i <= iterations; ++i) {
        // Set counter in consistent byte order
        counterSalt[1] = i;

        // Ui = HMAC(key, salt || counter)
        m_block* Ui = oes_raw_hmac(key, keyLen, counterSalt, 2, outLen);
        if (!Ui) {
            // Cleanup on failure
            secure_memzero(out, outLen * sizeof(m_block));
            mBlock_free(out);
            return nullptr;
        }

        // Accumulate: out ^= Ui
        for (size_t j = 0; j < outLen; ++j) {
            out[j] ^= Ui[j];
        }

        // Securely erase intermediate value
        secure_memzero(Ui, outLen * sizeof(m_block));
        mBlock_free(Ui);
    }

    return out;
}

/**
 * Generate round key from master key
 * Expands/contracts key to desired length and applies session-specific transformation
 *
 * @param key Master key
 * @param keyLen Length of master key in m_block units
 * @param outLen Desired round key length in m_block units
 * @param session Session/round number for key scheduling
 * @return Round key (caller must free)
 */
m_block* key_scheduler(const m_block* key, size_t keyLen, size_t outLen, size_t session) {
    // Input validation
    if (!key || keyLen == 0 || outLen == 0) {
        return nullptr;
    }

    m_block* roundKey = nullptr;

    // Expand or clone key to match output length
    if (keyLen != outLen) {
        roundKey = key_expansion(key, keyLen, outLen, 0, 1);
    } else {
        roundKey = mBlock_clone(nullptr, key, keyLen);
    }

    if (!roundKey) {
        return nullptr;
    }

    // Apply session-specific rotation
    mBlock_rotr_vec(roundKey, outLen, session);

    // XOR with round constant
    mBlock_xor(roundKey, &oesRcon[session % 256], outLen, true);

    return roundKey;
}