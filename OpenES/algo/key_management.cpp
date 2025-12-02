#include <malloc.h>
#include <vector>

#include <OpenES/layer/raw-layer.h>
#include "hashing.h"
#include "constants.h"
#include "key_management.h"

/**
 * Compute next salt value using bit rotations
 */
static m_block compute_next_salt(m_block current_salt, size_t count) {
    m_block salt_count = current_salt + static_cast<m_block>(count);
    return mBlock_rotr(count, 7) ^ mBlock_rotr(salt_count, 18);
}

/**
 * Password-Based Key Derivation Function
 * Generates multiple derived keys from a master key
 *
 * @param key Input key material (MBLOCK object)
 * @param outLen Desired output length per derived key in m_block units
 * @param count Number of derived keys to generate
 * @param salt Initial salt value
 * @param iterations Number of PBKDF iterations
 * @return Vector of derived keys (automatically managed)
 */
std::vector<MBLOCK *> PBKDF(const MBLOCK &key, size_t outLen, size_t count, m_block salt, size_t iterations) {
    // Input validation
    if (key.isNull() || key.getLen() == 0 || outLen == 0 || count == 0) {
        return {};
    }

    std::vector<MBLOCK *> w;
    w.reserve(count);

    // Generate each derived key
    for (size_t i = 0; i < count; i++) {
        MBLOCK *expanded = key_expansion(&key, outLen, salt, iterations);
        if (!expanded || expanded->isNull()) {
            // Cleanup on failure
            for (auto *block: w) {
                if (block) {
                    block->secure_zero();
                    delete block;
                }
            }
            if (expanded) {
                delete expanded;
            }
            return {};
        }

        // Clone the expanded key
        MBLOCK *derived = expanded->clone();

        // XOR with salt (assuming salt is a single m_block)
        for (size_t j = 0; j < derived->getLen(); j++) {
            m_block current = derived->getBlock(j);
            derived->setBlock(j, current ^ salt);
        }

        // Add to result vector
        w.push_back(derived);

        // Clean up intermediate value
        expanded->secure_zero();
        delete expanded;

        // Update salt for next iteration
        salt = compute_next_salt(salt, count);
    }

    return w;
}

/**
 * Helper function to cleanup PBKDF result
 *
 * @param roundKey Vector of MBLOCK pointers to free
 */
void cleanup_pbkdf_keys(std::vector<MBLOCK *> &roundKey) {
    for (auto *block: roundKey) {
        if (block) {
            block->secure_zero();
            delete block;
        }
    }
    roundKey.clear();
}

/**
 * Key expansion using PBKDF2-like construction
 *
 * @param key Input key material
 * @param outLen Desired output length in m_block units
 * @param salt Salt value for key derivation
 * @param iterations Number of iterations (min 1)
 * @return Derived key material (caller must securely free)
 */
MBLOCK *key_expansion(const MBLOCK *key, size_t outLen, m_block salt, uint16_t iterations) {
    // Input validation
    if (!key || key->isNull() || outLen == 0) {
        return nullptr;
    }

    // Ensure at least one iteration
    if (iterations == 0) {
        return key->clone();
    }

    // Create output block initialized to zero
    MBLOCK *out = MBLOCK::create(outLen, 0);
    if (!out) {
        return nullptr;
    }

    // Prepare salt||counter structure
    MBLOCK *counterSalt = MBLOCK::create(2, 0);
    if (!counterSalt) {
        delete out;
        return nullptr;
    }

    counterSalt->setBlock(0, salt);

    // PBKDF2-style iteration
    for (uint32_t i = 1; i <= iterations; ++i) {
        // Set counter in consistent byte order
        counterSalt->setBlock(1, i);

        // Ui = HMAC(key, salt || counter)
        MBLOCK *Ui = oes_raw_hmac(key, counterSalt, outLen);
        if (!Ui) {
            // Cleanup on failure
            out->secure_zero();
            delete out;
            delete counterSalt;
            return nullptr;
        }

        // Accumulate: out ^= Ui
        out->xor_with(*Ui, false);

        // Securely erase intermediate value
        Ui->secure_zero();
        delete Ui;
    }

    delete counterSalt;
    return out;
}


/**
 * Generate round key from master key
 * Expands/contracts key to desired length and applies session-specific transformation
 *
 * @param key Master key
 * @param outLen Desired round key length in m_block units
 * @param session Session/round number for key scheduling
 * @return Round key (caller must free)
 */
MBLOCK *key_scheduler(const MBLOCK *key, size_t outLen, size_t session) {
    // Input validation
    if (!key || key->isNull() || outLen == 0) {
        return nullptr;
    }

    size_t keyLen = key->getLen();
    MBLOCK *roundKey = nullptr;

    // Expand or clone key to match output length
    if (keyLen != outLen) {
        roundKey = key_expansion(key, outLen, 0, 1);
    } else {
        roundKey = key->clone();
    }

    if (!roundKey) {
        return nullptr;
    }

    // Apply session-specific rotation
    roundKey->rotr(session);

    // XOR with round constant
    m_block rcon = oesRcon[session % 256];
    for (size_t i = 0; i < outLen; i++) {
        if (i % 2 == 0) {
            // alternate XOR like mBlock_xor with alternate=true
            m_block current = roundKey->getBlock(i);
            roundKey->setBlock(i, current ^ rcon);
        }
    }

    return roundKey;
}
