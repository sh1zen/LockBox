#include <vector>
#include <memory>

#include <OpenES/layer/raw-layer.h>
#include "hashing.h"
#include "constants.h"
#include "key_management.h"
#include "oesMath.h"
#include "utils.h"

/**
 * Compute next salt value using bit rotations
 */
static m_block compute_next_salt(m_block current_salt, size_t count) {
    const m_block salt_count = current_salt + static_cast<m_block>(count);
    return mBlock::rotr(count, 7) ^ mBlock::rotr(salt_count, 18);
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
    if (key.isNull() || outLen == 0 || count == 0) {
        return {};
    }

    // Usa unique_ptr internamente per exception safety
    std::vector<std::unique_ptr<MBLOCK> > temp;
    temp.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        std::unique_ptr<MBLOCK> derived(key_expansion(&key, outLen, salt, iterations));
        if (!derived || derived->isNull()) {
            return {}; // cleanup automatico
        }

        for (size_t j = 0; j < derived->getLen(); ++j) {
            derived->setBlock(j, derived->getBlock(j) ^ salt);
        }

        temp.push_back(std::move(derived));
        salt = compute_next_salt(salt, count);
    }

    // Rilascia ownership al chiamante
    std::vector<MBLOCK *> result;
    result.reserve(count);
    for (auto &ptr: temp) {
        result.push_back(ptr.release());
    }

    return result;
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
MBLOCK *key_expansion(const MBLOCK *key, const size_t outLen, const m_block salt, const size_t iterations) {
    if (!key || key->isNull() || outLen == 0) {
        return nullptr;
    }

    if (iterations == 0) {
        return key->clone();
    }

    const std::unique_ptr<MBLOCK> counterSalt(MBLOCK::create(2, 0));
    if (!counterSalt) {
        return nullptr;
    }

    counterSalt->setBlock(0, salt);
    counterSalt->setBlock(1, 1);

    // U1 = HMAC(key, salt || 1)
    std::unique_ptr<MBLOCK> U(oes_raw_hmac(key, counterSalt.get(), outLen));
    if (!U) {
        return nullptr;
    }

    // T = U1
    std::unique_ptr<MBLOCK> out(U->clone());
    if (!out) {
        return nullptr;
    }

    // Iterazioni: Ui = HMAC(key, U_{i-1}), T ^= Ui
    for (size_t iter = 2; iter <= iterations; ++iter) {
        std::unique_ptr<MBLOCK> U_next(oes_raw_hmac(key, U.get(), outLen));
        if (!U_next) {
            return nullptr;
        }

        out->xor_with(*U_next, false);
        U = std::move(U_next);
    }

    return out.release();
}

static inline m_block oesRcon(const size_t session, const size_t index) {
    m_block x = DIFFUSE_CONST ^ session;

    x ^= static_cast<m_block>(index);
    x = mBlock::rotl(x, (index * 7) % OES_MEM_SIZE);
    x ^= xtime(x);
    x ^= mBlock::rotl(x, 13);
    x ^= xtime(x);

    return x;
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
MBLOCK *key_scheduler(const MBLOCK *key, const size_t outLen, size_t session) {
    if (!key || key->isNull() || outLen == 0) return nullptr;

    const size_t keyLen = key->getLen();

    MBLOCK *roundKey = (keyLen != outLen) ? key_expansion(key, outLen, session, 1) : key->clone();

    if (!roundKey) return nullptr;

    // session whitening iniziale
    m_block feedback = DIFFUSE_CONST ^ session;
    for (size_t i = 0; i < outLen; ++i) {
        m_block b = roundKey->getBlock(i);

        // combinazione di rotazioni, Rcon dinamico e feedback chaining
        b ^= mBlock::rotl(feedback, (i * 5 + session) % OES_MEM_SIZE);
        b ^= oesRcon(session, i);
        b ^= feedback;

        feedback = xtime(b) ^ b; // aggiornamento feedback per il prossimo blocco
        roundKey->setBlock(i, b);
    }

    // permutazione finale globale
    roundKey->rotr((session * 11 + outLen) % (outLen * OES_MEM_SIZE));

    return roundKey;
}
