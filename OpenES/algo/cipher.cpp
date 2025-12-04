#include <cstdlib>
#include <utility>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/support/oesMath.h>
#include "key_management.h"
#include "cipher.h"
#include "constants.h"
#include "support.h"
#include "core.h"

/**
 * Mix function ottimizzata
 */
static inline m_block mix(m_block x) {
    x = pseudoHadamardT(x);
    return x ^ mBlock::rotl(x, 7) ^ mBlock::rotr(x, 11);
}

/**
 * Global diffusion
 */
void global_diffuse(MBLOCK *data, const m_block seed) {
    if (!data || data->isNull()) return;

    const size_t len = data->getLen();
    if (len < 2) return;

    const m_block k0 = seed;
    const m_block k1 = seed ^ DIFFUSE_CONST;
    const m_block k2 = seed ^ mBlock::rotl(DIFFUSE_CONST, 1);

    // Pass 1: forward
    m_block prev = k0;
    for (size_t i = 0; i < len; ++i) {
        m_block cur = data->getBlock(i);
        data->setBlock(i, cur ^ mix(prev));
        prev = cur;
    }

    // Pass 2: backward
    m_block next = k1;
    for (size_t i = len; i-- > 0;) {
        m_block cur = data->getBlock(i);
        data->setBlock(i, cur ^ mix(next));
        next = cur;
    }

    // Pass 3: forward
    prev = k2;
    for (size_t i = 0; i < len; ++i) {
        const m_block cur = data->getBlock(i);
        data->setBlock(i, cur ^ mix(prev));
        prev = cur;
    }
}

/**
 * Inverse diffusion
 */
void global_diffuse_inv(MBLOCK *data, m_block seed) {
    if (!data || data->isNull()) return;

    const size_t len = data->getLen();
    if (len < 2) return;

    const m_block k0 = seed;
    const m_block k1 = seed ^ DIFFUSE_CONST;
    const m_block k2 = seed ^ mBlock::rotl(DIFFUSE_CONST, 1);

    // Undo pass 3
    m_block prev = k2;
    for (size_t i = 0; i < len; ++i) {
        m_block cur = data->getBlock(i) ^ mix(prev);
        data->setBlock(i, cur);
        prev = cur;
    }

    // Undo pass 2
    m_block next = k1;
    for (size_t i = len; i-- > 0;) {
        m_block cur = data->getBlock(i) ^ mix(next);
        data->setBlock(i, cur);
        next = cur;
    }

    // Undo pass 1
    prev = k0;
    for (size_t i = 0; i < len; ++i) {
        m_block cur = data->getBlock(i) ^ mix(prev);
        data->setBlock(i, cur);
        prev = cur;
    }
}

// ============================================================================
// BIJECTIVE S-BOX BASED ON FEISTEL STRUCTURE
// ============================================================================
//
// Instead of EC polynomials (hard to invert exactly), we use a Feistel-based
// S-box which is guaranteed to be bijective and perfectly invertible.
// The non-linearity comes from mixing operations within the Feistel rounds.
// ============================================================================
static inline __attribute__((always_inline)) m_block sbox_f(m_block x, m_block key) {
    m_block t = x ^ key;
    t *= PRNG_MULT1;
    t ^= mBlock::rotr(t, 5);
    t += mBlock::rotl(x, 11);
    t ^= t >> 7;
    t *= PRNG_MULT2;
    t ^= mBlock::rotr(t, 13);
    return t;
}

static inline m_block feistel_sbox(m_block block, m_block key) {
    m_block L = (block >> OES_HALF_MEM_SIZE) & OES_HALF_BLOCK_MASK;
    m_block R = block & OES_HALF_BLOCK_MASK;
    m_block k = key;

#pragma unroll
    for (unsigned i = 0; i < 6; ++i) {
        const m_block F = sbox_f(R, k) & OES_HALF_BLOCK_MASK;
        const m_block newR = L ^ F;
        L = R;
        R = newR;
        k = prng_next(&k);
    }
    return (L << OES_HALF_MEM_SIZE) | R;
}

static inline m_block feistel_sbox_inv(const m_block block, m_block key) {
    m_block L = (block >> OES_HALF_MEM_SIZE) & OES_HALF_BLOCK_MASK;
    m_block R = block & OES_HALF_BLOCK_MASK;

    m_block keys[6];
    m_block k = key;
#pragma unroll
    for (unsigned i = 0; i < 6; ++i) keys[i] = k, k = prng_next(&k);

    for (int i = 5; i >= 0; --i) {
        const m_block F = sbox_f(L, keys[i]) & OES_HALF_BLOCK_MASK;
        const m_block newL = R ^ F;
        R = L;
        L = newL;
    }

    volatile m_block *vk = keys;
#pragma unroll
    for (unsigned i = 0; i < 6; ++i) vk[i] = 0;

    return (L << OES_HALF_MEM_SIZE) | R;
}

// ============================================================================
// PERMUTATION LAYER
// ============================================================================

/**
 * Generate a permutation array using Fisher-Yates shuffle
 */
static inline void generate_permutation(size_t *__restrict perm, size_t len, m_block seed) {
    for (size_t i = 0; i < len; ++i) perm[i] = i;

    m_block state = seed ? seed : PRNG_SEED;
    for (size_t i = len - 1; i > 0; --i) {
        size_t j = prng_next(&state) % (i + 1);
        std::swap(perm[i], perm[j]);
    }
}

static inline void invert_permutation(size_t *__restrict inv, const size_t *__restrict perm, size_t len) {
    for (size_t i = 0; i < len; ++i) inv[perm[i]] = i;
}

static inline void apply_block_permutation(m_block *__restrict data, const size_t *__restrict perm, size_t len,
                                           m_block *__restrict temp) {
    for (size_t i = 0; i < len; ++i) temp[i] = data[perm[i]];
    memcpy(data, temp, len * sizeof(m_block));
}

static inline m_block bit_permute(m_block block, m_block seed) {
    m_block result = 0;
    m_block state = seed ? seed : PRNG_SEED;

    uint8_t perm[OES_MEM_SIZE];
#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i) perm[i] = i;
    for (uint32_t i = OES_MEM_SIZE - 1; i > 0; --i) {
        uint32_t j = prng_next(&state) % (i + 1);
        std::swap(perm[i], perm[j]);
    }
#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i)
        result |= ((block >> i) & 1) << perm[i];

    volatile uint8_t *vp = perm;
#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i) vp[i] = 0;
    return result;
}

static inline m_block bit_permute_inv(m_block block, m_block seed) {
    m_block result = 0;
    m_block state = seed ? seed : PRNG_SEED;

    uint8_t perm[OES_MEM_SIZE], inv[OES_MEM_SIZE];

#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i) perm[i] = i;

#pragma unroll
    for (uint32_t i = OES_MEM_SIZE - 1; i > 0; --i) {
        uint32_t j = prng_next(&state) % (i + 1);
        std::swap(perm[i], perm[j]);
    }
#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i) inv[perm[i]] = i;
#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i)
        result |= ((block >> i) & 1) << inv[i];

    uint8_t *vp = perm;
    uint8_t *vi = inv;
#pragma unroll
    for (uint32_t i = 0; i < OES_MEM_SIZE; ++i) vp[i] = vi[i] = 0;

    return result;
}

// ============================================================================
// LINEAR MIXING LAYER (Invertible)
// ============================================================================

/**
 * Mix adjacent blocks - uses XOR and rotation (perfectly invertible)
 */
static inline void mix_blocks(m_block *__restrict data, size_t len, m_block seed) {
    if (len < 2) return;

    m_block state = seed ? seed : PRNG_SEED;
    m_block rots[128];
    if (len > 128) return;

    for (size_t i = 0; i < len; i++)
        rots[i] = (prng_next(&state) % (OES_MEM_SIZE - 1)) + 1;

    for (size_t i = 0; i < len - 1; i++)
        data[i + 1] ^= mBlock::rotl(data[i], rots[i]);

    data[0] ^= mBlock::rotl(data[len - 1], rots[len - 1]);

    volatile m_block *vp = rots;
    for (size_t i = 0; i < len; i++) vp[i] = 0;
}

static inline void mix_blocks_inv(m_block *__restrict data, size_t len, m_block seed) {
    if (len < 2) return;

    m_block state = seed ? seed : PRNG_SEED;
    m_block rots[128];
    if (len > 128) return;

    for (size_t i = 0; i < len; i++)
        rots[i] = (prng_next(&state) % (OES_MEM_SIZE - 1)) + 1;

    data[0] ^= mBlock::rotl(data[len - 1], rots[len - 1]);

    for (size_t i = len - 1; i > 0; i--)
        data[i] ^= mBlock::rotl(data[i - 1], rots[i - 1]);

    volatile m_block *vp = rots;

    for (size_t i = 0; i < len; i++) vp[i] = 0;
}

// ============================================================================
// ROUND FUNCTIONS
// ============================================================================

/**
 * Single encryption round
 */
static void enc_round(m_block *__restrict data,
                      size_t len,
                      const m_block *__restrict round_key,
                      size_t *__restrict perm,
                      m_block *__restrict temp,
                      int round) {
    // Note: caller must guarantee round_key has at least 'len' elements.
    // Protect seeds that use round % len from division-by-zero (len > 0 here).
    const size_t round_mod_len = static_cast<size_t>(round) % len;
    const auto mround = static_cast<m_block>(round);

    // 1. Add round key

    for (size_t i = 0; i < len; ++i) {
        data[i] ^= round_key[i];
    }

    // 2. Feistel S-box
    const m_block sbox_key = round_key[0] ^ (mround * PHI_CONST);

    for (size_t i = 0; i < len; ++i) {
        data[i] = feistel_sbox(data[i], sbox_key ^ static_cast<m_block>(i));
    }

    // 3. Bit permutation
    const m_block bit_seed = round_key[round_mod_len] ^ mround;

    for (size_t i = 0; i < len; ++i) {
        data[i] = bit_permute(data[i], bit_seed ^ static_cast<m_block>(i));
    }

    // 4. Pseudo-Hadamard

    for (size_t i = 0; i < len; ++i) {
        data[i] = pseudoHadamardT(data[i]);
    }

    // 5. Block permutation
    if (len > 1) {
        const m_block perm_seed = round_key[1 % len] ^ (mround * PERM_CONST);
        generate_permutation(perm, len, perm_seed);
        apply_block_permutation(data, perm, len, temp);
    }

    // 6. Linear mixing
    const m_block mix_seed = round_key[2 % len] ^ (mround * MIX_CONST);
    mix_blocks(data, len, mix_seed);
}


static void dec_round(m_block *__restrict data,
                      size_t len,
                      const m_block *__restrict round_key,
                      size_t *__restrict perm,
                      size_t *__restrict inv_perm,
                      m_block *__restrict temp,
                      int round) {
    const size_t round_mod_len = static_cast<size_t>(round) % len;
    const auto mround = static_cast<m_block>(round);

    // 6. Inverse linear mixing
    const m_block mix_seed = round_key[2 % len] ^ (mround * MIX_CONST);
    mix_blocks_inv(data, len, mix_seed);

    // 5. Inverse block permutation
    if (len > 1) {
        const m_block perm_seed = round_key[1 % len] ^ (mround * PERM_CONST);
        generate_permutation(perm, len, perm_seed);
        invert_permutation(inv_perm, perm, len);
        apply_block_permutation(data, inv_perm, len, temp);
    }

    // 4. Inverse Pseudo-Hadamard

    for (size_t i = 0; i < len; ++i) {
        data[i] = pseudoHadamardTInv(data[i]);
    }

    // 3. Inverse bit permutation
    const m_block bit_seed = round_key[round_mod_len] ^ mround;

    for (size_t i = 0; i < len; ++i) {
        data[i] = bit_permute_inv(data[i], bit_seed ^ static_cast<m_block>(i));
    }

    // 2. Inverse Feistel S-box
    const m_block sbox_key = round_key[0] ^ (mround * PHI_CONST);

    for (size_t i = 0; i < len; ++i) {
        data[i] = feistel_sbox_inv(data[i], sbox_key ^ static_cast<m_block>(i));
    }

    // 1. Remove round key
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= round_key[i];
    }
}


// ============================================================================
// MAIN ENCRYPTION/DECRYPTION
// ============================================================================

/**
 * Raw encryption using MBLOCK
 * @param data Input data MBLOCK
 * @param key Key MBLOCK
 * @return Encrypted MBLOCK* (caller must delete), or nullptr on error
 */
MBLOCK *raw_enc(const MBLOCK *data, const MBLOCK *key) {
    if (!data || data->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    const size_t dataLen = data->getLen();
    if (dataLen == 0) return nullptr;

    // Clone input data
    MBLOCK *cipher = data->clone();

    // Expand key
    const size_t exp_key_len = (OES_CORE_ROUNDS + 2) * dataLen;
    MBLOCK *exp_key = key_expansion(key, exp_key_len, static_cast<m_block>(0x67452301), 8);
    if (!exp_key || exp_key->isNull()) {
        delete cipher;
        delete exp_key;
        return nullptr;
    }

    // Extract cipher data for processing
    auto *cipherData = new m_block[dataLen];
    for (size_t i = 0; i < dataLen; i++) {
        cipherData[i] = cipher->getBlock(i);
    }

    // Initial whitening
    for (size_t i = 0; i < dataLen; i++) {
        cipherData[i] ^= exp_key->getBlock(i);
    }

    auto *temp = new m_block[dataLen];
    auto *perm = new size_t[dataLen];
    auto *round_key = new m_block[dataLen];

    // Main rounds
#pragma unroll
    for (int r = 0; r < OES_CORE_ROUNDS; r++) {
        // Extract round key for this round
        for (size_t i = 0; i < dataLen; i++) {
            round_key[i] = exp_key->getBlock((r + 1) * dataLen + i);
        }

        enc_round(cipherData, dataLen, round_key, perm, temp, r);

        secure_memzero(round_key, dataLen * sizeof(m_block));
    }

    // Final whitening
    for (size_t i = 0; i < dataLen; i++) {
        cipherData[i] ^= exp_key->getBlock((OES_CORE_ROUNDS + 1) * dataLen + i);
    }

    // Update cipher MBLOCK with encrypted data
    for (size_t i = 0; i < dataLen; i++) {
        cipher->setBlock(i, cipherData[i]);
    }

    // Cleanup
    exp_key->secure_zero();
    delete exp_key;
    secure_memzero(cipherData, dataLen * sizeof(m_block));
    delete[] cipherData;

    secure_memzero(temp, dataLen * sizeof(m_block));
    delete[] temp;
    secure_memzero(perm, dataLen * sizeof(size_t));
    delete[] perm;
    secure_memzero(round_key, dataLen * sizeof(m_block));
    delete[] round_key;

    return cipher;
}

/**
 * Raw decryption using MBLOCK
 * @param data Input ciphertext MBLOCK
 * @param key Key MBLOCK
 * @return Decrypted MBLOCK* (caller must delete), or nullptr on error
 */
MBLOCK *raw_dec(const MBLOCK *data, const MBLOCK *key) {
    if (!data || data->isNull() || !key || key->isNull()) {
        return nullptr;
    }

    size_t dataLen = data->getLen();
    if (dataLen == 0) return nullptr;

    // Clone input data
    MBLOCK *plain = data->clone();

    // Expand key
    const size_t exp_key_len = (OES_CORE_ROUNDS + 2) * dataLen;
    MBLOCK *exp_key = key_expansion(key, exp_key_len, static_cast<m_block>(0x67452301), 8);
    if (!exp_key || exp_key->isNull()) {
        delete plain;
        delete exp_key;
        return nullptr;
    }

    // Extract data for processing
    auto *plainData = new m_block[dataLen];
    for (size_t i = 0; i < dataLen; i++) {
        plainData[i] = plain->getBlock(i);
    }

    // Remove final whitening

    for (size_t i = 0; i < dataLen; i++) {
        plainData[i] ^= exp_key->getBlock((OES_CORE_ROUNDS + 1) * dataLen + i);
    }

    // Allocate working buffers
    auto *temp = new m_block[dataLen];
    auto *perm = new size_t[dataLen];
    auto *inv_perm = new size_t[dataLen];
    auto *round_key = new m_block[dataLen];

    // Inverse rounds (reverse order)
#pragma unroll
    for (int r = OES_CORE_ROUNDS - 1; r >= 0; r--) {
        for (size_t i = 0; i < dataLen; i++) {
            round_key[i] = exp_key->getBlock((r + 1) * dataLen + i);
        }

        dec_round(plainData, dataLen, round_key, perm, inv_perm, temp, r);
        secure_memzero(round_key, dataLen * sizeof(m_block));
    }

    // Remove initial whitening
    for (size_t i = 0; i < dataLen; i++) {
        plainData[i] ^= exp_key->getBlock(i);
    }

    // Update MBLOCK with decrypted data
    for (size_t i = 0; i < dataLen; i++) {
        plain->setBlock(i, plainData[i]);
    }

    // Cleanup
    exp_key->secure_zero();
    delete exp_key;

    secure_memzero(plainData, dataLen * sizeof(m_block));
    delete[] plainData;

    secure_memzero(temp, dataLen * sizeof(m_block));
    delete[] temp;
    secure_memzero(perm, dataLen * sizeof(size_t));
    delete[] perm;
    secure_memzero(inv_perm, dataLen * sizeof(size_t));
    delete[] inv_perm;

    secure_memzero(round_key, dataLen * sizeof(m_block));
    delete[] round_key;

    return plain;
}
