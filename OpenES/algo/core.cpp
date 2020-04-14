#include <cstdlib>
#include <cstring>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/support/oesMath.h>
#include "key_managment.h"
#include "converter.h"
#include "core.h"

#include "support.h"

// ============================================================================
// PSEUDO-HADAMARD TRANSFORM
// ============================================================================

static m_block pseudoHadamardT(m_block block) {
    m_block mask = (m_block(1) << OES_MID_BLOCK_SIZE) - 1;
    m_block a = (block >> OES_MID_BLOCK_SIZE) & mask;
    m_block b = block & mask;

    m_block a_new = (a + b) & mask;
    m_block b_new = (a + b + b) & mask;  // a + 2b

    return (a_new << OES_MID_BLOCK_SIZE) | b_new;
}

static m_block pseudoHadamardTInv(m_block block) {
    m_block mask = (m_block(1) << OES_MID_BLOCK_SIZE) - 1;
    m_block a_new = (block >> OES_MID_BLOCK_SIZE) & mask;
    m_block b_new = block & mask;

    // Inverse: a = 2*a_new - b_new, b = b_new - a_new
    m_block a = ((a_new << 1) - b_new) & mask;
    m_block b = (b_new - a_new) & mask;

    return (a << OES_MID_BLOCK_SIZE) | b;
}

// ============================================================================
// SIMPLE PRNG FOR DETERMINISTIC OPERATIONS
// ============================================================================

static inline m_block prng_next(m_block *state) {
    m_block x = *state;
#if OES_MEM_SIZE <= 32
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
#else
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
#endif
    if (x == 0) x = 0x12345678;
    *state = x;
    return x;
}

// ============================================================================
// BIJECTIVE S-BOX BASED ON FEISTEL STRUCTURE
// ============================================================================
//
// Instead of EC polynomials (hard to invert exactly), we use a Feistel-based
// S-box which is guaranteed to be bijective and perfectly invertible.
// The non-linearity comes from mixing operations within the Feistel rounds.
// ============================================================================

/**
 * Non-linear mixing function for Feistel S-box
 */
static inline m_block sbox_f(m_block x, m_block key) {
    // Non-linear operations that don't need to be invertible
    m_block t = x ^ key;
    t = t * 0x9E3779B9;  // Multiplication by golden ratio constant
    t ^= mBlock_rotr(t, 5);
    t += mBlock_rotl(x, 11);
    t ^= (t >> 7);
    t *= 0x85EBCA6B;
    t ^= mBlock_rotr(t, 13);
    return t;
}

/**
 * Feistel-based S-Box (4 rounds) - guaranteed bijective
 */
static m_block feistel_sbox(m_block block, m_block key) {
    m_block mask = (m_block(1) << OES_MID_BLOCK_SIZE) - 1;
    m_block L = (block >> OES_MID_BLOCK_SIZE) & mask;
    m_block R = block & mask;

    // 4 Feistel rounds
    m_block k = key;
    for (int i = 0; i < 4; i++) {
        m_block F = sbox_f(R, k) & mask;
        m_block newR = L ^ F;
        L = R;
        R = newR;
        k = prng_next(&k);
    }

    return (L << OES_MID_BLOCK_SIZE) | R;
}

/**
 * Inverse Feistel S-Box - undo the 4 rounds in reverse
 */
static m_block feistel_sbox_inv(m_block block, m_block key) {
    m_block mask = (m_block(1) << OES_MID_BLOCK_SIZE) - 1;
    m_block L = (block >> OES_MID_BLOCK_SIZE) & mask;
    m_block R = block & mask;

    // Generate all round keys first
    m_block keys[4];
    m_block k = key;
    for (int i = 0; i < 4; i++) {
        keys[i] = k;
        k = prng_next(&k);
    }

    // 4 Feistel rounds in reverse
    for (int i = 3; i >= 0; i--) {
        m_block F = sbox_f(L, keys[i]) & mask;
        m_block newL = R ^ F;
        R = L;
        L = newL;
    }

    return (L << OES_MID_BLOCK_SIZE) | R;
}

// ============================================================================
// PERMUTATION LAYER
// ============================================================================

/**
 * Generate a permutation array using Fisher-Yates shuffle
 */
static void generate_permutation(size_t *perm, size_t len, m_block seed) {
    for (size_t i = 0; i < len; i++) {
        perm[i] = i;
    }

    m_block state = seed;
    if (state == 0) state = 0x12345678;

    for (size_t i = len - 1; i > 0; i--) {
        size_t j = prng_next(&state) % (i + 1);
        size_t temp = perm[i];
        perm[i] = perm[j];
        perm[j] = temp;
    }
}

/**
 * Generate inverse permutation
 */
static void invert_permutation(size_t *inv, const size_t *perm, size_t len) {
    for (size_t i = 0; i < len; i++) {
        inv[perm[i]] = i;
    }
}

/**
 * Apply permutation to blocks
 */
static void apply_block_permutation(m_block *data, const size_t *perm, size_t len, m_block *temp) {
    for (size_t i = 0; i < len; i++) {
        temp[i] = data[perm[i]];
    }
    memcpy(data, temp, len * sizeof(m_block));
}

/**
 * Bit permutation within a block
 */
static m_block bit_permute(m_block block, m_block seed) {
    m_block result = 0;
    m_block state = seed;
    if (state == 0) state = 0xDEADBEEF;

    uint8_t perm[OES_MEM_SIZE];
    for (int i = 0; i < OES_MEM_SIZE; i++) {
        perm[i] = i;
    }

    for (int i = OES_MEM_SIZE - 1; i > 0; i--) {
        int j = prng_next(&state) % (i + 1);
        uint8_t t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
    }

    for (int i = 0; i < OES_MEM_SIZE; i++) {
        if (block & (m_block(1) << i)) {
            result |= (m_block(1) << perm[i]);
        }
    }

    return result;
}

/**
 * Inverse bit permutation
 */
static m_block bit_permute_inv(m_block block, m_block seed) {
    m_block result = 0;
    m_block state = seed;
    if (state == 0) state = 0xDEADBEEF;

    uint8_t perm[OES_MEM_SIZE];
    uint8_t inv[OES_MEM_SIZE];
    for (int i = 0; i < OES_MEM_SIZE; i++) {
        perm[i] = i;
    }

    for (int i = OES_MEM_SIZE - 1; i > 0; i--) {
        int j = prng_next(&state) % (i + 1);
        uint8_t t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
    }

    // Invert
    for (int i = 0; i < OES_MEM_SIZE; i++) {
        inv[perm[i]] = i;
    }

    for (int i = 0; i < OES_MEM_SIZE; i++) {
        if (block & (m_block(1) << i)) {
            result |= (m_block(1) << inv[i]);
        }
    }

    return result;
}

// ============================================================================
// LINEAR MIXING LAYER (Invertible)
// ============================================================================

/**
 * Mix adjacent blocks - uses XOR and rotation (perfectly invertible)
 */
static void mix_blocks(m_block *data, size_t len, m_block seed) {
    if (len < 2) return;

    m_block state = seed;
    if (state == 0) state = 0xCAFEBABE;

    // Forward pass: each block mixes with the next
    for (size_t i = 0; i < len - 1; i++) {
        m_block rot_amount = (prng_next(&state) % (OES_MEM_SIZE - 1)) + 1;
        data[i + 1] ^= mBlock_rotl(data[i], rot_amount);
    }

    // Wrap-around
    m_block rot_amount = (prng_next(&state) % (OES_MEM_SIZE - 1)) + 1;
    data[0] ^= mBlock_rotl(data[len - 1], rot_amount);
}

/**
 * Inverse mix - undo in reverse order
 */
static void mix_blocks_inv(m_block *data, size_t len, m_block seed) {
    if (len < 2) return;

    m_block state = seed;
    if (state == 0) state = 0xCAFEBABE;

    // Pre-generate rotation amounts
    m_block *rots = static_cast<m_block*>(malloc(len * sizeof(m_block)));
    if (!rots) return;

    for (size_t i = 0; i < len; i++) {
        rots[i] = (prng_next(&state) % (OES_MEM_SIZE - 1)) + 1;
    }

    // Undo wrap-around first
    data[0] ^= mBlock_rotl(data[len - 1], rots[len - 1]);

    // Backward pass
    for (size_t i = len - 1; i > 0; i--) {
        data[i] ^= mBlock_rotl(data[i - 1], rots[i - 1]);
    }

    free(rots);
}

// ============================================================================
// ROUND FUNCTIONS
// ============================================================================

/**
 * Single encryption round
 */
static void enc_round(m_block *data, size_t len, const m_block *round_key,
                      size_t *perm, m_block *temp, int round) {
    // 1. Add round key
    for (size_t i = 0; i < len; i++) {
        data[i] ^= round_key[i % len];
    }

    // 2. Feistel S-box (non-linear, bijective)
    m_block sbox_key = round_key[0] ^ (m_block(round) * 0x9E3779B9);
    for (size_t i = 0; i < len; i++) {
        data[i] = feistel_sbox(data[i], sbox_key ^ i);
    }

    // 3. Bit permutation
    m_block bit_seed = round_key[round % len] ^ round;
    for (size_t i = 0; i < len; i++) {
        data[i] = bit_permute(data[i], bit_seed ^ i);
    }

    // 4. Pseudo-Hadamard
    for (size_t i = 0; i < len; i++) {
        data[i] = pseudoHadamardT(data[i]);
    }

    // 5. Block permutation
    if (len > 1) {
        m_block perm_seed = round_key[1 % len] ^ (round * 0x85EBCA6B);
        generate_permutation(perm, len, perm_seed);
        apply_block_permutation(data, perm, len, temp);
    }

    // 6. Linear mixing
    m_block mix_seed = round_key[2 % len] ^ (round * 0xC2B2AE35);
    mix_blocks(data, len, mix_seed);
}

/**
 * Single decryption round (exact inverse)
 */
static void dec_round(m_block *data, size_t len, const m_block *round_key,
                      size_t *perm, size_t *inv_perm, m_block *temp, int round) {
    // 6. Inverse linear mixing
    m_block mix_seed = round_key[2 % len] ^ (round * 0xC2B2AE35);
    mix_blocks_inv(data, len, mix_seed);

    // 5. Inverse block permutation
    if (len > 1) {
        m_block perm_seed = round_key[1 % len] ^ (round * 0x85EBCA6B);
        generate_permutation(perm, len, perm_seed);
        invert_permutation(inv_perm, perm, len);
        apply_block_permutation(data, inv_perm, len, temp);
    }

    // 4. Inverse Pseudo-Hadamard
    for (size_t i = 0; i < len; i++) {
        data[i] = pseudoHadamardTInv(data[i]);
    }

    // 3. Inverse bit permutation
    m_block bit_seed = round_key[round % len] ^ round;
    for (size_t i = 0; i < len; i++) {
        data[i] = bit_permute_inv(data[i], bit_seed ^ i);
    }

    // 2. Inverse Feistel S-box
    m_block sbox_key = round_key[0] ^ (m_block(round) * 0x9E3779B9);
    for (size_t i = 0; i < len; i++) {
        data[i] = feistel_sbox_inv(data[i], sbox_key ^ i);
    }

    // 1. Remove round key
    for (size_t i = 0; i < len; i++) {
        data[i] ^= round_key[i % len];
    }
}

// ============================================================================
// MAIN ENCRYPTION/DECRYPTION
// ============================================================================

m_block *raw_enc(const m_block *data, size_t dataLen, const m_block *key) {
    if (!data || !key || dataLen == 0) {
        return nullptr;
    }

    // Clone input data
    m_block *cipher = mBlock_clone(nullptr, data, dataLen);
    if (!cipher) {
        return nullptr;
    }

    // Allocate working buffers
    m_block *temp = static_cast<m_block*>(malloc(dataLen * sizeof(m_block)));
    size_t *perm = static_cast<size_t*>(malloc(dataLen * sizeof(size_t)));

    if (!temp || !perm) {
        free(cipher);
        if (temp) free(temp);
        if (perm) free(perm);
        return nullptr;
    }

    // Expand key
    size_t exp_key_len = (OES_CORE_ROUNDS + 2) * dataLen;
    m_block *exp_key = key_expansion(key, dataLen, exp_key_len, m_block(0x67452301), 5);
    if (!exp_key) {
        free(cipher);
        free(temp);
        free(perm);
        return nullptr;
    }

    // Initial whitening
    for (size_t i = 0; i < dataLen; i++) {
        cipher[i] ^= exp_key[i];
    }

    // Main rounds
    for (int r = 0; r < OES_CORE_ROUNDS; r++) {
        const m_block *round_key = &exp_key[(r + 1) * dataLen];
        enc_round(cipher, dataLen, round_key, perm, temp, r);
    }

    // Final whitening
    for (size_t i = 0; i < dataLen; i++) {
        cipher[i] ^= exp_key[(OES_CORE_ROUNDS + 1) * dataLen + i];
    }

    // Cleanup
    secure_memzero(exp_key, exp_key_len * sizeof(m_block));
    free(exp_key);
    free(temp);
    free(perm);

    return cipher;
}

m_block *raw_dec(const m_block *data, size_t dataLen, const m_block *key) {
    if (!data || !key || dataLen == 0) {
        return nullptr;
    }

    // Clone input data
    m_block *plain = mBlock_clone(nullptr, data, dataLen);
    if (!plain) {
        return nullptr;
    }

    // Allocate working buffers
    m_block *temp = static_cast<m_block*>(malloc(dataLen * sizeof(m_block)));
    size_t *perm = static_cast<size_t*>(malloc(dataLen * sizeof(size_t)));
    size_t *inv_perm = static_cast<size_t*>(malloc(dataLen * sizeof(size_t)));

    if (!temp || !perm || !inv_perm) {
        free(plain);
        if (temp) free(temp);
        if (perm) free(perm);
        if (inv_perm) free(inv_perm);
        return nullptr;
    }

    // Expand key (same as encryption)
    size_t exp_key_len = (OES_CORE_ROUNDS + 2) * dataLen;
    m_block *exp_key = key_expansion(key, dataLen, exp_key_len, m_block(0x67452301), 5);
    if (!exp_key) {
        free(plain);
        free(temp);
        free(perm);
        free(inv_perm);
        return nullptr;
    }

    // Remove final whitening
    for (size_t i = 0; i < dataLen; i++) {
        plain[i] ^= exp_key[(OES_CORE_ROUNDS + 1) * dataLen + i];
    }

    // Inverse rounds (reverse order)
    for (int r = OES_CORE_ROUNDS - 1; r >= 0; r--) {
        const m_block *round_key = &exp_key[(r + 1) * dataLen];
        dec_round(plain, dataLen, round_key, perm, inv_perm, temp, r);
    }

    // Remove initial whitening
    for (size_t i = 0; i < dataLen; i++) {
        plain[i] ^= exp_key[i];
    }

    // Cleanup
    secure_memzero(exp_key, exp_key_len * sizeof(m_block));
    free(exp_key);
    free(temp);
    free(perm);
    free(inv_perm);

    return plain;
}

// ============================================================================
// DATA CORRELATION (preserved from original)
// ============================================================================


/**
 * Implement some data diffusion
 * Over input of 3 blocks the output is:
 * - 0 F(F(F(0)))
 * - 1 F(F(0)) ^ 2
 * - 2 F(F(F(0))) ^ F(0) ^ 1
 */
void correlate_data(m_block *data, size_t dataLen, m_block seed) {
    if (!data || dataLen == 0) return;

    m_block k;
    xTimeMBlock(&seed);

    for (size_t i = 0; i < dataLen; i++) {
        k = mBlock_rotl(data[i] ^ seed, 3);
        k = pseudoHadamardT(k);

        data[i] = k ^ data[(i + 1) % dataLen];
        data[(i + 1) % dataLen] = k;
    }
}

void uncorrelate_data(m_block *data, size_t dataLen, m_block seed) {
    if (!data || dataLen == 0) return;

    m_block k;
    xTimeMBlock(&seed);

    for (size_t j, i = dataLen; i >= 1; i--) {
        j = i - 1;

        k = pseudoHadamardTInv(data[(j + 1) % dataLen]);
        data[(j + 1) % dataLen] ^= data[j];
        data[j] = mBlock_rotr(k, 3) ^ seed;
    }
}