#include <cstdlib>
#include <utility>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/support/oesMath.h>
#include "key_management.h"
#include "core.h"
#include "support.h"

// ============================================================================
// PSEUDO-HADAMARD TRANSFORM
// ============================================================================

static m_block pseudoHadamardT(m_block block) {
    m_block mask = (m_block(1) << OES_HALF_BLOCK_SIZE) - 1;
    m_block a = (block >> OES_HALF_BLOCK_SIZE) & mask;
    m_block b = block & mask;

    m_block a_new = (a + b) & mask;
    m_block b_new = (a + b + b) & mask; // a + 2b

    return (a_new << OES_HALF_BLOCK_SIZE) | b_new;
}

static m_block pseudoHadamardTInv(m_block block) {
    m_block mask = (m_block(1) << OES_HALF_BLOCK_SIZE) - 1;
    m_block a_new = (block >> OES_HALF_BLOCK_SIZE) & mask;
    m_block b_new = block & mask;

    // Inverse: a = 2*a_new - b_new, b = b_new - a_new
    m_block a = ((a_new << 1) - b_new) & mask;
    m_block b = (b_new - a_new) & mask;

    return (a << OES_HALF_BLOCK_SIZE) | b;
}

// ============================================================================
// SIMPLE PRNG FOR DETERMINISTIC OPERATIONS
// ============================================================================

static m_block prng_next(m_block *state) {
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
    if (x == 0) x = MASK_TO_BLOCK_SIZE(0x12345678, 0x12345678);;
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
    t = t * 0x9E3779B9; // Multiplication by golden ratio constant
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
    m_block mask = (m_block(1) << OES_HALF_BLOCK_SIZE) - 1;
    m_block L = (block >> OES_HALF_BLOCK_SIZE) & mask;
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

    return (L << OES_HALF_BLOCK_SIZE) | R;
}

/**
 * Inverse Feistel S-Box - undo the 4 rounds in reverse
 */
static m_block feistel_sbox_inv(m_block block, m_block key) {
    m_block mask = (m_block(1) << OES_HALF_BLOCK_SIZE) - 1;
    m_block L = (block >> OES_HALF_BLOCK_SIZE) & mask;
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

    return (L << OES_HALF_BLOCK_SIZE) | R;
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
    if (state == 0) {
        state =MASK_TO_BLOCK_SIZE(0x12345678, 0x12345678);
    }

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
    if (state == 0) state = MASK_TO_BLOCK_SIZE(0xDEADBEEF, 0xDEADBEEF);

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
    if (state == 0) {
        state = MASK_TO_BLOCK_SIZE(0xDEADBEEF, 0xDEADBEEF);
    }

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
    if (state == 0) {
        state = MASK_TO_BLOCK_SIZE(0xCAFEBABE, 0xCAFEBABE);
    }

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
    if (state == 0) {
        state = MASK_TO_BLOCK_SIZE(0xCAFEBABE, 0xCAFEBABE);
    }

    // Pre-generate rotation amounts
    auto *rots = static_cast<m_block *>(malloc(len * sizeof(m_block)));
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

    size_t dataLen = data->getLen();

    // Clone input data
    MBLOCK *cipher = data->clone();

    // Allocate working buffers
    auto temp = new m_block[dataLen];
    auto perm = new size_t[dataLen];

    // Expand key using MBLOCK
    size_t exp_key_len = (OES_CORE_ROUNDS + 2) * dataLen;
    MBLOCK *exp_key = key_expansion(key, exp_key_len, m_block(0x67452301), 5);

    if (!exp_key || exp_key->isNull()) {
        delete cipher;
        delete[] temp;
        delete[] perm;
        if (exp_key) delete exp_key;
        return nullptr;
    }

    // Extract cipher data for processing
    auto cipherData = new m_block[dataLen];
    for (size_t i = 0; i < dataLen; i++) {
        cipherData[i] = cipher->getBlock(i);
    }

    // Initial whitening
    for (size_t i = 0; i < dataLen; i++) {
        cipherData[i] ^= exp_key->getBlock(i);
    }

    // Main rounds
    for (int r = 0; r < OES_CORE_ROUNDS; r++) {
        // Extract round key
        auto round_key = new m_block[dataLen];
        for (size_t i = 0; i < dataLen; i++) {
            round_key[i] = exp_key->getBlock((r + 1) * dataLen + i);
        }

        enc_round(cipherData, dataLen, round_key, perm, temp, r);

        secure_memzero(round_key, dataLen * sizeof(m_block));
        delete[] round_key;
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
    delete[] temp;
    delete[] perm;

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

    // Clone input data
    MBLOCK *plain = data->clone();

    // Allocate working buffers
    auto temp = new m_block[dataLen];
    auto perm = new size_t[dataLen];
    auto inv_perm = new size_t[dataLen];

    // Expand key using MBLOCK (same as encryption)
    size_t exp_key_len = (OES_CORE_ROUNDS + 2) * dataLen;
    MBLOCK *exp_key = key_expansion(key, exp_key_len, m_block(0x67452301), 5);

    if (!exp_key || exp_key->isNull()) {
        delete plain;
        delete[] temp;
        delete[] perm;
        delete[] inv_perm;
        if (exp_key) delete exp_key;
        return nullptr;
    }

    // Extract plain data for processing
    auto plainData = new m_block[dataLen];
    for (size_t i = 0; i < dataLen; i++) {
        plainData[i] = plain->getBlock(i);
    }

    // Remove final whitening
    for (size_t i = 0; i < dataLen; i++) {
        plainData[i] ^= exp_key->getBlock((OES_CORE_ROUNDS + 1) * dataLen + i);
    }

    // Inverse rounds (reverse order)
    for (int r = OES_CORE_ROUNDS - 1; r >= 0; r--) {
        // Extract round key
        auto round_key = new m_block[dataLen];
        for (size_t i = 0; i < dataLen; i++) {
            round_key[i] = exp_key->getBlock((r + 1) * dataLen + i);
        }

        dec_round(plainData, dataLen, round_key, perm, inv_perm, temp, r);

        secure_memzero(round_key, dataLen * sizeof(m_block));
        delete[] round_key;
    }

    // Remove initial whitening
    for (size_t i = 0; i < dataLen; i++) {
        plainData[i] ^= exp_key->getBlock(i);
    }

    // Update plain MBLOCK with decrypted data
    for (size_t i = 0; i < dataLen; i++) {
        plain->setBlock(i, plainData[i]);
    }

    // Cleanup
    exp_key->secure_zero();
    delete exp_key;
    secure_memzero(plainData, dataLen * sizeof(m_block));
    delete[] plainData;
    delete[] temp;
    delete[] perm;
    delete[] inv_perm;

    return plain;
}

// ============================================================================
// DATA CORRELATION
// ============================================================================

/**
 * Implement some data diffusion
 * Over input of 3 blocks the output is:
 * - 0 F(F(F(0)))
 * - 1 F(F(0)) ^ 2
 * - 2 F(F(F(0))) ^ F(0) ^ 1
 */
void correlate_data(MBLOCK *data, m_block seed) {
    if (!data || data->isNull()) return;

    size_t dataLen = data->getLen();
    if (dataLen == 0) return;

    m_block k;
    xTimeMBlock(&seed);

    for (size_t i = 0; i < dataLen; i++) {
        m_block currentBlock = data->getBlock(i);
        m_block nextBlock = data->getBlock((i + 1) % dataLen);

        k = mBlock_rotl(currentBlock ^ seed, 3);
        k = pseudoHadamardT(k);

        data->setBlock(i, k ^ nextBlock);
        data->setBlock((i + 1) % dataLen, k);
    }
}

void uncorrelate_data(MBLOCK *data, m_block seed) {
    if (!data || data->isNull()) return;

    size_t dataLen = data->getLen();
    if (dataLen == 0) return;

    m_block k;
    xTimeMBlock(&seed);

    for (size_t j, i = dataLen; i >= 1; i--) {
        j = i - 1;

        m_block nextBlock = data->getBlock((j + 1) % dataLen);
        m_block currentBlock = data->getBlock(j);

        k = pseudoHadamardTInv(nextBlock);
        data->setBlock((j + 1) % dataLen, nextBlock ^ currentBlock);
        data->setBlock(j, mBlock_rotr(k, 3) ^ seed);
    }
}
