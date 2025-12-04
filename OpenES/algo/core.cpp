#include "core.h"

#include "constants.h"
#include "m_block.h"
#include "oesMath.h"
#include "raw-layer.h"


// ==========================================
// COMPACT GENERIC PRNG
// ==========================================
m_block prng_next(m_block *state) {
    // 1. Avanzamento dello stato
    m_block x = *state + PRNG_SEED;

    // 2. Fast mix dei bit vicini
    x ^= mBlock::rotl(x, 1) ^ mBlock::rotl(x, 3) ^ (x >> 1);

    // 3. Diffusione non-lineare globale
    x ^= (x >> 3) * PRNG_MULT1 + ((x << 3) >> 3) * PRNG_MULT2;

    // 8. Aggiornamento dello stato
    *state = (x + 1) ^ mBlock::rotl(x + x, x);

    return x;
}


// ==========================================
// PSEUDO-HADAMARD TRANSFORM (generic)
// ==========================================
m_block pseudoHadamardT(const m_block block) {
    const m_block a = (block >> OES_HALF_MEM_SIZE) & OES_HALF_BLOCK_MASK;
    const m_block b = block & OES_HALF_BLOCK_MASK;
    const m_block sum = (a + b) & OES_HALF_BLOCK_MASK;
    return ((sum << OES_HALF_MEM_SIZE) | ((sum + b) & OES_HALF_BLOCK_MASK));
}

m_block pseudoHadamardTInv(const m_block block) {
    const m_block a_new = (block >> OES_HALF_MEM_SIZE) & OES_HALF_BLOCK_MASK;
    const m_block b_new = block & OES_HALF_BLOCK_MASK;
    const m_block b = (b_new - a_new) & OES_HALF_BLOCK_MASK;
    return ((a_new - b) & OES_HALF_BLOCK_MASK) << OES_HALF_MEM_SIZE | b;
}


// ============================================================================
// DATA CORRELATION
// ============================================================================

/**
 * Implement data diffusion using block transformations
 * Over input of 3 blocks the output is:
 * - Block 0: F(F(F(0)))
 * - Block 1: F(F(0)) ^ Block 2
 * - Block 2: F(F(F(0))) ^ F(0) ^ Block 1
 */
void correlate_data(MBLOCK *data, m_block seed) {
    if (!data || data->isNull()) return;

    const size_t dataLen = data->getLen();
    if (dataLen == 0) return;

    // Apply xTime transformation to seed once
    xTimeMBlock(&seed);

    // Process blocks in forward order
    for (size_t i = 0; i < dataLen; i++) {
        const m_block currentBlock = data->getBlock(i);
        const size_t nextIdx = (i + 1) % dataLen;
        const m_block nextBlock = data->getBlock(nextIdx);

        // Apply transformations: rotate, XOR with seed, then Hadamard
        m_block k = mBlock::rotl(currentBlock ^ seed, 3);
        k = pseudoHadamardT(k);

        // Update blocks (order matters!)
        data->setBlock(nextIdx, k); // Update next block first
        data->setBlock(i, k ^ nextBlock); // Then update current block
    }
}

void uncorrelate_data(MBLOCK *data, m_block seed) {
    if (!data || data->isNull()) return;

    const size_t dataLen = data->getLen();
    if (dataLen == 0) return;

    // Apply xTime transformation to seed once (must match correlate_data)
    xTimeMBlock(&seed);

    // Process blocks in reverse order to undo correlation
    for (size_t i = dataLen; i > 0; i--) {
        size_t j = i - 1;
        const size_t nextIdx = (j + 1) % dataLen;

        const m_block currentBlock = data->getBlock(j);
        const m_block nextBlock = data->getBlock(nextIdx);

        // Inverse transformations in reverse order
        m_block k = pseudoHadamardTInv(nextBlock);
        k = mBlock::rotr(k, 3) ^ seed;

        // Update blocks in reverse order
        data->setBlock(j, k);
        data->setBlock(nextIdx, nextBlock ^ currentBlock);
    }
}
