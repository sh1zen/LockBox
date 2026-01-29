#pragma once

#include "m_block.h"

m_block prng_next(m_block *state);

m_block pseudoHadamardT(m_block block);

m_block pseudoHadamardTInv(m_block block);

/**
 * Apply data correlation/diffusion (forward direction) - MBLOCK version
 *
 * @param data Data MBLOCK to correlate (modified in place)
 * @param seed Seed value for the transformation
 *
 * Example:
 *   MBLOCK* data = MBLOCK::fromBytes("data", 4);
 *   correlate_data(data, 0x12345678);
 *   // data is now correlated
 *   delete data;
 */
void correlate_data(MBLOCK *data, m_block seed = 0);

/**
 * Apply data uncorrelation/diffusion (inverse direction) - MBLOCK version
 *
 * @param data Data MBLOCK to uncorrelate (modified in place)
 * @param seed Seed value for the transformation (must match correlate_data)
 *
 * Example:
 *   uncorrelate_data(data, 0x12345678);
 *   // data is now uncorrelated
 */
void uncorrelate_data(MBLOCK *data, m_block seed = 0);

/**
 * Apply global diffusion to spread changes across all blocks (forward)
 * This ensures that a random value at any position affects ALL blocks.
 *
 * @param data Data MBLOCK to diffuse (modified in place)
 * @param seed Seed value for the transformation
 */
void global_diffuse(MBLOCK *data, m_block seed);

/**
 * Apply inverse global diffusion (reverse direction)
 *
 * @param data Data MBLOCK to un-diffuse (modified in place)
 * @param seed Seed value (must match global_diffuse)
 */
void global_diffuse_inv(MBLOCK *data, m_block seed);
