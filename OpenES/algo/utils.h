#ifndef LOCKBOX_UTILS_H
#define LOCKBOX_UTILS_H

#include "m_block.h"

/**
 * Apply global diffusion to spread changes across all blocks (forward)
 * This ensures that a random value at any position affects ALL blocks.
 *
 * @param data Data MBLOCK to diffuse (modified in place)
 * @param seed Seed value for the transformation
 */
void global_diffuse(MBLOCK* data, m_block seed);

/**
 * Apply inverse global diffusion (reverse direction)
 *
 * @param data Data MBLOCK to un-diffuse (modified in place)
 * @param seed Seed value (must match global_diffuse)
 */
void global_diffuse_inv(MBLOCK* data, m_block seed);

MBLOCK* oes_raw_hmac(const MBLOCK* key, const MBLOCK* data, size_t hmacLen);

#endif //LOCKBOX_UTILS_H