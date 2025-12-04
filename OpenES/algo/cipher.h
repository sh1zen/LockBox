#ifndef LOCKBOX_ALGO_CIPHER_H
#define LOCKBOX_ALGO_CIPHER_H

#include "m_block.h"

/**
 * OES Post-Quantum Core Encryption Module
 *
 * This module implements a post-quantum resistant symmetric cipher based on:
 * 1. Key-dependent permutation matrices for diffusion
 * 2. Non-linear polynomials over elliptic curve arithmetic for confusion
 * 3. Multiple rounds with key schedule derived from expanded key
 *
 * Security features:
 * - Resistant to Grover's algorithm (symmetric key doubling)
 * - Non-linear S-box based on elliptic curve point operations
 * - Key-dependent permutations prevent linear/differential cryptanalysis
 */

// Number of encryption rounds (minimum 12 for security)
#define OES_CORE_ROUNDS 16

// ============================================================================
// MBLOCK API (RECOMMENDED)
// ============================================================================

/**
 * Raw encryption function - Post-Quantum resistant (MBLOCK version)
 *
 * @param data Input plaintext MBLOCK
 * @param key Encryption key MBLOCK
 * @return Newly allocated ciphertext MBLOCK (caller must delete), or nullptr on error
 *
 * Example:
 *   MBLOCK* plaintext = MBLOCK::fromBytes("Hello", 5);
 *   MBLOCK* key = MBLOCK::fromBytes("password", 8);
 *   MBLOCK* ciphertext = raw_enc(plaintext, key);
 *   // Use ciphertext...
 *   delete plaintext;
 *   delete key;
 *   delete ciphertext;
 */
MBLOCK* raw_enc(const MBLOCK* data, const MBLOCK* key);

/**
 * Raw decryption function - Post-Quantum resistant (MBLOCK version)
 *
 * @param data Input ciphertext MBLOCK
 * @param key Decryption key MBLOCK
 * @return Newly allocated plaintext MBLOCK (caller must delete), or nullptr on error
 *
 * Example:
 *   MBLOCK* decrypted = raw_dec(ciphertext, key);
 *   auto [bytes, len] = decrypted->toBytes();
 *   // Use bytes...
 *   delete[] bytes;
 *   delete decrypted;
 */
MBLOCK* raw_dec(const MBLOCK* data, const MBLOCK* key);

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

#endif //LOCKBOX_ALGO_CIPHER_H