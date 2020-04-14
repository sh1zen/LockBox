#ifndef LOCKBOX_ALGO_CORE_H
#define LOCKBOX_ALGO_CORE_H

#include <OpenES/layer/raw-layer.h>
#include "oes_common.h"

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

// Elliptic curve parameters for non-linear layer
// Using a Montgomery curve: By² = x³ + Ax² + x (mod p)
// These are chosen for efficiency and security
#define EC_PARAM_A 0x1F3D5B79
#define EC_PARAM_B 0x2E4C6A8B

/**
 * Raw encryption function - Post-Quantum resistant
 *
 * @param data Input plaintext blocks
 * @param dataLen Number of blocks
 * @param key Encryption key blocks
 * @return Newly allocated ciphertext (caller must free), or nullptr on error
 */
m_block *raw_enc(const m_block *data, size_t dataLen, const m_block *key);

/**
 * Raw decryption function - Post-Quantum resistant
 *
 * @param data Input ciphertext blocks
 * @param dataLen Number of blocks
 * @param key Decryption key blocks
 * @return Newly allocated plaintext (caller must free), or nullptr on error
 */
m_block *raw_dec(const m_block *data, size_t dataLen, const m_block *key);

/**
 * Apply data correlation/diffusion (forward direction)
 *
 * @param data Data blocks to correlate (modified in place)
 * @param dataLen Number of blocks
 * @param seed Seed value for the transformation
 */
void correlate_data(m_block *data, size_t dataLen, m_block seed = 0);

/**
 * Apply data uncorrelation/diffusion (inverse direction)
 *
 * @param data Data blocks to uncorrelate (modified in place)
 * @param dataLen Number of blocks
 * @param seed Seed value for the transformation (must match correlate_data)
 */
void uncorrelate_data(m_block *data, size_t dataLen, m_block seed = 0);

#endif //LOCKBOX_ALGO_CORE_H