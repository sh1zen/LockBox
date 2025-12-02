#ifndef LOCKBOX_ALGO_CORE_H
#define LOCKBOX_ALGO_CORE_H

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

// Elliptic curve parameters for non-linear layer
// Using a Montgomery curve: By² = x³ + Ax² + x (mod p)
// These are chosen for efficiency and security
#define EC_PARAM_A 0x1F3D5B79
#define EC_PARAM_B 0x2E4C6A8B

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
void correlate_data(MBLOCK* data, m_block seed = 0);

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
void uncorrelate_data(MBLOCK* data, m_block seed = 0);

#endif //LOCKBOX_ALGO_CORE_H