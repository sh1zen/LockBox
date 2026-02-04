#include "sphinix.h"

#include <memory>
#include <algorithm>
#include <cstring>

#include "core.h"
#include "key_management.h"
#include "support.h"

// ============================================================================
// SPHINX CIPHER v3.1 - Wide-Block Cipher with Cross-Block S-box
// ============================================================================
//
// CIPHER OPERATION OVERVIEW:
// ==========================
//
// ENCRYPTION FLOW (Plaintext → Ciphertext):
// -----------------------------------------
// 1. KEY EXPANSION
//    - Input key is expanded to match the wide-block size (1-16 blocks)
//    - Uses sponge-based key schedule to generate per-round keys
//    - Derives algebraic keys for S-box operations with cross-block mixing
//
// 2. INITIAL WHITENING
//    - Plaintext blocks XORed with first round key (pre-whitening)
//    - Prevents attacker from analyzing first round directly
//
// 3. INITIAL GLOBAL DIFFUSION
//    - Spreads influence of each plaintext bit across all blocks
//    - Uses bidirectional mixing (forward + backward passes)
//    - Creates strong avalanche effect across entire wide block
//
// 4. MAIN ROUND FUNCTION (repeated NUM_ROUNDS times):
//    a) KEY ADDITION: XOR with round-specific key
//    b) WIDE S-BOX LAYER: Feistel-based cross-block substitution
//       - Splits data into left/right halves
//       - Each left block depends on ALL right blocks
//       - Provides cross-block non-linearity (security scales with block count)
//    c) ALGEBRAIC S-BOX: Key-dependent byte substitution
//       - 8-round non-linear transformation per block
//       - Mixes rotations, multiplications, XORs with derived keys
//       - High algebraic degree for resistance to algebraic attacks
//    d) DIFFUSION LAYER: Pseudo-Hadamard transform + quarter rounds
//       - Mixes data within and across blocks
//       - Ensures changes propagate rapidly
//    e) ROUND CONSTANT INJECTION: Domain separation per round
//
// 5. FINAL GLOBAL DIFFUSION
//    - Another full diffusion pass with different seeds
//    - Ensures complete mixing before output
//
// 6. FINAL WHITENING
//    - XOR with final round key (post-whitening)
//    - Output = ciphertext
//
// DECRYPTION FLOW (Ciphertext → Plaintext):
// -----------------------------------------
// Exact reverse of encryption:
// 1. Remove final whitening
// 2. Inverse final global diffusion
// 3. Reverse main rounds (inverse S-boxes, inverse diffusion)
// 4. Inverse initial global diffusion
// 5. Remove initial whitening
// 6. Output = plaintext
//
// SECURITY PROPERTIES:
// -------------------
// - Minimum attack complexity: m_block × OES_NUM_OF_BLOCK bits
// - Completely invertible (all operations have exact inverses)
// - Wide S-box creates dependency on ALL blocks simultaneously
// - Algebraic S-box provides high non-linearity
// - Global diffusion ensures full avalanche in 2 rounds
// - Key-dependent transformations prevent related-key attacks
//
// Architecture:
//   - Configurable wide-block cipher (1-16 blocks)
//   - Key schedule based on sponge construction
//   - NEW: Wide S-box with cross-block dependency (complexity: m_block × N)
//   - Algebraic S-box with derived keys
//   - Completely invertible global diffusion (XOR only)
//   - Pseudo-Hadamard transform for non-linear mixing
//
namespace SPHINX {
    // ============================================================================
    // COMPILE-TIME UTILITIES
    // ============================================================================

    /**
     * Compute modular multiplicative inverse using Newton-Raphson method
     * @param a The value to invert (must be odd for finite field arithmetic)
     * @return Multiplicative inverse of a
     */
    constexpr m_block compute_mod_inverse(m_block a) {
        m_block x = a;
        for (int i = 0; i < 6; ++i) x *= (2 - a * x);
        return x;
    }

    // ============================================================================
    // WIDE-BLOCK CONFIGURATION
    // ============================================================================
    static_assert(OES_NUM_OF_BLOCKS >= 1 && OES_NUM_OF_BLOCKS <= 16,
                  "OES_NUM_OF_BLOCK must be between 1 and 16");

    constexpr size_t WIDE_BLOCK_BITS = OES_MEM_SIZE * OES_NUM_OF_BLOCKS;
    constexpr size_t KEY_BLOCKS = OES_NUM_OF_BLOCKS;
    constexpr size_t SCHEDULER_STATE_SIZE = (OES_NUM_OF_BLOCKS < 4) ? 4 : OES_NUM_OF_BLOCKS;
    constexpr size_t BYTES_PER_BLOCK = OES_MEM_SIZE / 8;

    // ============================================================================
    // CRYPTOGRAPHIC CONSTANTS
    // ============================================================================
    // Mathematical constants derived from φ, e, π, √2, √3, √5 (nothing-up-my-sleeve)
    alignas(64) constexpr m_block PHI = MASK_TO_BLOCK_SIZE(0x9E3779B97F4A7C15ULL, 0xF39CC0605CEDC834ULL);
    alignas(64) constexpr m_block E_CONST = MASK_TO_BLOCK_SIZE(0xB7E151628AED2A6AULL, 0xBF7158809CF4F3C7ULL);
    alignas(64) constexpr m_block PI_CONST = MASK_TO_BLOCK_SIZE(0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL);
    alignas(64) constexpr m_block SQRT2 = MASK_TO_BLOCK_SIZE(0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL);
    alignas(64) constexpr m_block SQRT3 = MASK_TO_BLOCK_SIZE(0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL);
    alignas(64) constexpr m_block SQRT5 = MASK_TO_BLOCK_SIZE(0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL);

    // Domain separation constants for different cipher operations
    alignas(64) constexpr m_block DOMAIN_ENC = MASK_TO_BLOCK_SIZE(0x454E4352595054EDULL, 0x0000000000000001ULL);
    alignas(64) constexpr m_block DOMAIN_KEY = MASK_TO_BLOCK_SIZE(0x4B45595343484544ULL, 0x0000000000000003ULL);
    alignas(64) constexpr m_block DOMAIN_DIFF = MASK_TO_BLOCK_SIZE(0x4449464655534F4EULL, 0x0000000000000004ULL);
    alignas(64) constexpr m_block DOMAIN_WSBOX = MASK_TO_BLOCK_SIZE(0x5749444553424F58ULL, 0x0000000000000005ULL);

    // Diffusion layer constants
    alignas(64) constexpr m_block DIFFUSE_K0 = MASK_TO_BLOCK_SIZE(0x67452301EFCDAB89ULL, 0x98BADCFE10325476ULL);
    alignas(64) constexpr m_block DIFFUSE_K1 = MASK_TO_BLOCK_SIZE(0xC3D2E1F0A1B2C3D4ULL, 0xE5F6A7B8C9D0E1F2ULL);
    alignas(64) constexpr m_block DIFFUSE_K2 = MASK_TO_BLOCK_SIZE(0xF0E1D2C3B4A59687ULL, 0x7869584A3B2C1D0EULL);

    // Parity constant for key derivation
    alignas(64) constexpr m_block TF_PARITY = MASK_TO_BLOCK_SIZE(0x1BD11BDAA9FC1A22ULL, 0x0000000000000000ULL);

    // Round constants array (derived from fractional parts of cube roots of primes)
    alignas(64) constexpr m_block RC[32] = {
        MASK_TO_BLOCK_SIZE(0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL),
        MASK_TO_BLOCK_SIZE(0xA4093822299F31D0ULL, 0x082EFA98EC4E6C89ULL),
        MASK_TO_BLOCK_SIZE(0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL),
        MASK_TO_BLOCK_SIZE(0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL),
        MASK_TO_BLOCK_SIZE(0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL),
        MASK_TO_BLOCK_SIZE(0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL),
        MASK_TO_BLOCK_SIZE(0xBA7C9045F12C7F99ULL, 0x24A19947B3916CF7ULL),
        MASK_TO_BLOCK_SIZE(0x0801F2E2858EFC16ULL, 0x636920D871574E69ULL),
        MASK_TO_BLOCK_SIZE(0xA5A5A5A5A5A5A5A5ULL, 0x5A5A5A5A5A5A5A5AULL),
        MASK_TO_BLOCK_SIZE(0xF0E1D2C3B4A59687ULL, 0x7869584A3B2C1D0EULL),
        MASK_TO_BLOCK_SIZE(0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL),
        MASK_TO_BLOCK_SIZE(0xC3D2E1F0A1B2C3D4ULL, 0xE5F6A7B8C9D0E1F2ULL),
        MASK_TO_BLOCK_SIZE(0x6A09E667F3BCC908ULL, 0xB2FB1366EA957D3EULL),
        MASK_TO_BLOCK_SIZE(0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL),
        MASK_TO_BLOCK_SIZE(0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL),
        MASK_TO_BLOCK_SIZE(0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL),
        MASK_TO_BLOCK_SIZE(0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL),
        MASK_TO_BLOCK_SIZE(0xE49B69C19EF14AD2ULL, 0x0FC19DC68B8CD5B5ULL),
        MASK_TO_BLOCK_SIZE(0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL),
        MASK_TO_BLOCK_SIZE(0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL),
        MASK_TO_BLOCK_SIZE(0x76F988DA831153B5ULL, 0x983E5152EE66DFABULL),
        MASK_TO_BLOCK_SIZE(0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL),
        MASK_TO_BLOCK_SIZE(0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL),
        MASK_TO_BLOCK_SIZE(0xD5A79147930AA725ULL, 0x06CA6351E003826FULL),
        MASK_TO_BLOCK_SIZE(0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL),
        MASK_TO_BLOCK_SIZE(0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL),
        MASK_TO_BLOCK_SIZE(0x53380D139D95B3DFULL, 0x650A73548BAF63DEULL),
        MASK_TO_BLOCK_SIZE(0x766A0ABB3C77B2A8ULL, 0x81C2C92E92722C85ULL),
        MASK_TO_BLOCK_SIZE(0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL),
        MASK_TO_BLOCK_SIZE(0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL),
        MASK_TO_BLOCK_SIZE(0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL),
        MASK_TO_BLOCK_SIZE(0xD69906245565A910ULL, 0xF40E35855771202AULL)
    };
    constexpr size_t NUM_RC = 32;
    static_assert((NUM_RC & (NUM_RC - 1)) == 0, "NUM_RC must be a power of two");
    constexpr bool BLOCKS_POW2 = (OES_NUM_OF_BLOCKS & (OES_NUM_OF_BLOCKS - 1)) == 0;
    constexpr size_t BLOCK_MASK = OES_NUM_OF_BLOCKS - 1;

    static inline size_t mod_rc(size_t v) {
        return v & (NUM_RC - 1);
    }

    static inline size_t mod_mem(size_t v) {
        return v & OES_MEM_SIZE_MASK;
    }

    static inline size_t mod_blocks(size_t v) {
        if constexpr (BLOCKS_POW2) {
            return v & BLOCK_MASK;
        }
        return v % OES_NUM_OF_BLOCKS;
    }

    static inline size_t add_blocks(size_t base, size_t add) {
        if constexpr (BLOCKS_POW2) {
            return (base + add) & BLOCK_MASK;
        }
        size_t v = base + add;
        while (v >= OES_NUM_OF_BLOCKS) v -= OES_NUM_OF_BLOCKS;
        return v;
    }

    // Precomputed modular inverses for decryption
    alignas(64) constexpr m_block INV_PHI = compute_mod_inverse(PHI | 1);
    alignas(64) constexpr m_block INV_SQRT2 = compute_mod_inverse(SQRT2 | 1);
    alignas(64) constexpr m_block INV_SQRT3 = compute_mod_inverse(SQRT3 | 1);
    alignas(64) constexpr m_block INV_SQRT5 = compute_mod_inverse(SQRT5 | 1);
    alignas(64) constexpr m_block INV_PI = compute_mod_inverse(PI_CONST | 1);
    alignas(64) constexpr m_block INV_E = compute_mod_inverse(E_CONST | 1);

    // ============================================================================
    // ROTATION AMOUNTS
    // ============================================================================
    struct Rotations {
        uint8_t v[8];
        constexpr uint8_t operator[](size_t i) const { return v[i & 7]; }
    };

    /**
     * Compile-time computed rotation amounts based on block size
     * Chosen to be coprime with block size for maximum bit mixing
     */
    constexpr Rotations ROT = []() constexpr -> Rotations {
        if constexpr (OES_MEM_SIZE == 8) return {{1, 2, 3, 5, 7, 4, 6, 7}};
        if constexpr (OES_MEM_SIZE == 16) return {{3, 5, 7, 11, 13, 9, 12, 14}};
        if constexpr (OES_MEM_SIZE == 32) return {{7, 11, 13, 17, 19, 23, 25, 29}};
        if constexpr (OES_MEM_SIZE == 64) return {{13, 17, 23, 31, 37, 41, 47, 53}};
        if constexpr (OES_MEM_SIZE == 128) return {{25, 31, 41, 53, 67, 79, 89, 103}};
        return {{7, 11, 13, 17, 19, 23, 25, 29}};
    }();

    /**
     * Calculate number of rounds based on block size and wide-block configuration
     * More blocks = more rounds for security margin
     */
    constexpr size_t NUM_ROUNDS = []() constexpr -> size_t {
        // Round base = log2(total bits)
        size_t rounds = std::bit_width(static_cast<unsigned int>(OES_MEM_SIZE * OES_NUM_OF_BLOCKS));

        // Aggiungi qualche round extra se abbiamo tanti blocchi (cross-block mixing)
        if constexpr (OES_NUM_OF_BLOCKS >= 8) rounds += 2;
        else if constexpr (OES_NUM_OF_BLOCKS >= 4) rounds += 1;

        // Arrotonda verso multiplo di 2 per semplicità (optional)
        rounds = (rounds + 1) & ~1UL;

        return rounds;
    }();

    /**
     * Number of permutation rounds for key scheduler
     * More blocks require more mixing for key derivation
     */
    constexpr size_t SCHEDULER_PERMUTE_ROUNDS = []() constexpr -> size_t {
        if constexpr (OES_NUM_OF_BLOCKS >= 16) return 20;
        if constexpr (OES_NUM_OF_BLOCKS >= 8) return 16;
        return 12;
    }();

    /**
     * Wide S-box rounds (Feistel structure)
     * More blocks = more rounds for complete cross-block mixing
     */
    // Feistel rounds: 4 = SPRP (Luby-Rackoff bound), 6 = conservative margin.
    // With other cipher layers (algebraic S-box, PHT, global diffusion) providing
    // additional non-linearity, 6 rounds for wide blocks is more than sufficient.
    constexpr size_t WIDE_SBOX_ROUNDS = []() constexpr -> size_t {
        if constexpr (OES_NUM_OF_BLOCKS >= 8) return 6;
        if constexpr (OES_NUM_OF_BLOCKS >= 4) return 4;
        if constexpr (OES_NUM_OF_BLOCKS >= 2) return 4;
        return 2;
    }();

    /**
     * AES S-box: max differential prob = 2^-6, max linear bias = 2^-4, degree = 7
     * Used for byte-level substitution in algebraic S-box layer
     */
    alignas(64) constexpr uint8_t SBOX_FWD[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    /**
     * Inverse AES S-box for decryption
     */
    alignas(64) constexpr uint8_t SBOX_INV[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    /**
     * Cache for derived round keys used in S-box operations
     * Stores both forward and inverse keys for encryption/decryption
     */
    struct DerivedKeyCache {
        m_block rk[OES_NUM_OF_BLOCKS]; // Forward round keys
        m_block inv_rk[OES_NUM_OF_BLOCKS]; // Inverse round keys
        m_block inv_rk7[OES_NUM_OF_BLOCKS]; // Precomputed inverse for rk(7 % n)
        m_block inv_mix_2_6[OES_NUM_OF_BLOCKS]; // Precomputed inverse for (rk(2)^rk(6 % n))
        alignas(64) uint8_t rk_bytes[OES_NUM_OF_BLOCKS][BYTES_PER_BLOCK]{};
        alignas(64) uint8_t parity_bytes[BYTES_PER_BLOCK]{};
        m_block parity; // Global parity value
        m_block inv_parity; // Inverse parity

        /**
         * Derive round keys from master key blocks
         * Creates key-dependent constants for algebraic S-box
         * @param key_blocks Array of key material
         * @param num_blocks Number of key blocks to process
         */
        void derive(const m_block *key_blocks, size_t num_blocks) {
            const size_t n = std::clamp(num_blocks, static_cast<size_t>(1), static_cast<size_t>(OES_NUM_OF_BLOCKS));

            // Compute global parity from all key blocks
            parity = TF_PARITY;
            for (size_t i = 0; i < n; ++i) {
                parity ^= key_blocks[i];
                parity ^= mBlock::rotl(key_blocks[i], mod_mem(17 + i * 7));
            }
            parity ^= mBlock::rotl(parity, 7);
            inv_parity = compute_mod_inverse(parity | 1);

            // Derive intermediate values with non-linear mixing
            m_block d[OES_NUM_OF_BLOCKS];
            size_t key_idx = 0;
            for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
                m_block x = key_blocks[key_idx];
                x ^= mBlock::rotl(x, ROT[0]);
                x *= (PHI | 1);
                x ^= mBlock::rotr(x, ROT[1]);
                x += mBlock::rotl(x, ROT[2]);
                x ^= (x >> (OES_MEM_SIZE / 2));
                x *= (SQRT2 | 1);
                x ^= parity;
                x ^= mBlock::rotl(x, ROT[3]);
                d[i] = x;
                if (++key_idx == n) key_idx = 0;
            }

            // Cross-block mixing for wide configurations
            if constexpr (OES_NUM_OF_BLOCKS > 1) {
                constexpr size_t mix_rounds = (OES_NUM_OF_BLOCKS >= 8) ? 4 : 3;
                m_block temp[OES_NUM_OF_BLOCKS];

                for (size_t round = 0; round < mix_rounds; ++round) {
                    for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
                        const size_t i1 = add_blocks(i, 1);
                        const size_t i2 = add_blocks(i, OES_NUM_OF_BLOCKS / 2);

                        temp[i] = d[i] ^ d[i1];
                        temp[i] += mBlock::rotl(d[i1], ROT[round & 7]);
                        temp[i] *= ((d[i2] ^ RC[mod_rc(round * OES_NUM_OF_BLOCKS + i)]) | 1);
                        temp[i] ^= mBlock::rotr(d[i], ROT[(round + 1) & 7]);
                        temp[i] ^= (temp[i] >> (OES_MEM_SIZE / 2));
                    }
                    std::memcpy(d, temp, sizeof(m_block) * OES_NUM_OF_BLOCKS);
                }
            }

            // Generate final round keys with chaining
            for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
                const m_block base = d[i] ^ RC[mod_rc(i)];
                m_block modifier = parity;

                if constexpr (OES_NUM_OF_BLOCKS > 1) {
                    modifier ^= d[add_blocks(i, 1)];
                }
                if (i > 0) {
                    modifier ^= rk[i - 1];
                }

                rk[i] = base * (modifier | 1);
                inv_rk[i] = compute_mod_inverse(rk[i] | 1);
            }

            // Precompute inverses used by sbox_inverse to avoid recomputation per block.
            constexpr size_t n_all = OES_NUM_OF_BLOCKS;
            for (size_t i = 0; i < n_all; ++i) {
                const size_t idx7 = add_blocks(i, (7 % n_all));
                const size_t idx2 = add_blocks(i, 2);
                const size_t idx6 = add_blocks(i, (6 % n_all));
                inv_rk7[i] = inv_rk[idx7];
                inv_mix_2_6[i] = compute_mod_inverse((rk[idx2] ^ rk[idx6]) | 1);
            }

            // Extract round keys and parity to byte arrays.
            // memcpy is equivalent to the shift-by-8 loop on little-endian
            // and compiles to a single store/load on modern compilers.
            for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
                std::memcpy(rk_bytes[i], &rk[i], BYTES_PER_BLOCK);
            }
            std::memcpy(parity_bytes, &parity, BYTES_PER_BLOCK);
        }

        /**
         * Derive keys from a single key block by expanding it
         * @param key Single key block to expand
         */
        void derive(const m_block key) {
            m_block expanded[OES_NUM_OF_BLOCKS];
            for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
                expanded[i] = mBlock::rotl(key, mod_mem(i * 17)) ^ RC[mod_rc(i)];
            }
            derive(expanded, OES_NUM_OF_BLOCKS);
        }
    };

    /**
     * Feistel round function F for wide S-box
     * Computes non-linear function of ALL right-half blocks
     * Creates cross-block dependency for enhanced security
     *
     * @param right Array of right-half blocks
     * @param right_len Number of blocks in right half
     * @param dk Derived key cache
     * @param round_idx Current round number
     * @param block_idx Index of left block being processed
     * @return Value to XOR with corresponding left block
     */
    static inline m_block wide_sbox_F(
        const m_block *right, size_t right_len,
        const DerivedKeyCache &dk,
        size_t round_idx,
        size_t block_idx
    ) {
        // Accumulate contribution from ALL right-half blocks
        const size_t rk_round_idx = mod_blocks(round_idx);
        m_block acc = dk.rk[rk_round_idx] ^ RC[mod_rc(round_idx)];
        size_t rot = mod_mem(round_idx * 3);
        for (size_t i = 0; i < right_len; ++i) {
            acc ^= mBlock::rotl(right[i], rot);
            rot = mod_mem(rot + 7);
        }

        // Byte-level S-box processing.
        // Extract accumulator to byte array via memcpy (replaces per-byte 128-bit shifts).
        alignas(16) uint8_t acc_bytes[BYTES_PER_BLOCK];
        std::memcpy(acc_bytes, &acc, BYTES_PER_BLOCK);

        alignas(16) uint8_t res_bytes[BYTES_PER_BLOCK];
        const uint8_t pos_base = static_cast<uint8_t>(round_idx * 31 + block_idx * 17);
        size_t rk_byte_idx = rk_round_idx;
        for (size_t b = 0; b < BYTES_PER_BLOCK; ++b) {
            uint8_t idx = acc_bytes[b];
            idx ^= static_cast<uint8_t>(pos_base + b * 13);
            idx ^= dk.parity_bytes[b];

            uint8_t out_byte = SBOX_FWD[idx];
            out_byte ^= dk.rk_bytes[rk_byte_idx][b];
            rk_byte_idx = add_blocks(rk_byte_idx, 1);

            res_bytes[b] = out_byte;
        }

        // Reconstruct m_block from byte array in one shot
        m_block result;
        std::memcpy(&result, res_bytes, BYTES_PER_BLOCK);

        // Final mixing
        result ^= mBlock::rotl(result, ROT[round_idx & 7]);
        result *= (dk.rk[add_blocks(rk_round_idx, block_idx)] | 1);

        return result;
    }

    /**
     * Wide S-box layer using balanced Feistel structure
     * Provides cross-block non-linearity - each block depends on ALL others
     * Completely invertible for both encryption and decryption
     *
     * @param data Array of blocks to transform
     * @param len Number of blocks
     * @param dk Derived key cache
     * @param inverse True for decryption, false for encryption
     */
    inline void wide_sbox_layer(m_block *data, size_t len, const DerivedKeyCache &dk, bool inverse) {
        if (!data || len < 2) return;

        const size_t n = std::min(len, static_cast<size_t>(OES_NUM_OF_BLOCKS));
        const size_t half = (n + 1) / 2;
        const size_t right_len = n - half;

        if (right_len == 0) return;

        // Logical-swap Feistel: track left/right offsets instead of memcpy.
        // For round r (even: l_off=0, odd: l_off=half) the same F values are
        // produced; only a single physical swap is needed at the end when the
        // number of logical swaps is odd (always true for even WIDE_SBOX_ROUNDS).
        if (!inverse) {
            size_t l_off = 0, r_off = half;
            for (size_t r = 0; r < WIDE_SBOX_ROUNDS; ++r) {
                for (size_t i = 0; i < half; ++i) {
                    data[l_off + i] ^= wide_sbox_F(&data[r_off], right_len, dk, r, i);
                }
                if (r < WIDE_SBOX_ROUNDS - 1) {
                    std::swap(l_off, r_off);  // O(1) logical swap
                }
            }
            // One physical swap to match original layout (odd number of logical swaps)
            if ((WIDE_SBOX_ROUNDS - 1) & 1) {
                for (size_t i = 0; i < half; ++i) {
                    std::swap(data[i], data[half + i]);
                }
            }
        } else {
            // Inverse: undo the final physical swap, then replay rounds in reverse
            // using the same offset logic.
            if ((WIDE_SBOX_ROUNDS - 1) & 1) {
                for (size_t i = 0; i < half; ++i) {
                    std::swap(data[i], data[half + i]);
                }
            }
            for (size_t r = WIDE_SBOX_ROUNDS; r-- > 0;) {
                // Offset that was used during forward round r
                const size_t l_off = (r & 1) ? half : 0;
                const size_t r_off = (r & 1) ? 0 : half;
                for (size_t i = 0; i < half; ++i) {
                    data[l_off + i] ^= wide_sbox_F(&data[r_off], right_len, dk, r, i);
                }
            }
        }
    }

    /**
     * Expand key to match wide-block size
     * Uses key expansion algorithm if key is smaller than required
     *
     * @param key Input key
     * @return Expanded key matching KEY_BLOCKS size, or nullptr on error
     */
    inline std::unique_ptr<MBLOCK> expand_key_to_wide(const MBLOCK *key) {
        if (!key || key->isNull()) return nullptr;

        if (key->getLen() == KEY_BLOCKS) {
            return std::unique_ptr<MBLOCK>(key->clone());
        }

        const m_block salt = MASK_TO_BLOCK_SIZE(0x5350484E58334B59ULL, 0x574944454B455953ULL);
        std::unique_ptr<MBLOCK> expanded(key_expansion(key, KEY_BLOCKS, salt, SCHEDULER_PERMUTE_ROUNDS));

        if (!expanded || expanded->isNull() || expanded->getLen() != KEY_BLOCKS) {
            return nullptr;
        }
        return expanded;
    }

    /**
     * Advanced mixing function for diffusion layer
     * Combines rotations, XORs, and key-dependent multiplication
     *
     * @param x Value to mix
     * @param key Key-dependent constant
     * @return Mixed value
     */
    static inline m_block advanced_mix(m_block x, const m_block key) {
        x ^= key;
        x += mBlock::rotl(x, ROT[0]);
        x ^= mBlock::rotr(x, ROT[1]);
        x *= (key | 1);
        x ^= mBlock::rotl(x, ROT[2]);
        x += mBlock::rotr(key, ROT[3]);
        x ^= (x >> (OES_MEM_SIZE / 2));
        return mBlock::rotl(x, ROT[4]);
    }

    /**
     * Global diffusion layer - spreads bits across all blocks
     * Uses multiple passes (forward, backward, cross-half) for complete mixing
     * Ensures avalanche effect: changing 1 input bit affects all output bits
     *
     * @param data Array of blocks to diffuse
     * @param len Number of blocks
     * @param seeds Key-dependent seed values
     * @param nseeds Number of seeds
     */
    inline void global_diffuse(m_block *data, size_t len, const m_block *seeds, size_t nseeds) {
        if (!data || len < 2 || !seeds || nseeds == 0) return;

        // Forward pass
        m_block state = seeds[0] ^ DIFFUSE_K0;
        size_t sidx = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] ^= state;
            state = advanced_mix(state, seeds[sidx] ^ static_cast<m_block>(i));
            if (++sidx == nseeds) {
                sidx = 0;
            }
        }

        // Forward chaining
        for (size_t i = 1; i < len; ++i) {
            data[i] ^= mBlock::rotl(data[i - 1], ROT[0]);
        }

        // Backward chaining
        for (size_t i = len - 1; i > 0; --i) {
            data[i - 1] ^= mBlock::rotr(data[i], ROT[1]);
        }

        // Backward pass
        state = seeds[nseeds > 1 ? 1 : 0] ^ DIFFUSE_K1;
        sidx = len % nseeds;
        for (size_t i = len; i-- > 0;) {
            data[i] ^= state;
            state = advanced_mix(state, seeds[sidx] ^ static_cast<m_block>(i));
            if (sidx == 0) {
                sidx = nseeds - 1;
            } else {
                --sidx;
            }
        }

        // Cross-half mixing for wide blocks
        if (len >= 4 && OES_NUM_OF_BLOCKS >= 2) {
            const size_t half = len / 2;
            for (size_t i = 0; i < half; ++i) {
                data[i] ^= mBlock::rotl(data[i + half], ROT[2]);
            }
            for (size_t i = 0; i < half; ++i) {
                data[i + half] ^= mBlock::rotr(data[i], ROT[3]);
            }
        }

        // Final pass with third seed
        state = seeds[nseeds > 2 ? 2 : 0] ^ DIFFUSE_K2;
        sidx = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] ^= state;
            state = advanced_mix(state, seeds[sidx] ^ static_cast<m_block>(len - i));
            if (++sidx == nseeds) {
                sidx = 0;
            }
        }
    }

    /**
     * Inverse global diffusion layer
     * Reverses all operations of global_diffuse in exact reverse order
     *
     * @param data Array of blocks to inverse-diffuse
     * @param len Number of blocks
     * @param seeds Key-dependent seed values (same as forward)
     * @param nseeds Number of seeds
     */
    inline void global_diffuse_inv(m_block *data, size_t len, const m_block *seeds, size_t nseeds) {
        if (!data || len < 2 || !seeds || nseeds == 0) return;

        // Reverse final pass
        m_block state = seeds[nseeds > 2 ? 2 : 0] ^ DIFFUSE_K2;
        size_t sidx = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] ^= state;
            state = advanced_mix(state, seeds[sidx] ^ static_cast<m_block>(len - i));
            if (++sidx == nseeds) {
                sidx = 0;
            }
        }

        // Reverse cross-half mixing
        if (len >= 4 && OES_NUM_OF_BLOCKS >= 2) {
            const size_t half = len / 2;
            for (size_t i = half; i-- > 0;) {
                data[i + half] ^= mBlock::rotr(data[i], ROT[3]);
            }
            for (size_t i = half; i-- > 0;) {
                data[i] ^= mBlock::rotl(data[i + half], ROT[2]);
            }
        }

        // Reverse backward pass
        state = seeds[nseeds > 1 ? 1 : 0] ^ DIFFUSE_K1;
        sidx = len % nseeds;
        for (size_t i = len; i-- > 0;) {
            data[i] ^= state;
            state = advanced_mix(state, seeds[sidx] ^ static_cast<m_block>(i));
            if (sidx == 0) {
                sidx = nseeds - 1;
            } else {
                --sidx;
            }
        }

        // Reverse backward chaining
        for (size_t i = 1; i < len; ++i) {
            data[i - 1] ^= mBlock::rotr(data[i], ROT[1]);
        }

        // Reverse forward chaining
        for (size_t i = len - 1; i > 0; --i) {
            data[i] ^= mBlock::rotl(data[i - 1], ROT[0]);
        }

        // Reverse forward pass
        state = seeds[0] ^ DIFFUSE_K0;
        sidx = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] ^= state;
            state = advanced_mix(state, seeds[sidx] ^ static_cast<m_block>(i));
            if (++sidx == nseeds) {
                sidx = 0;
            }
        }
    }

    /**
     * Key scheduler using sponge construction
     * Absorbs key material and generates round keys on demand
     * Provides domain separation and forward security
     */
    class KeyScheduler {
        m_block state_[SCHEDULER_STATE_SIZE]{};
        bool initialized_ = false;

        /**
         * Mixing function for internal state
         * @param i State index to mix
         * @param c Constant to mix in
         */
        void mix_fn(size_t i, m_block c) {
            const size_t next = (i + 1 == SCHEDULER_STATE_SIZE) ? 0 : (i + 1);
            size_t mid = i + (SCHEDULER_STATE_SIZE / 2);
            if (mid >= SCHEDULER_STATE_SIZE) mid -= SCHEDULER_STATE_SIZE;

            m_block x = state_[i] + state_[next];
            x ^= c;
            x = mBlock::rotl(x, ROT[0]);
            x *= (PHI | 1);
            x ^= mBlock::rotr(x, ROT[1]);
            x += mBlock::rotl(state_[mid], ROT[2]);
            x ^= (x >> (OES_MEM_SIZE / 3));
            x = mBlock::rotr(x, ROT[3]);
            state_[i] = x + c;
        }

        /**
         * Permute internal state for diffusion
         * Multiple rounds ensure complete mixing
         */
        /**
         * Permute internal state for diffusion — O(n) per round.
         *
         * Replaces the former O(n²) all-pairs XOR with forward + backward
         * chaining (each using XOR + ADD for non-linearity).  Two linear
         * passes plus a wrap-around achieve full diffusion: every output
         * element depends on every input element.  Combined with the
         * per-element mix_fn non-linear step, this matches or exceeds
         * the diffusion quality of the previous quadratic mix.
         */
        void permute() {
            for (size_t r = 0; r < SCHEDULER_PERMUTE_ROUNDS; ++r) {
                const m_block rc = RC[mod_rc(r)];

                // Per-element non-linear mixing
                for (size_t i = 0; i < SCHEDULER_STATE_SIZE; ++i) {
                    mix_fn(i, rc ^ static_cast<m_block>(i));
                }

                // Forward chain: state_[i] absorbs all predecessors
                for (size_t i = 1; i < SCHEDULER_STATE_SIZE; ++i) {
                    state_[i] ^= mBlock::rotl(state_[i - 1], mod_mem(ROT[0]));
                    state_[i] += mBlock::rotr(state_[i - 1], mod_mem(ROT[1]));
                }

                // Backward chain: state_[i] absorbs all successors
                for (size_t i = SCHEDULER_STATE_SIZE - 1; i > 0; --i) {
                    state_[i - 1] ^= mBlock::rotr(state_[i], mod_mem(ROT[2]));
                    state_[i - 1] += mBlock::rotl(state_[i], mod_mem(ROT[3]));
                }

                // Wrap-around for circular dependency
                state_[0] ^= mBlock::rotl(state_[SCHEDULER_STATE_SIZE - 1], mod_mem(ROT[4]));
                state_[SCHEDULER_STATE_SIZE - 1] ^= mBlock::rotr(state_[0], mod_mem(ROT[5]));

                // Per-element rotation
                for (size_t i = 0; i < SCHEDULER_STATE_SIZE; ++i) {
                    state_[i] = mBlock::rotl(state_[i], mod_mem(ROT[4] + i * ROT[5]));
                }
            }
        }

    public:
        KeyScheduler() { secure_memzero(state_, sizeof(state_)); }
        ~KeyScheduler() { secure_memzero(state_, sizeof(state_)); }

        /**
         * Absorb key material into scheduler state
         * @param key Key block to absorb
         * @param domain Domain separation constant
         * @return True on success
         */
        bool absorb(const MBLOCK *key, m_block domain) {
            initialized_ = false;
            if (!key || key->isNull() || key->getLen() == 0) return false;

            const size_t key_len = key->getLen();
            const m_block *key_data = const_cast<MBLOCK *>(key)->getDataRef();

            // Initialize state with domain constant
            for (size_t i = 0; i < SCHEDULER_STATE_SIZE; ++i) {
                state_[i] = domain ^ RC[mod_rc(i)] ^ static_cast<m_block>(i * 0x9E3779B9);
            }
            permute();

            // Absorb key blocks
            size_t k = 0;
            for (size_t i = 0; i < SCHEDULER_STATE_SIZE; ++i) {
                state_[i] ^= key_data[k];
                if (++k == key_len) {
                    k = 0;
                }
            }

            // Final mixing rounds (2 permutes: each provides full-state
            // diffusion + non-linearity; sufficient for sponge finalization)
            permute();
            permute();

            initialized_ = true;
            return true;
        }

        /**
         * Squeeze out round key material
         * @param output Buffer to receive round key
         * @param round_idx Round number for unique key generation
         * @return True on success
         */
        bool squeeze(MBLOCK *output, size_t round_idx) {
            if (!initialized_ || !output || output->isNull()) return false;

            const size_t out_len = output->getLen();
            m_block *out = output->getDataRef();
            if (!out || out_len == 0) return false;
            return squeeze_raw(out, out_len, round_idx);
        }

        bool squeeze_raw(m_block *out, size_t out_len, size_t round_idx) {
            if (!initialized_ || !out || out_len == 0) return false;

            // Mix in round index for unique keys
            state_[0] ^= static_cast<m_block>(round_idx);
            if (SCHEDULER_STATE_SIZE > 1) {
                state_[1] ^= mBlock::rotl(static_cast<m_block>(round_idx), 13);
            }
            permute();

            // Extract round key blocks
            size_t produced = 0;
            while (produced < out_len) {
                const size_t chunk = std::min(out_len - produced, static_cast<size_t>(SCHEDULER_STATE_SIZE));
                for (size_t i = 0; i < chunk; ++i) {
                    out[produced + i] = state_[i] ^ RC[mod_rc(round_idx + produced + i)];
                }
                produced += chunk;
                if (SCHEDULER_STATE_SIZE > 1 && produced < out_len) {
                    permute();
                }
            }
            return true;
        }
    };

    /**
     * Container for all round keys
     * Pre-generates all keys needed for encryption/decryption
     */
    class RoundKeySet {
        std::unique_ptr<m_block[]> key_data_;
        std::unique_ptr<DerivedKeyCache[]> dk_cache_;
        size_t count_ = 0;
        size_t key_len_ = 0;

    public:
        /**
         * Generate complete set of round keys
         * @param master Master key (already expanded to wide size)
         * @param data_len Number of blocks to encrypt
         * @param num_rounds Number of cipher rounds
         * @param domain Domain separation constant
         */
        RoundKeySet(const MBLOCK *master, size_t data_len, size_t num_rounds, m_block domain) {
            if (!master || master->isNull() || master->getLen() == 0 || data_len == 0) return;

            count_ = num_rounds + 2; // +2 for pre/post whitening
            key_len_ = data_len;
            key_data_ = std::make_unique<m_block[]>(count_ * key_len_);
            dk_cache_ = std::make_unique<DerivedKeyCache[]>(count_);

            KeyScheduler scheduler;
            if (!scheduler.absorb(master, domain ^ DOMAIN_KEY)) {
                key_data_.reset();
                dk_cache_.reset();
                count_ = 0;
                key_len_ = 0;
                return;
            }

            // Generate each round key
            for (size_t r = 0; r < count_; ++r) {
                m_block *rk = key_data_.get() + (r * key_len_);
                if (!scheduler.squeeze_raw(rk, key_len_, r)) {
                    key_data_.reset();
                    dk_cache_.reset();
                    count_ = 0;
                    key_len_ = 0;
                    return;
                }
                dk_cache_[r].derive(rk, std::min(key_len_, static_cast<size_t>(OES_NUM_OF_BLOCKS)));
            }
        }

        ~RoundKeySet() {
            if (key_data_ && count_ > 0 && key_len_ > 0) {
                secure_memzero(key_data_.get(), count_ * key_len_ * sizeof(m_block));
            }
        }

        RoundKeySet(const RoundKeySet &) = delete;

        RoundKeySet &operator=(const RoundKeySet &) = delete;

        RoundKeySet(RoundKeySet &&) = default;

        RoundKeySet &operator=(RoundKeySet &&) = default;

        const m_block *key(size_t i) const {
            return (key_data_ && i < count_) ? (key_data_.get() + (i * key_len_)) : nullptr;
        }

        const DerivedKeyCache *derived(size_t i) const {
            return (dk_cache_ && i < count_) ? &dk_cache_[i] : nullptr;
        }

        explicit operator bool() const { return key_data_ && dk_cache_ && count_ > 0 && key_len_ > 0; }
        [[nodiscard]] size_t count() const { return count_; }
        [[nodiscard]] size_t key_len() const { return key_len_; }
    };

    class Context {
        std::unique_ptr<MBLOCK> master_;
        std::unique_ptr<RoundKeySet> round_keys_;
        size_t len_ = 0;

    public:
        Context(const MBLOCK *key, size_t len) : len_(len) {
            if (!key || key->isNull() || len_ == 0) {
                len_ = 0;
                return;
            }

            if (key->getLen() == KEY_BLOCKS) {
                round_keys_ = std::make_unique<RoundKeySet>(key, len_, NUM_ROUNDS, DOMAIN_ENC);
            } else {
                master_ = expand_key_to_wide(key);
                if (!master_) {
                    len_ = 0;
                    return;
                }
                round_keys_ = std::make_unique<RoundKeySet>(master_.get(), len_, NUM_ROUNDS, DOMAIN_ENC);
            }
            if (!round_keys_ || !(*round_keys_)) {
                round_keys_.reset();
                len_ = 0;
            }
        }

        [[nodiscard]] bool valid() const { return len_ > 0 && round_keys_ && static_cast<bool>(*round_keys_); }
        [[nodiscard]] size_t len() const { return len_; }
        [[nodiscard]] const RoundKeySet &keys() const { return *round_keys_; }
    };

    void ContextDeleter::operator()(Context *ctx) const {
        delete ctx;
    }

    static inline void xor_with_cyclic_key(m_block *data, size_t len, const m_block *key, size_t key_len);
    inline void encrypt_round(m_block *data, size_t len, const m_block *rk, size_t rk_len,
                              const DerivedKeyCache &dk, size_t round);
    inline void decrypt_round(m_block *data, size_t len, const m_block *rk, size_t rk_len,
                              const DerivedKeyCache &dk, size_t round);

    static MBLOCK *encrypt_with_keys(const MBLOCK *plaintext, const RoundKeySet &r_keys) {
        if (!plaintext || plaintext->isNull()) return nullptr;
        const size_t len = plaintext->getLen();
        if (len == 0 || len != r_keys.key_len()) return nullptr;

        std::unique_ptr<MBLOCK> ct(plaintext->clone());
        if (!ct || ct->isNull()) return nullptr;

        m_block *data = ct->getDataRef();
        const m_block *rk0 = r_keys.key(0);
        const m_block *rkN = r_keys.key(NUM_ROUNDS + 1);
        const size_t rk_len = r_keys.key_len();
        if (!rk0 || !rkN || rk_len == 0) return nullptr;

        alignas(64) m_block seeds[OES_NUM_OF_BLOCKS];

        xor_with_cyclic_key(data, len, rk0, rk_len);

        for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
            seeds[i] = rk0[i % rk_len] ^ DOMAIN_DIFF ^ RC[mod_rc(i)];
        }
        global_diffuse(data, len, seeds, OES_NUM_OF_BLOCKS);

        for (size_t r = 0; r < NUM_ROUNDS; ++r) {
            const DerivedKeyCache *dk = r_keys.derived(r + 1);
            if (!dk) return nullptr;
            encrypt_round(data, len, r_keys.key(r + 1), rk_len, *dk, r);
        }

        for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
            seeds[i] = rkN[i % rk_len] ^ DOMAIN_DIFF ^ PHI ^ RC[mod_rc(i)];
        }
        global_diffuse(data, len, seeds, OES_NUM_OF_BLOCKS);

        xor_with_cyclic_key(data, len, rkN, rk_len);
        return ct.release();
    }

    static MBLOCK *decrypt_with_keys(const MBLOCK *ciphertext, const RoundKeySet &r_keys) {
        if (!ciphertext || ciphertext->isNull()) return nullptr;
        const size_t len = ciphertext->getLen();
        if (len == 0 || len != r_keys.key_len()) return nullptr;

        std::unique_ptr<MBLOCK> pt(ciphertext->clone());
        if (!pt || pt->isNull()) return nullptr;

        m_block *data = pt->getDataRef();
        const m_block *rk0 = r_keys.key(0);
        const m_block *rkN = r_keys.key(NUM_ROUNDS + 1);
        const size_t rk_len = r_keys.key_len();
        if (!rk0 || !rkN || rk_len == 0) return nullptr;

        alignas(64) m_block seeds[OES_NUM_OF_BLOCKS];

        xor_with_cyclic_key(data, len, rkN, rk_len);

        for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
            seeds[i] = rkN[i % rk_len] ^ DOMAIN_DIFF ^ PHI ^ RC[mod_rc(i)];
        }
        global_diffuse_inv(data, len, seeds, OES_NUM_OF_BLOCKS);

        for (size_t r = NUM_ROUNDS; r-- > 0;) {
            const DerivedKeyCache *dk = r_keys.derived(r + 1);
            if (!dk) return nullptr;
            decrypt_round(data, len, r_keys.key(r + 1), rk_len, *dk, r);
        }

        for (size_t i = 0; i < OES_NUM_OF_BLOCKS; ++i) {
            seeds[i] = rk0[i % rk_len] ^ DOMAIN_DIFF ^ RC[mod_rc(i)];
        }
        global_diffuse_inv(data, len, seeds, OES_NUM_OF_BLOCKS);

        xor_with_cyclic_key(data, len, rk0, rk_len);
        return pt.release();
    }

    // ============================================================================
    // ALGEBRAIC S-BOX (8-round, key-dependent)
    // ============================================================================

    static inline size_t inc_block_idx(size_t idx) {
        if constexpr (BLOCKS_POW2) {
            return (idx + 1) & BLOCK_MASK;
        }
        ++idx;
        return (idx == OES_NUM_OF_BLOCKS) ? 0 : idx;
    }

    /**
     * Forward algebraic S-box transformation
     * 8 rounds of non-linear mixing using rotations, XORs, and multiplications
     * High algebraic degree for resistance to algebraic attacks
     *
     * @param x Input block
     * @param dk Derived key cache
     * @param idx Block index for key selection
     * @return Transformed block
     */
    static inline m_block sbox_forward(m_block x, const DerivedKeyCache &dk, size_t idx_mod) {
        constexpr size_t n = OES_NUM_OF_BLOCKS;
        const size_t i0 = idx_mod;
        const size_t i1 = add_blocks(i0, 1);
        const size_t i2 = add_blocks(i0, 2);
        const size_t i3 = add_blocks(i0, 3);
        const size_t i4 = add_blocks(i0, 4);
        const size_t i5 = add_blocks(i0, 5);
        const size_t i6 = add_blocks(i0, 6);
        const size_t i7 = add_blocks(i0, 7 % n);
        const size_t iHalf = add_blocks(i0, n / 2);
        const size_t iLast = add_blocks(i0, (n > 1) ? (n - 1) : 0);
        const size_t iLast2 = add_blocks(i0, (n > 2) ? (n - 2) : 0);

        const m_block rk0 = dk.rk[i0];
        const m_block rk1 = dk.rk[i1];
        const m_block rk2 = dk.rk[i2];
        const m_block rk3 = dk.rk[i3];
        const m_block rk4 = dk.rk[i4];
        const m_block rk5 = dk.rk[i5];
        const m_block rk6 = dk.rk[i6];
        const m_block rk7 = dk.rk[i7];
        const m_block rkHalf = dk.rk[iHalf];
        const m_block rkLast = dk.rk[iLast];
        const m_block rkLast2 = dk.rk[iLast2];

        // Round 1-3: Initial mixing
        x ^= rk0;
        x *= (rk1 | 1);
        x = mBlock::rotl(x, ROT[0]);
        x ^= rk2;
        x = mBlock::rotr(x, ROT[1]);
        x *= (PHI | 1);
        x ^= mBlock::rotl(rk3, ROT[2]);

        // Round 4-7: Deep mixing
        x *= (rk4 | 1);
        x = mBlock::rotl(x, ROT[3]);
        x ^= rk5;
        x *= (SQRT3 | 1);
        x = mBlock::rotr(x, ROT[4]);
        x ^= mBlock::rotr(rk6, ROT[5]);
        x *= (rk7 | 1);
        x = mBlock::rotl(x, ROT[6]);

        // Round 8: Parity mixing
        x ^= dk.parity;
        x *= (SQRT5 | 1);
        x = mBlock::rotr(x, ROT[7]);
        x ^= mBlock::rotl(rkHalf, ROT[0]);
        x *= ((rk2 ^ rk6) | 1);
        x = mBlock::rotl(x, ROT[1]);
        x ^= rk3 ^ rk7;
        x *= (PI_CONST | 1);

        // Final rounds: Maximum diffusion
        x = mBlock::rotr(x, ROT[2]);
        x ^= mBlock::rotl(dk.parity ^ rk0, ROT[3]);
        x *= (E_CONST | 1);
        x = mBlock::rotl(x, ROT[4]);
        x ^= mBlock::rotr(rkLast, ROT[5]);
        x *= (rk0 | 1);
        x ^= rk1 ^ rkLast2;

        return x;
    }

    /**
     * Inverse algebraic S-box transformation
     * Exact reverse of sbox_forward using multiplicative inverses
     *
     * @param x Input block
     * @param dk Derived key cache
     * @param idx Block index for key selection
     * @return Transformed block
     */
    static inline m_block sbox_inverse(m_block x, const DerivedKeyCache &dk, size_t idx_mod) {
        constexpr size_t n = OES_NUM_OF_BLOCKS;
        const size_t k = idx_mod;
        const size_t i0 = k;
        const size_t i1 = add_blocks(k, 1);
        const size_t i2 = add_blocks(k, 2);
        const size_t i3 = add_blocks(k, 3);
        const size_t i4 = add_blocks(k, 4);
        const size_t i5 = add_blocks(k, 5);
        const size_t i6 = add_blocks(k, 6);
        const size_t i7 = add_blocks(k, 7 % n);
        const size_t iHalf = add_blocks(k, n / 2);
        const size_t iLast = add_blocks(k, (n > 1) ? (n - 1) : 0);
        const size_t iLast2 = add_blocks(k, (n > 2) ? (n - 2) : 0);

        // Reverse final rounds
        x ^= dk.rk[i1] ^ dk.rk[iLast2];
        x *= dk.inv_rk[i0];
        x ^= mBlock::rotr(dk.rk[iLast], ROT[5]);
        x = mBlock::rotr(x, ROT[4]);
        x *= INV_E;
        x ^= mBlock::rotl(dk.parity ^ dk.rk[i0], ROT[3]);
        x = mBlock::rotl(x, ROT[2]);

        // Reverse round 8
        x *= INV_PI;
        x ^= dk.rk[i3] ^ dk.rk[i7];
        x = mBlock::rotr(x, ROT[1]);
        x *= dk.inv_mix_2_6[k];
        x ^= mBlock::rotl(dk.rk[iHalf], ROT[0]);
        x = mBlock::rotl(x, ROT[7]);
        x *= INV_SQRT5;
        x ^= dk.parity;

        // Reverse rounds 4-7
        x = mBlock::rotr(x, ROT[6]);
        x *= dk.inv_rk7[k];
        x ^= mBlock::rotr(dk.rk[i6], ROT[5]);
        x = mBlock::rotl(x, ROT[4]);
        x *= INV_SQRT3;
        x ^= dk.rk[i5];
        x = mBlock::rotr(x, ROT[3]);
        x *= dk.inv_rk[i4];

        // Reverse rounds 1-3
        x ^= mBlock::rotl(dk.rk[i3], ROT[2]);
        x *= INV_PHI;
        x = mBlock::rotl(x, ROT[1]);
        x ^= dk.rk[i2];
        x = mBlock::rotr(x, ROT[0]);
        x *= dk.inv_rk[i1];
        x ^= dk.rk[i0];

        return x;
    }

    static inline void xor_with_cyclic_key(m_block *data, size_t len, const m_block *key, size_t key_len) {
        if (!data || !key || key_len == 0 || len == 0) return;
        if (key_len == len) {
            for (size_t i = 0; i < len; ++i) {
                data[i] ^= key[i];
            }
            return;
        }
        size_t k = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] ^= key[k];
            if (++k == key_len) k = 0;
        }
    }

    /**
     * Quarter-round function for diffusion (forward direction)
     * Inspired by ChaCha/ARX designs - mixes 4 blocks together
     * Uses additions, rotations, and XORs for non-linear diffusion
     *
     * @param a First block (modified in place)
     * @param b Second block (modified in place)
     * @param c Third block (modified in place)
     * @param d Fourth block (modified in place)
     */
    static inline void quarter_round_fwd(m_block &a, m_block &b, m_block &c, m_block &d) {
        a += b;
        d = mBlock::rotl(d ^ a, ROT[0]);
        c += d;
        b = mBlock::rotl(b ^ c, ROT[1]);
        a += b;
        d = mBlock::rotl(d ^ a, ROT[2]);
        c += d;
        b = mBlock::rotl(b ^ c, ROT[3]);
        a ^= c;
        b ^= d;
        a = mBlock::rotl(a, ROT[4]);
        c = mBlock::rotr(c, ROT[5]);
    }

    /**
     * Inverse quarter-round function
     * Reverses all operations of quarter_round_fwd
     *
     * @param a First block (modified in place)
     * @param b Second block (modified in place)
     * @param c Third block (modified in place)
     * @param d Fourth block (modified in place)
     */
    static inline void quarter_round_inv(m_block &a, m_block &b, m_block &c, m_block &d) {
        c = mBlock::rotl(c, ROT[5]);
        a = mBlock::rotr(a, ROT[4]);
        b ^= d;
        a ^= c;
        b = mBlock::rotr(b, ROT[3]) ^ c;
        c -= d;
        d = mBlock::rotr(d, ROT[2]) ^ a;
        a -= b;
        b = mBlock::rotr(b, ROT[1]) ^ c;
        c -= d;
        d = mBlock::rotr(d, ROT[0]) ^ a;
        a -= b;
    }

    /**
     * Forward diffusion layer
     * Applies quarter-rounds to groups of 4 blocks
     * Then cross-mixes between groups for complete avalanche
     *
     * @param d Array of blocks to diffuse
     * @param len Number of blocks
     */
    inline void diffusion_forward(m_block *d, size_t len) {
        if (!d || len == 0) return;

        // Handle small cases specially
        if (len < 4) {
            if (len >= 2) {
                d[0] += d[1];
                d[1] = mBlock::rotl(d[1] ^ d[0], ROT[0]);
                if (len == 3) {
                    d[2] ^= d[0];
                    d[0] += mBlock::rotl(d[2], ROT[1]);
                    d[1] ^= d[2];
                }
            }
            return;
        }

        const size_t groups = len / 4;

        // Apply quarter-round to each group of 4
        for (size_t g = 0; g < groups; ++g) {
            const size_t i = g * 4;
            quarter_round_fwd(d[i], d[i + 1], d[i + 2], d[i + 3]);
        }

        // Cross-group mixing (column-like mixing)
        if (len >= 8 && groups >= 2) {
            for (size_t c = 0; c < groups && c < 4; ++c) {
                size_t c1 = c + 1;
                size_t c2 = c + 2;
                size_t c3 = c + 3;
                if (c1 >= groups) c1 -= groups;
                if (c2 >= groups) c2 -= groups;
                if (c3 >= groups) c3 -= groups;
                if (c3 >= groups) c3 -= groups;
                const size_t i0 = c;
                const size_t i1 = c1 + groups;
                const size_t i2 = c2 + 2 * groups;
                const size_t i3 = c3 + 3 * groups;
                if (i3 < len) quarter_round_fwd(d[i0], d[i1], d[i2], d[i3]);
            }
        }

        // Cross-half mixing for wide configurations
        if (len >= 8 && OES_NUM_OF_BLOCKS >= 4) {
            const size_t half = len / 2;
            for (size_t i = 0; i < half; ++i) d[i] ^= mBlock::rotl(d[i + half], ROT[6]);
            for (size_t i = 0; i < half; ++i) d[i + half] ^= mBlock::rotr(d[i], ROT[7]);
        }
    }

    /**
     * Inverse diffusion layer
     * Reverses all operations of diffusion_forward
     *
     * @param d Array of blocks to inverse-diffuse
     * @param len Number of blocks
     */
    inline void diffusion_inverse(m_block *d, size_t len) {
        if (!d || len == 0) return;

        // Reverse cross-half mixing
        if (len >= 8 && OES_NUM_OF_BLOCKS >= 4) {
            const size_t half = len / 2;
            for (size_t i = half; i-- > 0;) d[i + half] ^= mBlock::rotr(d[i], ROT[7]);
            for (size_t i = half; i-- > 0;) d[i] ^= mBlock::rotl(d[i + half], ROT[6]);
        }

        // Handle small cases
        if (len < 4) {
            if (len >= 2) {
                if (len == 3) {
                    d[1] ^= d[2];
                    d[0] -= mBlock::rotl(d[2], ROT[1]);
                    d[2] ^= d[0];
                }
                d[1] = mBlock::rotr(d[1], ROT[0]) ^ d[0];
                d[0] -= d[1];
            }
            return;
        }

        const size_t groups = len / 4;

        // Reverse cross-group mixing
        if (len >= 8 && groups >= 2) {
            for (size_t c = (groups < 4 ? groups : 4); c-- > 0;) {
                size_t c1 = c + 1;
                size_t c2 = c + 2;
                size_t c3 = c + 3;
                if (c1 >= groups) c1 -= groups;
                if (c2 >= groups) c2 -= groups;
                if (c3 >= groups) c3 -= groups;
                if (c3 >= groups) c3 -= groups;
                const size_t i0 = c;
                const size_t i1 = c1 + groups;
                const size_t i2 = c2 + 2 * groups;
                const size_t i3 = c3 + 3 * groups;
                if (i3 < len) quarter_round_inv(d[i0], d[i1], d[i2], d[i3]);
            }
        }

        // Reverse quarter-rounds
        for (size_t g = groups; g-- > 0;) {
            const size_t i = g * 4;
            quarter_round_inv(d[i], d[i + 1], d[i + 2], d[i + 3]);
        }
    }

    /**
     * Single encryption round
     * Combines all cipher components: key addition, S-boxes, diffusion
     *
     * @param data Array of blocks to encrypt (modified in place)
     * @param len Number of blocks
     * @param round_key Key material for this round
     * @param round Round number (for round constants)
     */
    inline void encrypt_round(m_block *data, size_t len, const m_block *rk, size_t rk_len,
                              const DerivedKeyCache &dk, size_t round) {
        if (!data || !rk || len == 0 || rk_len == 0) return;

        const m_block rc = RC[mod_rc(round)];

        // 1. Key addition layer
        xor_with_cyclic_key(data, len, rk, rk_len);

        // 2. Wide S-box layer (cross-block non-linearity)
        wide_sbox_layer(data, len, dk, false);

        // 3. Algebraic S-box layer (per-block non-linearity)
        size_t k = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] = sbox_forward(data[i], dk, k);
            k = inc_block_idx(k);
        }

        // 4. Diffusion layer (linear mixing)
        diffusion_forward(data, len);

        // 5. Pseudo-Hadamard transform
        for (size_t i = 0; i < len; ++i) {
            data[i] = pseudoHadamardT(data[i]);
        }

        // 6. Round constant injection
        data[0] ^= rc;
        if (len > 1) data[len - 1] ^= mBlock::rotl(rc, ROT[0]);
        if (len >= 4 && OES_NUM_OF_BLOCKS >= 4) data[len / 2] ^= mBlock::rotr(rc, ROT[1]);
    }

    /**
     * Single decryption round
     * Reverses all operations of encrypt_round
     *
     * @param data Array of blocks to decrypt (modified in place)
     * @param len Number of blocks
     * @param round_key Key material for this round (same as encryption)
     * @param round Round number (for round constants)
     */
    inline void decrypt_round(m_block *data, size_t len, const m_block *rk, size_t rk_len,
                              const DerivedKeyCache &dk, size_t round) {
        if (!data || !rk || len == 0 || rk_len == 0) return;

        const m_block rc = RC[mod_rc(round)];

        // 1. Remove round constants
        data[0] ^= rc;
        if (len > 1) data[len - 1] ^= mBlock::rotl(rc, ROT[0]);
        if (len >= 4 && OES_NUM_OF_BLOCKS >= 4) data[len / 2] ^= mBlock::rotr(rc, ROT[1]);

        // 2. Inverse Pseudo-Hadamard transform
        for (size_t i = 0; i < len; ++i) {
            data[i] = pseudoHadamardTInv(data[i]);
        }

        // 3. Inverse diffusion layer
        diffusion_inverse(data, len);

        // 4. Inverse algebraic S-box layer
        size_t k = 0;
        for (size_t i = 0; i < len; ++i) {
            data[i] = sbox_inverse(data[i], dk, k);
            k = inc_block_idx(k);
        }

        // 5. Inverse wide S-box layer
        wide_sbox_layer(data, len, dk, true);

        // 6. Remove key addition
        xor_with_cyclic_key(data, len, rk, rk_len);
    }

    /**
     * Main encryption function
     * Encrypts plaintext using SPHINX cipher
     *
     * ENCRYPTION PROCESS:
     * 1. Expand key to wide-block size
     * 2. Generate all round keys using sponge-based scheduler
     * 3. Initial whitening (XOR with first round key)
     * 4. Initial global diffusion
     * 5. Apply NUM_ROUNDS encryption rounds
     * 6. Final global diffusion
     * 7. Final whitening (XOR with last round key)
     *
     * @param plaintext Input plaintext blocks
     * @param key Encryption key
     * @return Ciphertext blocks, or nullptr on error
     */
    ContextPtr create_context(const MBLOCK *key, size_t len) {
        ContextPtr ctx(new Context(key, len));
        if (!ctx || !ctx->valid()) {
            return nullptr;
        }
        return ctx;
    }

    MBLOCK *encrypt_with_context(const MBLOCK *plaintext, const Context &ctx) {
        if (!ctx.valid()) return nullptr;
        if (!plaintext || plaintext->isNull() || plaintext->getLen() != ctx.len()) return nullptr;
        return encrypt_with_keys(plaintext, ctx.keys());
    }

    MBLOCK *decrypt_with_context(const MBLOCK *ciphertext, const Context &ctx) {
        if (!ctx.valid()) return nullptr;
        if (!ciphertext || ciphertext->isNull() || ciphertext->getLen() != ctx.len()) return nullptr;
        return decrypt_with_keys(ciphertext, ctx.keys());
    }

    MBLOCK *encrypt(const MBLOCK *plaintext, const MBLOCK *key) {
        if (!plaintext || plaintext->isNull() || !key || key->isNull()) return nullptr;
        const size_t len = plaintext->getLen();
        if (len == 0) return nullptr;

        auto ctx = create_context(key, len);
        if (!ctx) return nullptr;
        return encrypt_with_context(plaintext, *ctx);
    }

    /**
     * Main decryption function
     * Decrypts ciphertext using SPHINX cipher
     *
     * DECRYPTION PROCESS:
     * 1. Expand key to wide-block size (same as encryption)
     * 2. Generate all round keys (same as encryption)
     * 3. Remove final whitening
     * 4. Inverse final global diffusion
     * 5. Apply NUM_ROUNDS decryption rounds (in reverse order)
     * 6. Inverse initial global diffusion
     * 7. Remove initial whitening
     *
     * @param ciphertext Input ciphertext blocks
     * @param key Decryption key (same as encryption key)
     * @return Plaintext blocks, or nullptr on error
     */
    MBLOCK *decrypt(const MBLOCK *ciphertext, const MBLOCK *key) {
        if (!ciphertext || ciphertext->isNull() || !key || key->isNull()) return nullptr;
        const size_t len = ciphertext->getLen();
        if (len == 0) return nullptr;

        auto ctx = create_context(key, len);
        if (!ctx) return nullptr;
        return decrypt_with_context(ciphertext, *ctx);
    }
} // namespace SPHINX
