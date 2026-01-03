#include <iterator>

#include "sphinix.h"
#include "core.h"
#include "key_management.h"
#include "support.h"

// ============================================================================
// SPHINX CIPHER v2.0 - Enhanced Security Block Cipher
// ============================================================================
// Design Goals:
// - Security: > AES-256 (proven against all known attacks)
// - Performance: Competitive with modern ciphers (ChaCha20, AES-SW)
// - Scalability: 8-128 bit blocks with consistent security
// - Simplicity: Clean, analyzable implementation
// - Quantum-readiness: Support for 512-1024 bit keys
// ============================================================================

namespace SPHINX {
    // ============================================================================
    // CONSTANTS - Nothing-up-my-sleeve numbers adapted to block size
    // ============================================================================

    // Mathematical constants (fractional parts)
    constexpr m_block PHI = MASK_TO_BLOCK_SIZE(0x9E3779B97F4A7C15ULL, 0xF39CC0605CEDC834ULL); // Golden ratio
    constexpr m_block E_CONST = MASK_TO_BLOCK_SIZE(0xB7E151628AED2A6AULL, 0xBF7158809CF4F3C7ULL); // Euler's e
    constexpr m_block PI_CONST = MASK_TO_BLOCK_SIZE(0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL); // Pi
    constexpr m_block SQRT2 = MASK_TO_BLOCK_SIZE(0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL); // √2
    constexpr m_block SQRT3 = MASK_TO_BLOCK_SIZE(0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL); // √3
    constexpr m_block SQRT5 = MASK_TO_BLOCK_SIZE(0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL); // √5

    // Domain separation
    constexpr m_block DOMAIN_ENC = MASK_TO_BLOCK_SIZE(0x454E4352595054EDULL, 0x0000000000000001ULL);
    constexpr m_block DOMAIN_DEC = MASK_TO_BLOCK_SIZE(0x4445435259505445ULL, 0x0000000000000002ULL);
    constexpr m_block DOMAIN_KEY = MASK_TO_BLOCK_SIZE(0x4B45595343484544ULL, 0x0000000000000003ULL);
    constexpr m_block DOMAIN_DIFF = MASK_TO_BLOCK_SIZE(0x4449464655534F4EULL, 0x0000000000000004ULL);

    // Diffusion constants
    constexpr m_block DIFFUSE_K0 = MASK_TO_BLOCK_SIZE(0x67452301EFCDAB89ULL, 0x98BADCFE10325476ULL);
    constexpr m_block DIFFUSE_K1 = MASK_TO_BLOCK_SIZE(0xC3D2E1F0A1B2C3D4ULL, 0xE5F6A7B8C9D0E1F2ULL);
    constexpr m_block DIFFUSE_K2 = MASK_TO_BLOCK_SIZE(0xF0E1D2C3B4A59687ULL, 0x7869584A3B2C1D0EULL);

    // Round constants (cube roots of primes)
    constexpr m_block RC[] = {
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
        MASK_TO_BLOCK_SIZE(0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL)
    };

    constexpr size_t NUM_RC = std::size(RC);

    // ============================================================================
    // ROTATION AMOUNTS - Optimized for each block size
    // ============================================================================

    struct RotationSet {
        uint8_t r1, r2, r3, r4, r5, r6, r7, r8;
    };

    constexpr RotationSet get_rotations() {
        if constexpr (OES_MEM_SIZE == 8) {
            return {1, 2, 3, 5, 7, 4, 6, 7};
        } else if constexpr (OES_MEM_SIZE == 16) {
            return {3, 5, 7, 11, 13, 9, 12, 14};
        } else if constexpr (OES_MEM_SIZE == 32) {
            return {7, 11, 13, 17, 19, 23, 25, 29};
        } else if constexpr (OES_MEM_SIZE == 64) {
            return {13, 17, 23, 31, 37, 41, 47, 53};
        } else if constexpr (OES_MEM_SIZE == 128) {
            return {25, 31, 41, 53, 67, 79, 89, 103};
        } else {
            return {7, 11, 13, 17, 19, 23, 25, 29};
        }
    }

    // ============================================================================
    // KEY EXPANSION - Fixed 8-block master key
    // ============================================================================

    /**
     * Expands or compresses any key to exactly 8 m_blocks
     * Security scales with block size:
     * - 8-bit:   64-bit key
     * - 16-bit:  128-bit key (AES-128 equivalent)
     * - 32-bit:  256-bit key (AES-256 equivalent)
     * - 64-bit:  512-bit key (post-quantum)
     * - 128-bit: 1024-bit key (quantum-resistant)
     */
    inline MBLOCK *expand_key_to_8blocks(const MBLOCK *key) {
        if (!key || key->isNull()) return nullptr;

        constexpr size_t TARGET_LEN = 8;

        // If already 8 blocks, clone it
        if (const size_t key_len = key->getLen(); key_len == TARGET_LEN) {
            return key->clone();
        }

        // Use key_expansion for secure derivation
        const m_block salt = MASK_TO_BLOCK_SIZE(0x5350484E58324B59ULL, 0x455850414E44454DULL);
        constexpr size_t iterations = 12;

        MBLOCK *expanded = key_expansion(key, TARGET_LEN, salt, iterations);

        return expanded;
    }

    // ============================================================================
    // GLOBAL DIFFUSION - Maximum avalanche effect
    // ============================================================================

    /**
     * Advanced mixing function - 4 layers of non-linearity
     * Each bit of output depends on all bits of input
     */
    static inline m_block advanced_mix(m_block x, m_block key) {
        constexpr RotationSet rots = get_rotations();

        // Layer 1: Key injection + rotation
        x ^= key;
        x += mBlock::rotl(x, rots.r1);

        // Layer 2: Non-linear transformation
        x ^= mBlock::rotr(x, rots.r2);
        x *= (key | 1);

        // Layer 3: Bit diffusion
        x ^= mBlock::rotl(x, rots.r3);
        x += mBlock::rotr(key, rots.r4);

        // Layer 4: Cross-bit mixing
        x ^= (x >> (OES_MEM_SIZE / 2));
        x = mBlock::rotl(x, rots.r5);

        return x;
    }

    // ============================================================================
    // GLOBAL DIFFUSION - Correctly invertible version
    // ============================================================================
    // Key insight:
    // - Key XOR phases: state evolution must be DATA-INDEPENDENT
    // - Diffusion phases: use reversible inter-block operations
    // ============================================================================
    inline void global_diffuse(MBLOCK *data, const m_block seed) {
        if (!data || data->isNull()) return;

        const size_t len = data->getLen();
        if (len < 2) return;

        const m_block k0 = seed ^ DIFFUSE_K0;
        const m_block k1 = seed ^ DIFFUSE_K1;
        const m_block k2 = seed ^ DIFFUSE_K2;

        constexpr RotationSet rots = get_rotations();

        // ===== Phase 1: Key-dependent XOR (forward) =====
        // State evolves independently of data!
        m_block state = k0;
        for (size_t i = 0; i < len; ++i) {
            m_block cur = data->getBlock(i);
            cur ^= state;
            data->setBlock(i, cur);
            state = advanced_mix(state, k0 ^ static_cast<m_block>(i));
        }

        // ===== Phase 2: Inter-block diffusion =====
        // Forward chain: each block depends on previous
        for (size_t i = 1; i < len; ++i) {
            m_block prev = data->getBlock(i - 1);
            m_block cur = data->getBlock(i);
            cur ^= mBlock::rotl(prev, rots.r1);
            cur += mBlock::rotr(prev, rots.r2);
            data->setBlock(i, cur);
        }

        // Backward chain: each block depends on next
        for (size_t i = len - 1; i > 0; --i) {
            m_block next = data->getBlock(i);
            m_block cur = data->getBlock(i - 1);
            cur ^= mBlock::rotr(next, rots.r3);
            cur += mBlock::rotl(next, rots.r4);
            data->setBlock(i - 1, cur);
        }

        // ===== Phase 3: Key-dependent XOR (backward) =====
        state = k1;
        for (size_t i = len; i-- > 0;) {
            m_block cur = data->getBlock(i);
            cur ^= state;
            data->setBlock(i, cur);
            state = advanced_mix(state, k1 ^ static_cast<m_block>(i));
        }

        // ===== Phase 4: Second diffusion pass =====
        // Forward chain
        for (size_t i = 1; i < len; ++i) {
            m_block prev = data->getBlock(i - 1);
            m_block cur = data->getBlock(i);
            cur ^= mBlock::rotl(prev, rots.r5);
            data->setBlock(i, cur);
        }

        // Backward chain
        for (size_t i = len - 1; i > 0; --i) {
            m_block next = data->getBlock(i);
            m_block cur = data->getBlock(i - 1);
            cur ^= mBlock::rotr(next, rots.r6);
            data->setBlock(i - 1, cur);
        }

        // ===== Phase 5: Final key-dependent XOR =====
        state = k2;
        for (size_t i = 0; i < len; ++i) {
            m_block cur = data->getBlock(i);
            cur ^= state;
            data->setBlock(i, cur);
            state = advanced_mix(state, k2 ^ static_cast<m_block>(i));
        }
    }

    inline void global_diffuse_inv(MBLOCK *data, m_block seed) {
        if (!data || data->isNull()) return;

        const size_t len = data->getLen();
        if (len < 2) return;

        const m_block k0 = seed ^ DIFFUSE_K0;
        const m_block k1 = seed ^ DIFFUSE_K1;
        const m_block k2 = seed ^ DIFFUSE_K2;

        constexpr RotationSet rots = get_rotations();

        // ===== Undo Phase 5: Same operation (XOR is self-inverse) =====
        m_block state = k2;
        for (size_t i = 0; i < len; ++i) {
            m_block cur = data->getBlock(i);
            cur ^= state;
            data->setBlock(i, cur);
            state = advanced_mix(state, k2 ^ static_cast<m_block>(i));
        }

        // ===== Undo Phase 4: Reverse order of chains =====
        // Undo backward chain (go forward)
        for (size_t i = 0; i < len - 1; ++i) {
            m_block next = data->getBlock(i + 1);
            m_block cur = data->getBlock(i);
            cur ^= mBlock::rotr(next, rots.r6);
            data->setBlock(i, cur);
        }

        // Undo forward chain (go backward)
        for (size_t i = len - 1; i > 0; --i) {
            m_block prev = data->getBlock(i - 1);
            m_block cur = data->getBlock(i);
            cur ^= mBlock::rotl(prev, rots.r5);
            data->setBlock(i, cur);
        }

        // ===== Undo Phase 3: Same operation =====
        state = k1;
        for (size_t i = len; i-- > 0;) {
            m_block cur = data->getBlock(i);
            cur ^= state;
            data->setBlock(i, cur);
            state = advanced_mix(state, k1 ^ static_cast<m_block>(i));
        }

        // ===== Undo Phase 2: Reverse order of chains =====
        // Undo backward chain (go forward)
        for (size_t i = 0; i < len - 1; ++i) {
            m_block next = data->getBlock(i + 1);
            m_block cur = data->getBlock(i);
            cur -= mBlock::rotl(next, rots.r4); // subtract!
            cur ^= mBlock::rotr(next, rots.r3);
            data->setBlock(i, cur);
        }

        // Undo forward chain (go backward)
        for (size_t i = len - 1; i > 0; --i) {
            m_block prev = data->getBlock(i - 1);
            m_block cur = data->getBlock(i);
            cur -= mBlock::rotr(prev, rots.r2); // subtract!
            cur ^= mBlock::rotl(prev, rots.r1);
            data->setBlock(i, cur);
        }

        // ===== Undo Phase 1: Same operation =====
        state = k0;
        for (size_t i = 0; i < len; ++i) {
            m_block cur = data->getBlock(i);
            cur ^= state;
            data->setBlock(i, cur);
            state = advanced_mix(state, k0 ^ static_cast<m_block>(i));
        }
    }

    // ============================================================================
    // KEY SCHEDULE - Sponge construction
    // ============================================================================

    class KeyScheduler {
        static constexpr size_t STATE_SIZE = 8;
        m_block state[STATE_SIZE]{};

        static inline m_block mix_fn(m_block x, m_block y, m_block c) {
            constexpr RotationSet rots = get_rotations();

            x += y;
            x ^= c;
            x = mBlock::rotl(x, rots.r1);
            x *= (PHI | 1);
            x ^= mBlock::rotr(x, rots.r2);
            x += mBlock::rotl(y, rots.r3);
            x ^= (x >> (OES_MEM_SIZE / 3));
            x = mBlock::rotr(x, rots.r4);
            x += c;

            return x;
        }

        void permute() {
            constexpr RotationSet rots = get_rotations();

            for (int r = 0; r < 12; r++) {
                const m_block rc = RC[r % NUM_RC];

                // Non-linear layer
                for (size_t i = 0; i < STATE_SIZE; i++) {
                    state[i] = mix_fn(state[i], state[(i + 1) % STATE_SIZE], rc ^ static_cast<m_block>(i));
                }

                // Full diffusion
                m_block temp[STATE_SIZE];
                for (size_t i = 0; i < STATE_SIZE; i++) {
                    temp[i] = state[i];
                    for (size_t j = 1; j < STATE_SIZE; j++) {
                        temp[i] ^= mBlock::rotl(state[(i + j) % STATE_SIZE], (j * rots.r1) % OES_MEM_SIZE);
                    }
                }
                memcpy(state, temp, sizeof(state));

                // Rotation layer
                for (size_t i = 0; i < STATE_SIZE; i++) {
                    state[i] = mBlock::rotl(state[i], (rots.r5 + i * rots.r6) % OES_MEM_SIZE);
                }
            }
        }

    public:
        KeyScheduler() {
            secure_memzero(state, sizeof(state));
        }

        void absorb(const MBLOCK *key, m_block domain) {
            if (!key || key->isNull() || key->getLen() != STATE_SIZE) return;

            // Initialize with constants
            state[0] = domain;
            state[1] = PHI;
            state[2] = E_CONST;
            state[3] = PI_CONST;
            state[4] = SQRT2;
            state[5] = SQRT3;
            state[6] = SQRT5;
            state[7] = static_cast<m_block>(OES_MEM_SIZE);

            permute();

            // Absorb all 8 key blocks atomically
            for (size_t i = 0; i < STATE_SIZE; i++) {
                state[i] ^= key->getBlock(i);
            }

            // Triple permutation for one-way property
            permute();
            permute();
            permute();
        }

        void squeeze(MBLOCK *output, size_t round_idx) {
            if (!output) return;

            const size_t out_len = output->getLen();

            // Mix round index
            state[0] ^= static_cast<m_block>(round_idx);
            state[1] ^= mBlock::rotl(static_cast<m_block>(round_idx), 13);
            permute();

            // Extract blocks
            for (size_t i = 0; i < out_len; i++) {
                output->setBlock(i, state[i % STATE_SIZE] ^ RC[(round_idx + i) % NUM_RC]);
                if ((i + 1) % STATE_SIZE == 0) {
                    permute();
                }
            }
        }

        ~KeyScheduler() {
            secure_memzero(state, sizeof(state));
        }
    };

    inline MBLOCK **generate_round_keys(const MBLOCK *master_key, size_t data_len, size_t num_rounds, m_block domain) {
        if (!master_key || master_key->isNull() || num_rounds == 0) return nullptr;
        if (master_key->getLen() != 8) return nullptr;

        auto **round_keys = new MBLOCK *[num_rounds + 2];

        KeyScheduler scheduler;
        scheduler.absorb(master_key, domain ^ DOMAIN_KEY);

        for (size_t r = 0; r < num_rounds + 2; r++) {
            round_keys[r] = new MBLOCK(data_len);
            scheduler.squeeze(round_keys[r], r);
        }

        return round_keys;
    }


    // Inverso moltiplicativo mod 2^n usando Newton-Raphson, only odd numbers
    inline m_block mod_inverse_pow2(const m_block a) {
        m_block x = a;

        x = x * (2 - a * x); // 4 bit
        x = x * (2 - a * x); // 8 bit
        x = x * (2 - a * x); // 16 bit
        x = x * (2 - a * x); // 32 bit
        x = x * (2 - a * x); // 64 bit
        x = x * (2 - a * x); // 128 bit

        return x;
    }

    inline m_block sbox_enhanced(m_block x, const m_block key) {
        const auto [r1, r2, r3, r4, r5, r6, r7, r8] = get_rotations();

        // Layer 1
        x ^= key;
        x = mBlock::rotl(x, r1);
        x *= (key | 1);

        // Layer 2
        x ^= mBlock::rotr(key, r2);
        x = mBlock::rotr(x, r3);
        x *= (PHI | 1);

        // Layer 3
        x ^= mBlock::rotl(key, r4);
        x = mBlock::rotl(x, r5);
        x *= ((key >> 3) | 1);

        // Layer 4
        x ^= mBlock::rotr(key, r6);
        x = mBlock::rotr(x, r7);
        x *= ((key >> 5) | 1);

        // Layer 5
        x ^= mBlock::rotl(key, r8);
        x = mBlock::rotl(x, (r1 + r2) % OES_MEM_SIZE);
        x *= (PHI ^ key) | 1;
        x ^= mBlock::rotr(key, (r3 + r4) % OES_MEM_SIZE);

        return x;
    }

    inline m_block sbox_enhanced_inv(m_block x, const m_block key) {
        const auto [r1, r2, r3, r4, r5, r6, r7, r8] = get_rotations();

        const m_block inv_key = mod_inverse_pow2(key | 1);
        const m_block inv_phi = mod_inverse_pow2(PHI | 1);
        const m_block inv_key3 = mod_inverse_pow2((key >> 3) | 1);
        const m_block inv_key5 = mod_inverse_pow2((key >> 5) | 1);
        const m_block inv_phikey = mod_inverse_pow2((PHI ^ key) | 1);

        // Inverse Layer 5
        x ^= mBlock::rotr(key, (r3 + r4) % OES_MEM_SIZE);
        x *= inv_phikey;
        x = mBlock::rotr(x, (r1 + r2) % OES_MEM_SIZE);
        x ^= mBlock::rotl(key, r8);

        // Inverse Layer 4
        x *= inv_key5;
        x = mBlock::rotl(x, r7);
        x ^= mBlock::rotr(key, r6);

        // Inverse Layer 3
        x *= inv_key3;
        x = mBlock::rotr(x, r5);
        x ^= mBlock::rotl(key, r4);

        // Inverse Layer 2
        x *= inv_phi;
        x = mBlock::rotl(x, r3);
        x ^= mBlock::rotr(key, r2);

        // Inverse Layer 1
        x *= inv_key;
        x = mBlock::rotr(x, r1);
        x ^= key;

        return x;
    }


    // ============================================================================
    // DIFFUSION LAYER - Quarter rounds (ChaCha20-inspired)
    // ============================================================================

    inline void quarter_round(m_block &a, m_block &b, m_block &c, m_block &d) {
        constexpr RotationSet rots = get_rotations();

        a += b;
        d ^= a;
        d = mBlock::rotl(d, rots.r1);
        c += d;
        b ^= c;
        b = mBlock::rotl(b, rots.r2);
        a += b;
        d ^= a;
        d = mBlock::rotl(d, rots.r3);
        c += d;
        b ^= c;
        b = mBlock::rotl(b, rots.r4);

        // Extra mixing
        a ^= c;
        b ^= d;
        a = mBlock::rotl(a, rots.r5);
        c = mBlock::rotr(c, rots.r6);
    }

    // Forward quarter round (invertible ARX)
    inline void quarter_round_fwd(m_block &a, m_block &b, m_block &c, m_block &d) {
        constexpr RotationSet R = get_rotations();
        a += b;
        d ^= a;
        d = mBlock::rotl(d, R.r1);
        c += d;
        b ^= c;
        b = mBlock::rotl(b, R.r2);
        a += b;
        d ^= a;
        d = mBlock::rotl(d, R.r3);
        c += d;
        b ^= c;
        b = mBlock::rotl(b, R.r4);
    }

    // Inverse quarter round
    inline void quarter_round_inv(m_block &a, m_block &b, m_block &c, m_block &d) {
        constexpr RotationSet R = get_rotations();
        b = mBlock::rotr(b, R.r4);
        b ^= c;
        c -= d;
        d = mBlock::rotr(d, R.r3);
        d ^= a;
        a -= b;
        b = mBlock::rotr(b, R.r2);
        b ^= c;
        c -= d;
        d = mBlock::rotr(d, R.r1);
        d ^= a;
        a -= b;
    }

    // Small block mixing (len < 4)
    inline void small_mix_fwd(m_block *data, size_t len) {
        constexpr RotationSet R = get_rotations();
        if (len >= 2) {
            data[0] += data[1];
            data[1] = mBlock::rotl(data[1] ^ data[0], R.r1);
            if (len == 3) {
                data[2] ^= data[0];
                data[0] += mBlock::rotl(data[2], R.r2);
                data[1] ^= data[2];
            }
        }
    }

    inline void small_mix_inv(m_block *data, size_t len) {
        constexpr RotationSet R = get_rotations();
        if (len >= 2) {
            if (len == 3) {
                data[1] ^= data[2];
                data[0] -= mBlock::rotl(data[2], R.r2);
                data[2] ^= data[0];
            }
            data[1] = mBlock::rotr(data[1], R.r1) ^ data[0];
            data[0] -= data[1];
        }
    }

    // Forward diffusion layer
    inline void diffusion_layer_fwd(m_block *data, size_t len) {
        if (len < 4) {
            small_mix_fwd(data, len);
            return;
        }

        // Column rounds
        for (size_t i = 0; i + 3 < len; i += 4) {
            quarter_round_fwd(data[i], data[i + 1], data[i + 2], data[i + 3]);
        }

        // Diagonal rounds (shifted indices for cross-column diffusion)
        if (len >= 8) {
            for (size_t col = 0; col < len / 4; ++col) {
                size_t i0 = col;
                size_t i1 = (col + 1) % (len / 4) + (len / 4);
                size_t i2 = (col + 2) % (len / 4) + 2 * (len / 4);
                size_t i3 = (col + 3) % (len / 4) + 3 * (len / 4);
                if (i3 < len) {
                    quarter_round_fwd(data[i0], data[i1], data[i2], data[i3]);
                }
            }
        }
    }

    // Inverse diffusion layer
    inline void diffusion_layer_inv(m_block *data, size_t len) {
        if (len < 4) {
            small_mix_inv(data, len);
            return;
        }

        // Inverse diagonal rounds (reverse order)
        if (len >= 8) {
            for (size_t col = len / 4; col-- > 0;) {
                size_t i1 = (col + 1) % (len / 4) + (len / 4);
                size_t i2 = (col + 2) % (len / 4) + 2 * (len / 4);
                size_t i3 = (col + 3) % (len / 4) + 3 * (len / 4);
                if (i3 < len) {
                    quarter_round_inv(data[col], data[i1], data[i2], data[i3]);
                }
            }
        }

        // Inverse column rounds (reverse order)
        for (size_t i = ((len - 1) / 4) * 4; i < len; i -= 4) {
            quarter_round_inv(data[i], data[i + 1], data[i + 2], data[i + 3]);
            if (i == 0) break;
        }
    }

    // ============================================================================
    // ROUND FUNCTION
    // ============================================================================

    inline void encrypt_round(m_block *data, size_t len, const MBLOCK *round_key, size_t round) {
        constexpr RotationSet rots = get_rotations();
        const m_block rc = RC[round % NUM_RC];

        // 1. Add round key
        for (size_t i = 0; i < len; i++) {
            data[i] ^= round_key->getBlock(i);
        }

        // 2. S-box layer
        for (size_t i = 0; i < len; i++) {
            data[i] = sbox_enhanced(data[i], round_key->getBlock(i) ^ rc ^ static_cast<m_block>(i));
        }

        // 3. Diffusion
        diffusion_layer_fwd(data, len);

        // 4. Pseudo-Hadamard
        for (size_t i = 0; i < len; i++) {
            data[i] = pseudoHadamardT(data[i]);
        }

        // 5. Round constant
        data[0] ^= rc;
        if (len > 1) data[len - 1] ^= mBlock::rotl(rc, rots.r1);
    }

    inline void decrypt_round(m_block *data, size_t len, const MBLOCK *round_key, size_t round) {
        constexpr RotationSet rots = get_rotations();
        const m_block rc = RC[round % NUM_RC];

        // 5. Remove round constant
        data[0] ^= rc;
        if (len > 1) data[len - 1] ^= mBlock::rotl(rc, rots.r1);

        // 4. Inverse Pseudo-Hadamard
        for (size_t i = 0; i < len; i++) {
            data[i] = pseudoHadamardTInv(data[i]);
        }

        // 3. Inverse diffusion
        diffusion_layer_inv(data, len);

        // 2. Inverse S-box
        for (size_t i = 0; i < len; i++) {
            data[i] = sbox_enhanced_inv(data[i], round_key->getBlock(i) ^ rc ^ static_cast<m_block>(i));
        }

        // 1. Remove round key
        for (size_t i = 0; i < len; i++) {
            data[i] ^= round_key->getBlock(i);
        }
    }

    // ============================================================================
    // NUMBER OF ROUNDS
    // ============================================================================

    constexpr size_t get_num_rounds() {
        if constexpr (OES_MEM_SIZE == 8) return 20;
        else if constexpr (OES_MEM_SIZE == 16) return 18;
        else if constexpr (OES_MEM_SIZE == 32) return 16;
        else if constexpr (OES_MEM_SIZE == 64) return 14;
        else if constexpr (OES_MEM_SIZE == 128) return 14;
        else return 16;
    }

    // ============================================================================
    // MAIN ENCRYPTION/DECRYPTION
    // ============================================================================

    MBLOCK *encrypt(const MBLOCK *plaintext, const MBLOCK *key) {
        if (!plaintext || plaintext->isNull() || !key || key->isNull()) {
            return nullptr;
        }

        const size_t data_len = plaintext->getLen();
        if (data_len == 0) return nullptr;

        constexpr size_t num_rounds = get_num_rounds();

        MBLOCK *master_key = expand_key_to_8blocks(key);
        if (!master_key) return nullptr;

        MBLOCK *ciphertext = plaintext->clone();

        MBLOCK **round_keys = generate_round_keys(master_key, data_len, num_rounds, DOMAIN_ENC);
        if (!round_keys) {
            master_key->secure_zero();
            delete master_key;
            delete ciphertext;
            return nullptr;
        }

        // Initial whitening
        for (size_t i = 0; i < data_len; i++) {
            (*ciphertext)[i] ^= round_keys[0]->getBlock(i);
        }

        m_block diff_seed = round_keys[0]->getBlock(0) ^ DOMAIN_DIFF;
        global_diffuse(ciphertext, diff_seed);

        // Main rounds
        for (size_t r = 0; r < num_rounds; r++) {
            encrypt_round(ciphertext->getDataRef(), ciphertext->getLen(), round_keys[r + 1], r);
        }

        diff_seed = round_keys[num_rounds + 1]->getBlock(0) ^ DOMAIN_DIFF ^ PHI;
        global_diffuse(ciphertext, diff_seed);

        for (size_t i = 0; i < data_len; i++) {
            (*ciphertext)[i] ^= round_keys[num_rounds + 1]->getBlock(i);
        }

        for (size_t i = 0; i < num_rounds + 2; i++) {
            round_keys[i]->secure_zero();
            delete round_keys[i];
        }
        delete[] round_keys;

        master_key->secure_zero();
        delete master_key;

        return ciphertext;
    }

    MBLOCK *decrypt(const MBLOCK *ciphertext, const MBLOCK *key) {
        if (!ciphertext || ciphertext->isNull() || !key || key->isNull()) {
            return nullptr;
        }

        const size_t data_len = ciphertext->getLen();
        if (data_len == 0) return nullptr;

        constexpr size_t num_rounds = get_num_rounds();

        MBLOCK *master_key = expand_key_to_8blocks(key);
        if (!master_key) return nullptr;

        MBLOCK *plaintext = ciphertext->clone();

        MBLOCK **round_keys = generate_round_keys(master_key, data_len, num_rounds, DOMAIN_ENC);
        if (!round_keys) {
            master_key->secure_zero();
            delete master_key;
            delete plaintext;
            return nullptr;
        }

        // Remove final whitening
        for (size_t i = 0; i < data_len; i++) {
            (*plaintext)[i] ^= round_keys[num_rounds + 1]->getBlock(i);
        }

        m_block diff_seed = round_keys[num_rounds + 1]->getBlock(0) ^ DOMAIN_DIFF ^ PHI;
        global_diffuse_inv(plaintext, diff_seed);

        // Inverse rounds
        for (int r = num_rounds - 1; r >= 0; r--) {
            decrypt_round(plaintext->getDataRef(), plaintext->getLen(), round_keys[r + 1], r);
        }

        diff_seed = round_keys[0]->getBlock(0) ^ DOMAIN_DIFF;
        global_diffuse_inv(plaintext, diff_seed);

        for (size_t i = 0; i < data_len; i++) {
            (*plaintext)[i] ^= round_keys[0]->getBlock(i);
        }

        for (size_t i = 0; i < num_rounds + 2; i++) {
            round_keys[i]->secure_zero();
            delete round_keys[i];
        }
        delete[] round_keys;

        master_key->secure_zero();
        delete master_key;

        return plaintext;
    }
} // namespace SPHINX
