#include <iomanip>
#include <iostream>
#include <cmath>
#include <vector>
#include <array>
#include <bitset>
#include <numeric>
#include <algorithm>
#include <cstdint>
#include <ctime>

#include "prng.h"

#include <functional>
#include <map>
#include <set>

#include "raw-layer.h"

namespace prng {
    // Secure clear
    void PRNG::clear() {
        for (int i = 0; i < 16; i++) {
            state[i] = 0;
            col_idx[i] = 0;
            diag_idx[i] = 0;
        }
        counter = 0;
        accumulator = 0;
    }

    // Private methods
    inline m_block PRNG::apply_sbox(const m_block x) {
        if constexpr (OES_MEM_SIZE == 8) {
            return static_cast<m_block>(SBOX256[static_cast<uint8_t>(x)]);
        } else if constexpr (OES_MEM_SIZE == 16) {
            return static_cast<m_block>(SBOX256[x & 0xFF])
                   | (static_cast<m_block>(SBOX256[(x >> 8) & 0xFF]) << 8);
        } else if constexpr (OES_MEM_SIZE == 32) {
            return static_cast<m_block>(SBOX256[x & 0xFF])
                   | (static_cast<m_block>(SBOX256[(x >> 8) & 0xFF]) << 8)
                   | (static_cast<m_block>(SBOX256[(x >> 16) & 0xFF]) << 16)
                   | (static_cast<m_block>(SBOX256[(x >> 24) & 0xFF]) << 24);
        } else if constexpr (OES_MEM_SIZE == 64) {
            return static_cast<m_block>(SBOX256[x & 0xFF])
                   | (static_cast<m_block>(SBOX256[(x >> 8) & 0xFF]) << 8)
                   | (static_cast<m_block>(SBOX256[(x >> 16) & 0xFF]) << 16)
                   | (static_cast<m_block>(SBOX256[(x >> 24) & 0xFF]) << 24)
                   | (static_cast<m_block>(SBOX256[(x >> 32) & 0xFF]) << 32)
                   | (static_cast<m_block>(SBOX256[(x >> 40) & 0xFF]) << 40)
                   | (static_cast<m_block>(SBOX256[(x >> 48) & 0xFF]) << 48)
                   | (static_cast<m_block>(SBOX256[(x >> 56) & 0xFF]) << 56);
        } else if constexpr (OES_MEM_SIZE == 128) {
            m_block result = 0;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x)]);
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 8)]) << 8;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 16)]) << 16;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 24)]) << 24;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 32)]) << 32;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 40)]) << 40;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 48)]) << 48;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 56)]) << 56;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 64)]) << 64;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 72)]) << 72;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 80)]) << 80;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 88)]) << 88;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 96)]) << 96;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 104)]) << 104;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 112)]) << 112;
            result |= static_cast<m_block>(SBOX256[static_cast<uint8_t>(x >> 120)]) << 120;
            return result;
        }
    }

    inline void PRNG::quarter_round(m_block &a, m_block &b, m_block &c, m_block &d) {
        a += b;
        d ^= a;
        d = mBlock::rotl(d, ROT1);
        c += d;
        b ^= c;
        b = mBlock::rotl(b, ROT2);
        a += b;
        d ^= a;
        d = mBlock::rotl(d, ROT3);
        c += d;
        b ^= c;
        b = mBlock::rotl(b, ROT4);

        // Extra diffusione per blocchi >= 32 bit
        if constexpr (OES_MEM_SIZE >= 32) {
            a ^= mBlock::rotl(c, R1);
            b ^= mBlock::rotl(d, R2);
        }
    }

    // Public methods
    void PRNG::init(const m_block seed) {
        counter = 0;
        accumulator = 0;

        // Inizializzazione indici (invariata ma con mixing migliore)
#pragma unroll
        for (int i = 0; i < 16; i++) {
            m_block s = seed * PRNG_MULT1;
            s ^= s >> S1;
            s += s >> ((i * 4) % OES_MEM_SIZE);
            col_idx[i] = SBOX16[(i + s) & 15];
            diag_idx[i] = SBOX16[(i + s + 5) & 15];
        }

        // Numero passate scalato per dimensione blocco
        constexpr int passes = (OES_MEM_SIZE <= 16) ? 4 : (OES_MEM_SIZE <= 32) ? 6 : 8;

        // seed hash
        m_block h = seed;
        h ^= h >> S1;
        h *= PRNG_MULT1;
        h ^= h >> S2;
        h *= PRNG_MULT2;
        h ^= h >> S3;
        h = h * LCG_MULT + LCG_INC;

        m_block s = seed;

#pragma unroll
        for (int pass = 0; pass < passes; pass++) {
#pragma unroll
            for (int i = 0; i < 16; i++) {
                // Mixing del seed
                s += static_cast<m_block>(i + pass);
                s *= PRNG_MULT1;
                s ^= s >> S1;
                s *= PRNG_MULT2;
                s ^= s >> S2;
                s = s * LCG_MULT + LCG_INC;

                // Aggiornamento state
                state[i] = apply_sbox(s ^ h);
                state[i] *= DIFFUSE_CONST;
                state[i] ^= state[i] >> S1;

                // Diffusione cross-state (aumentata per 32/64 bit)
                state[(i + 1) & 15] ^= mBlock::rotl(state[i], ROT1);
                state[(i + 7) & 15] ^= mBlock::rotl(state[i], ROT2);

                if constexpr (OES_MEM_SIZE >= 32) {
                    state[(i + 11) & 15] ^= mBlock::rotl(state[i], ROT3);
                    state[(i + 13) & 15] ^= mBlock::rotl(state[i], R3);
                }

                // Quarter round ogni 4 elementi
                if ((i & 3) == 3) {
                    quarter_round(state[i - 3], state[i - 2], state[i - 1], state[i]);
                }
            }

            // Column mixing per blocchi >= 32 bit (stile ChaCha)
            if constexpr (OES_MEM_SIZE >= 32) {
                for (int col = 0; col < 4; col++) {
                    quarter_round(state[col], state[col + 4], state[col + 8], state[col + 12]);
                }
                // Diagonal mixing
                quarter_round(state[0], state[5], state[10], state[15]);
                quarter_round(state[1], state[6], state[11], state[12]);
                quarter_round(state[2], state[7], state[8], state[13]);
                quarter_round(state[3], state[4], state[9], state[14]);
            }
        }
    }

    m_block PRNG::next() {
        m_block ctr = (counter++) * PRNG_MULT1;
        ctr ^= ctr >> (OES_MEM_SIZE / 2);

        // ========== 32/64-bit: ARX con doppio stato ==========
        // Costanti ottimizzate per dimensione
        constexpr int ROUNDS = (OES_MEM_SIZE <= 16) ? 6 : (OES_MEM_SIZE <= 32) ? 8 : 10;

        // Inizializzazione da counter e state
        m_block x = ctr ^ state[ctr & 15] ^ accumulator;
        m_block y = state[(ctr + 7) & 15];
        y ^= y >> S1;
        y *= PRNG_MULT1;
        y ^= ctr;

#pragma unroll
        for (int r = 0; r < ROUNDS; r++) {
#pragma unroll
            for (int s = 0; s < 4; s++) {
                x ^= mBlock::rotl(state[(ctr + r + s) & 15], ROT1 + s);
                y ^= mBlock::rotl(state[(r + s + 5) & 15], ctr + s);
            }

            // Mixing moltiplicativo
            x *= PRNG_MULT1;
            x ^= x >> S1;

            // Rotazioni per diffusione completa
            x = mBlock::rotl(x, ROT3);
            y = mBlock::rotl(y, R2);

            // Cross-mixing (cruciale per avalanche)
            x ^= mBlock::rotl(y, (r + 1) & (OES_MEM_SIZE - 1));
            y ^= mBlock::rotl(x, (r + 3) & (OES_MEM_SIZE - 1));
            x += y;
            y ^= mBlock::rotl(x, ROT3);

            // Iniezione addizionale ogni 4 round
            if ((r & 3) == 3) {
                x ^= state[(ctr + r) & 15];
                y *= PRNG_MULT2;
                y ^= y >> S2;
            }
        }


        // === Final non-bijective whitening ===
        m_block result = x ^ y;
        result ^= result >> S1;
        result *= PRNG_MULT1;
        result ^= result >> S2;
        result *= PRNG_MULT2;
        result ^= result >> S3;

        // Accumulator assorbe il feedback gradualmente
        accumulator ^= mBlock::rotl(result, ROT1);
        accumulator *= PRNG_MULT1;
        accumulator ^= accumulator >> S1;

        // State update meno frequente
        if ((ctr & 3) == 0) {
            state[(ctr >> 2) & 15] ^= accumulator;
        }

        return result;
    }
}


// ============================================================
// PRNG CRYPTOGRAPHIC TEST SUITE
// Adaptive for OES_MEM_SIZE: 8, 16, 32, 64, 128 bits
// ============================================================

namespace prng_tests {
    template<typename T>
    using Vec = std::vector<T, std::allocator<T> >;

    // ========================================================
    // CONFIGURAZIONE ADATTIVA
    // ========================================================

    constexpr bool FULL_PERIOD_POSSIBLE = (OES_MEM_SIZE <= 32);

    constexpr uint64_t get_samples() {
        if constexpr (OES_MEM_SIZE == 8) return 1ULL << 8;
        if constexpr (OES_MEM_SIZE == 16) return 1ULL << 16;
        if constexpr (OES_MEM_SIZE == 32) return 1ULL << 28;
        if constexpr (OES_MEM_SIZE == 64) return 1ULL << 28;
        if constexpr (OES_MEM_SIZE == 128) return 1ULL << 28;
        return 1ULL << 26;
    }

    constexpr uint64_t SAMPLES = get_samples();

    constexpr uint64_t get_fast_samples() {
        if constexpr (OES_MEM_SIZE <= 16) return SAMPLES;
        if constexpr (OES_MEM_SIZE == 32) return 1ULL << 26;
        return 1ULL << 25;
    }

    constexpr uint64_t FAST_SAMPLES = get_fast_samples();

    constexpr int get_bucket_bits() {
        if constexpr (OES_MEM_SIZE == 8) return 8;
        if constexpr (OES_MEM_SIZE == 16) return 16;
        if constexpr (OES_MEM_SIZE == 32) return 20;
        if constexpr (OES_MEM_SIZE == 64) return 24;
        if constexpr (OES_MEM_SIZE == 128) return 24;
        return 16;
    }

    constexpr int BUCKET_BITS = get_bucket_bits();
    constexpr uint64_t BUCKETS = 1ULL << BUCKET_BITS;
    constexpr uint64_t BUCKET_MASK = BUCKETS - 1;

    // Helper functions
    inline uint64_t to_u64(const m_block &val) {
        if constexpr (OES_MEM_SIZE <= 64) {
            return static_cast<uint64_t>(val);
        } else {
            return static_cast<uint64_t>(val & static_cast<m_block>(UINT64_MAX));
        }
    }

    inline uint64_t to_u64_high(const m_block &val) {
        if constexpr (OES_MEM_SIZE <= 64) {
            return static_cast<uint64_t>(val >> (OES_MEM_SIZE / 2));
        } else {
            return static_cast<uint64_t>(val >> 64);
        }
    }

    inline int popcount_mblock(const m_block &val) {
        if constexpr (OES_MEM_SIZE <= 64) {
            return __builtin_popcountll(static_cast<uint64_t>(val));
        } else {
            return __builtin_popcountll(to_u64(val)) + __builtin_popcountll(to_u64_high(val));
        }
    }

    inline bool get_bit(const m_block &val, int bit_pos) {
        if constexpr (OES_MEM_SIZE <= 64) {
            return ((val >> bit_pos) & static_cast<m_block>(1)) != 0;
        } else {
            if (bit_pos < 64) {
                return ((to_u64(val) >> bit_pos) & 1ULL) != 0;
            } else {
                return ((to_u64_high(val) >> (bit_pos - 64)) & 1ULL) != 0;
            }
        }
    }

    inline m_block make_seed(int t) {
        if constexpr (OES_MEM_SIZE <= 64) {
            return static_cast<m_block>(static_cast<uint64_t>(t) * 2654435761ULL);
        } else {
            uint64_t lo = static_cast<uint64_t>(t) * 2654435761ULL;
            uint64_t hi = static_cast<uint64_t>(t) * 0x9E3779B97F4A7C15ULL;
            return (static_cast<m_block>(hi) << 64) | static_cast<m_block>(lo);
        }
    }

    inline m_block make_seed_alt(int t) {
        if constexpr (OES_MEM_SIZE <= 64) {
            return static_cast<m_block>(static_cast<uint64_t>(t) * 0x9E3779B97F4A7C15ULL);
        } else {
            uint64_t lo = static_cast<uint64_t>(t) * 0x9E3779B97F4A7C15ULL;
            uint64_t hi = static_cast<uint64_t>(t) * 2654435761ULL;
            return (static_cast<m_block>(hi) << 64) | static_cast<m_block>(lo);
        }
    }

    void show_progress(uint64_t current, uint64_t total, clock_t start) {
        if (total < (1ULL << 20)) return;
        constexpr int BAR_WIDTH = 30;
        const double pct = static_cast<double>(current) / static_cast<double>(total);
        const int filled = static_cast<int>(pct * BAR_WIDTH);
        double elapsed = static_cast<double>(clock() - start) / CLOCKS_PER_SEC;
        double eta = (pct > 0.001) ? ((elapsed / pct) - elapsed) : 0.0;
        std::cout << "\r  [";
        for (int i = 0; i < BAR_WIDTH; ++i) std::cout << (i < filled ? '=' : ' ');
        std::cout << "] " << std::fixed << std::setprecision(1)
                << (pct * 100) << "% ETA: " << eta << "s   " << std::flush;
    }

    void clear_progress() {
        std::cout << "\r" << std::string(60, ' ') << "\r" << std::flush;
    }

    // Chi-square critical values (alpha = 0.01)
    double chi_sq_critical(int df) {
        if (df > 100) {
            double z = 2.326;
            return df * std::pow(1.0 - 2.0 / (9.0 * df) + z * std::sqrt(2.0 / (9.0 * df)), 3);
        }
        static const double table[] = {
            6.635, 9.210, 11.345, 13.277, 15.086, 16.812, 18.475, 20.090,
            21.666, 23.209, 24.725, 26.217, 27.688, 29.141, 30.578, 32.000
        };
        if (df <= 16) return table[df - 1];
        return df + 2.326 * std::sqrt(2.0 * df);
    }

    // ========================================================
    // TEST 1: SERIAL CORRELATION (Multi-dimensional)
    // ========================================================
    bool test_serial_correlation() {
        std::cout << "\n==== TEST 1: SERIAL CORRELATION (Multi-dimensional) ====\n";

        constexpr uint64_t TEST_SAMPLES = (OES_MEM_SIZE <= 16) ? SAMPLES : (1ULL << 25);

        constexpr int GRID_BITS_2D = (OES_MEM_SIZE <= 16) ? (OES_MEM_SIZE / 2) : 10;
        constexpr uint64_t GRID_2D = 1ULL << GRID_BITS_2D;
        constexpr uint64_t GRID_MASK_2D = GRID_2D - 1;

        constexpr int GRID_BITS_3D = (OES_MEM_SIZE <= 16) ? (OES_MEM_SIZE / 3) : 7;
        constexpr uint64_t GRID_3D = 1ULL << GRID_BITS_3D;
        constexpr uint64_t GRID_MASK_3D = GRID_3D - 1;

        Vec<uint64_t> grid_2d(static_cast<size_t>(GRID_2D * GRID_2D), 0ULL);
        Vec<uint64_t> grid_3d(static_cast<size_t>(GRID_3D * GRID_3D * GRID_3D), 0ULL);

        constexpr int MAX_LAG = 16;
        Vec<double> lag_correlations(MAX_LAG, 0.0);
        Vec<uint64_t> lag_counts(MAX_LAG, 0ULL);

        auto p = prng::PRNG(static_cast<m_block>(0x12345678ULL));
        clock_t start = clock();

        Vec<m_block> recent(MAX_LAG);
        for (int i = 0; i < MAX_LAG; ++i) recent[i] = p.next();

        m_block prev = recent[MAX_LAG - 1];
        m_block prev2 = recent[MAX_LAG - 2];

        for (uint64_t i = 0; i < TEST_SAMPLES; ++i) {
            const m_block curr = p.next();

            const uint64_t x = to_u64(prev) & GRID_MASK_2D;
            const uint64_t y = to_u64(curr) & GRID_MASK_2D;
            ++grid_2d[static_cast<size_t>(y * GRID_2D + x)];

            const uint64_t z = to_u64(prev2) & GRID_MASK_3D;
            const uint64_t x3 = to_u64(prev) & GRID_MASK_3D;
            const uint64_t y3 = to_u64(curr) & GRID_MASK_3D;
            ++grid_3d[static_cast<size_t>(z * GRID_3D * GRID_3D + y3 * GRID_3D + x3)];

            for (int lag = 1; lag < MAX_LAG && i >= static_cast<uint64_t>(lag); ++lag) {
                int bits_same = 0;
                m_block xor_val = curr ^ recent[(MAX_LAG - 1 - lag + static_cast<int>(i % MAX_LAG)) % MAX_LAG];
                bits_same = OES_MEM_SIZE - popcount_mblock(xor_val);
                lag_correlations[lag] += static_cast<double>(bits_same) / OES_MEM_SIZE;
                ++lag_counts[lag];
            }

            recent[static_cast<size_t>(i % MAX_LAG)] = curr;
            prev2 = prev;
            prev = curr;

            if ((i & 0xFFFFFULL) == 0) show_progress(i, TEST_SAMPLES, start);
        }
        clear_progress();

        const double expected_2d = static_cast<double>(TEST_SAMPLES) / static_cast<double>(GRID_2D * GRID_2D);
        double chi_sq_2d = 0.0;
        for (uint64_t i = 0; i < GRID_2D * GRID_2D; ++i) {
            const double obs = static_cast<double>(grid_2d[static_cast<size_t>(i)]);
            const double diff = obs - expected_2d;
            chi_sq_2d += (diff * diff) / expected_2d;
        }
        const double chi_sq_2d_norm = chi_sq_2d / static_cast<double>(GRID_2D * GRID_2D - 1);

        const double expected_3d = static_cast<double>(TEST_SAMPLES) / static_cast<double>(GRID_3D * GRID_3D * GRID_3D);
        double chi_sq_3d = 0.0;
        uint64_t non_zero_3d = 0;
        for (uint64_t i = 0; i < GRID_3D * GRID_3D * GRID_3D; ++i) {
            const double obs = static_cast<double>(grid_3d[static_cast<size_t>(i)]);
            const double diff = obs - expected_3d;
            if (expected_3d > 0.1) chi_sq_3d += (diff * diff) / expected_3d;
            if (grid_3d[static_cast<size_t>(i)] > 0) ++non_zero_3d;
        }
        const double chi_sq_3d_norm = chi_sq_3d / static_cast<double>(GRID_3D * GRID_3D * GRID_3D - 1);

        double max_lag_deviation = 0.0;
        int worst_lag = 0;
        for (int lag = 1; lag < MAX_LAG; ++lag) {
            if (lag_counts[lag] > 0) {
                lag_correlations[lag] /= static_cast<double>(lag_counts[lag]);
                double deviation = std::abs(lag_correlations[lag] - 0.5);
                if (deviation > max_lag_deviation) {
                    max_lag_deviation = deviation;
                    worst_lag = lag;
                }
            }
        }

        std::cout << "Samples         : " << TEST_SAMPLES << "\n";
        std::cout << "\n-- 2D Serial Test --\n";
        std::cout << "Grid size       : " << GRID_2D << "x" << GRID_2D << "\n";
        std::cout << "Expected/cell   : " << std::fixed << std::setprecision(2) << expected_2d << "\n";
        std::cout << "Chi-sq norm     : " << std::setprecision(4) << chi_sq_2d_norm << "\n";

        std::cout << "\n-- 3D Serial Test --\n";
        std::cout << "Grid size       : " << GRID_3D << "^3 = " << (GRID_3D * GRID_3D * GRID_3D) << "\n";
        std::cout << "Expected/cell   : " << std::setprecision(2) << expected_3d << "\n";
        std::cout << "Coverage        : " << std::setprecision(1)
                << (100.0 * non_zero_3d / (GRID_3D * GRID_3D * GRID_3D)) << "%\n";
        std::cout << "Chi-sq norm     : " << std::setprecision(4) << chi_sq_3d_norm << "\n";

        std::cout << "\n-- Lag Correlation --\n";
        std::cout << "Max deviation   : " << std::setprecision(4) << max_lag_deviation
                << " at lag " << worst_lag << "\n";
        std::cout << "Lag 1-4 corr    : ";
        for (int i = 1; i <= 4; ++i) {
            std::cout << std::setprecision(4) << lag_correlations[i] << " ";
        }
        std::cout << "(expected 0.5)\n";

        bool pass_2d = (chi_sq_2d_norm > 0.8 && chi_sq_2d_norm < 1.2);
        bool pass_3d = (chi_sq_3d_norm > 0.7 && chi_sq_3d_norm < 1.3);
        bool pass_lag = (max_lag_deviation < 0.01);

        bool pass = pass_2d && pass_3d && pass_lag;
        std::cout << "\nResult: 2D=" << (pass_2d ? "OK" : "FAIL")
                << " 3D=" << (pass_3d ? "OK" : "FAIL")
                << " Lag=" << (pass_lag ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 9: LINEAR COMPLEXITY (Enhanced)
    // ========================================================
    bool test_linear_complexity() {
        std::cout << "\n==== TEST 9: LINEAR COMPLEXITY (Enhanced) ====\n";

        const int SEQ_LEN = (OES_MEM_SIZE <= 32) ? 2048 : 4096;
        constexpr int NUM_TRIALS = 20;

        const double n = static_cast<double>(SEQ_LEN);
        const double expected_L = n / 2.0 + (4.0 + (SEQ_LEN % 2 == 0 ? -1.0 : 1.0)) / 9.0;
        const double variance = (86.0 * n) / 81.0 - (SEQ_LEN % 2 == 0 ? 1.0 / 9.0 : -1.0 / 9.0);
        const double stddev = std::sqrt(variance);

        auto berlekamp_massey = [](const Vec<int> &seq) -> int {
            int n = static_cast<int>(seq.size());
            Vec<int> C(n, 0), B(n, 0);
            C[0] = B[0] = 1;
            int L = 0, m = 1;

            for (int idx = 0; idx < n; ++idx) {
                int d = seq[idx];
                for (int i = 1; i <= L; ++i) {
                    d ^= C[i] & seq[idx - i];
                }
                if (d == 1) {
                    Vec<int> T = C;
                    for (int i = 0; i + m < n; ++i) {
                        C[i + m] ^= B[i];
                    }
                    if (2 * L <= idx) {
                        L = idx + 1 - L;
                        B = T;
                        m = 1;
                    } else {
                        ++m;
                    }
                } else {
                    ++m;
                }
            }
            return L;
        };

        std::cout << "Sequence length : " << SEQ_LEN << "\n";
        std::cout << "Trials          : " << NUM_TRIALS << "\n";
        std::cout << "Expected L      : " << std::setprecision(1) << expected_L
                << " ± " << stddev << " (1σ)\n\n";

        Vec<int> full_output_L(NUM_TRIALS);
        for (int trial = 0; trial < NUM_TRIALS; ++trial) {
            auto p = prng::PRNG(make_seed(trial * 77777));
            Vec<int> seq(SEQ_LEN);

            int bit_idx = 0;
            m_block curr = p.next();
            for (int i = 0; i < SEQ_LEN; ++i) {
                seq[i] = get_bit(curr, bit_idx) ? 1 : 0;
                if (++bit_idx >= OES_MEM_SIZE) {
                    bit_idx = 0;
                    curr = p.next();
                }
            }
            full_output_L[trial] = berlekamp_massey(seq);
        }

        double full_mean = 0.0;
        int full_min = SEQ_LEN, full_max = 0;
        for (int L: full_output_L) {
            full_mean += L;
            full_min = std::min(full_min, L);
            full_max = std::max(full_max, L);
        }
        full_mean /= NUM_TRIALS;
        double full_z = (full_mean - expected_L) / stddev;

        std::cout << "-- Full Output Stream --\n";
        std::cout << "Mean L          : " << std::setprecision(1) << full_mean
                << " [" << full_min << "-" << full_max << "]\n";
        std::cout << "Z-score         : " << std::setprecision(3) << full_z << "\n";

        auto p_bits = prng::PRNG(static_cast<m_block>(0x55AA55AAULL));
        Vec<m_block> outputs(SEQ_LEN);
        for (int i = 0; i < SEQ_LEN; ++i) {
            outputs[i] = p_bits.next();
        }

        Vec<int> bit_L(OES_MEM_SIZE);
        int weak_bits = 0;

        for (int bit = 0; bit < OES_MEM_SIZE; ++bit) {
            Vec<int> seq(SEQ_LEN);
            for (int i = 0; i < SEQ_LEN; ++i) {
                seq[i] = get_bit(outputs[i], bit) ? 1 : 0;
            }
            bit_L[bit] = berlekamp_massey(seq);
            if ((static_cast<double>(bit_L[bit]) - expected_L) / stddev < -3.0) {
                ++weak_bits;
            }
        }

        double bit_mean = std::accumulate(bit_L.begin(), bit_L.end(), 0.0) / OES_MEM_SIZE;
        int bit_min = *std::min_element(bit_L.begin(), bit_L.end());
        int bit_max = *std::max_element(bit_L.begin(), bit_L.end());
        double bit_z = (bit_mean - expected_L) / stddev;

        std::cout << "\n-- Per-Bit Analysis --\n";
        std::cout << "Mean L          : " << std::setprecision(1) << bit_mean
                << " [" << bit_min << "-" << bit_max << "]\n";
        std::cout << "Z-score         : " << std::setprecision(3) << bit_z << "\n";
        std::cout << "Weak bits (<-3σ): " << weak_bits << "/" << OES_MEM_SIZE << "\n";

        Vec<int> jump_seq(SEQ_LEN);
        auto p_jump = prng::PRNG(make_seed(12345));
        for (int i = 0; i < SEQ_LEN; ++i) {
            jump_seq[i] = get_bit(p_jump.next(), 0) ? 1 : 0;
        }

        bool complexity_grows = true;
        int prev_L = 0;
        for (int len = 64; len <= SEQ_LEN; len *= 2) {
            Vec<int> partial(jump_seq.begin(), jump_seq.begin() + len);
            int L = berlekamp_massey(partial);
            if (L < prev_L * 0.4 && prev_L > 0) {
                complexity_grows = false;
            }
            prev_L = L;
        }

        std::cout << "\n-- Complexity Growth --\n";
        std::cout << "Monotonic growth: " << (complexity_grows ? "YES" : "NO") << "\n";

        bool full_pass = std::abs(full_z) < 3.0 && full_min > SEQ_LEN / 4;
        bool bit_pass = weak_bits <= OES_MEM_SIZE / 4;
        bool growth_pass = complexity_grows;

        bool pass = full_pass && bit_pass && growth_pass;
        std::cout << "\nResult: full=" << (full_pass ? "OK" : "FAIL")
                << " bits=" << (bit_pass ? "OK" : "FAIL")
                << " growth=" << (growth_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 10: SAC & BIC (Bit Independence)
    // ========================================================
    bool test_sac() {
        std::cout << "\n==== TEST 10: SAC & BIC (Bit Independence) ====\n";

        constexpr int TRIALS = (OES_MEM_SIZE <= 16) ? 50000 : (OES_MEM_SIZE <= 32) ? 30000 : 20000;
        constexpr int WARMUP = (OES_MEM_SIZE <= 16) ? 3 : 1;

        Vec<Vec<uint64_t> > sac_matrix(OES_MEM_SIZE, Vec<uint64_t>(OES_MEM_SIZE, 0));

        Vec<Vec<Vec<uint64_t> > > bic_matrix(OES_MEM_SIZE);
        for (int i = 0; i < OES_MEM_SIZE; ++i) {
            bic_matrix[i].resize(OES_MEM_SIZE);
            for (int j = 0; j < OES_MEM_SIZE; ++j) {
                bic_matrix[i][j].resize(OES_MEM_SIZE, 0);
            }
        }

        clock_t start = clock();

        for (int t = 0; t < TRIALS; ++t) {
            const m_block base_seed = make_seed_alt(t);

            auto p_base = prng::PRNG(base_seed);

            for (int w = 1; w < WARMUP; ++w) p_base.next();
            m_block base_out = p_base.next();

            for (int in_bit = 0; in_bit < OES_MEM_SIZE; ++in_bit) {
                const m_block flipped_seed = base_seed ^ (static_cast<m_block>(1) << in_bit);

                auto p_flip = prng::PRNG(flipped_seed);
                m_block flip_out = p_flip.next();
                for (int w = 1; w < WARMUP; ++w) flip_out = p_flip.next();

                const m_block diff = base_out ^ flip_out;

                for (int out_bit = 0; out_bit < OES_MEM_SIZE; ++out_bit) {
                    if (get_bit(diff, out_bit)) {
                        ++sac_matrix[in_bit][out_bit];
                    }
                }

                for (int i = 0; i < OES_MEM_SIZE; ++i) {
                    if (get_bit(diff, i)) {
                        for (int j = i + 1; j < OES_MEM_SIZE; ++j) {
                            if (get_bit(diff, j)) {
                                ++bic_matrix[in_bit][i][j];
                            }
                        }
                    }
                }
            }

            if ((t & 0x3FF) == 0) show_progress(t, TRIALS, start);
        }
        clear_progress();

        const double expected_sac = static_cast<double>(TRIALS) * 0.5;
        const double sac_sigma = std::sqrt(static_cast<double>(TRIALS) * 0.25);

        const double expected_bic = static_cast<double>(TRIALS) * 0.25;
        const double bic_sigma = std::sqrt(static_cast<double>(TRIALS) * 0.25 * 0.75);

        double sac_max_dev = 0.0;
        double sac_sum_dev = 0.0;
        int sac_bad_cells = 0;

        for (int i = 0; i < OES_MEM_SIZE; ++i) {
            for (int j = 0; j < OES_MEM_SIZE; ++j) {
                auto obs = static_cast<double>(sac_matrix[i][j]);
                double dev = std::abs(obs - expected_sac) / expected_sac;
                sac_max_dev = std::max(sac_max_dev, dev);
                sac_sum_dev += dev;
                if (std::abs(obs - expected_sac) > 3.0 * sac_sigma) ++sac_bad_cells;
            }
        }
        double sac_avg_dev = sac_sum_dev / (OES_MEM_SIZE * OES_MEM_SIZE);

        double bic_max_dev = 0.0;
        double bic_sum_dev = 0.0;
        int bic_bad_cells = 0;
        int bic_total_cells = 0;

        for (int in_bit = 0; in_bit < OES_MEM_SIZE; ++in_bit) {
            for (int i = 0; i < OES_MEM_SIZE; ++i) {
                for (int j = i + 1; j < OES_MEM_SIZE; ++j) {
                    auto obs = static_cast<double>(bic_matrix[in_bit][i][j]);
                    double dev = std::abs(obs - expected_bic) / expected_bic;
                    bic_max_dev = std::max(bic_max_dev, dev);
                    bic_sum_dev += dev;
                    if (std::abs(obs - expected_bic) > 3.0 * bic_sigma) ++bic_bad_cells;
                    ++bic_total_cells;
                }
            }
        }
        double bic_avg_dev = (bic_total_cells > 0) ? bic_sum_dev / bic_total_cells : 0.0;

        int sac_total_cells = OES_MEM_SIZE * OES_MEM_SIZE;
        double expected_sac_bad = sac_total_cells * 0.0027;
        double expected_bic_bad = bic_total_cells * 0.0027;

        std::cout << "Trials          : " << TRIALS << "\n";
        std::cout << "Warmup rounds   : " << WARMUP << "\n\n";

        std::cout << "-- SAC Analysis --\n";
        std::cout << "Matrix size     : " << OES_MEM_SIZE << "x" << OES_MEM_SIZE << "\n";
        std::cout << "Max deviation   : " << std::setprecision(2) << (sac_max_dev * 100) << "%\n";
        std::cout << "Avg deviation   : " << std::setprecision(2) << (sac_avg_dev * 100) << "%\n";
        std::cout << ">3σ cells       : " << sac_bad_cells << "/" << sac_total_cells
                << " (expected ~" << std::setprecision(1) << expected_sac_bad << ")\n";

        std::cout << "\n-- BIC Analysis (Bit Independence) --\n";
        std::cout << "Tested pairs    : " << bic_total_cells << "\n";
        std::cout << "Max deviation   : " << std::setprecision(2) << (bic_max_dev * 100) << "%\n";
        std::cout << "Avg deviation   : " << std::setprecision(2) << (bic_avg_dev * 100) << "%\n";
        std::cout << ">3σ cells       : " << bic_bad_cells << "/" << bic_total_cells
                << " (expected ~" << std::setprecision(1) << expected_bic_bad << ")\n";

        bool crypto_sac = (sac_max_dev < 0.05) && (sac_avg_dev < 0.02);
        bool crypto_bic = (bic_max_dev < 0.10) && (bic_avg_dev < 0.04);

        double sac_max_tol = (OES_MEM_SIZE <= 16) ? 0.15 : 0.10;
        double sac_avg_tol = (OES_MEM_SIZE <= 16) ? 0.06 : 0.04;
        double bic_max_tol = (OES_MEM_SIZE <= 16) ? 0.20 : 0.15;
        double bic_avg_tol = (OES_MEM_SIZE <= 16) ? 0.08 : 0.06;

        bool sac_pass = (sac_max_dev < sac_max_tol) && (sac_avg_dev < sac_avg_tol);
        bool bic_pass = (bic_max_dev < bic_max_tol) && (bic_avg_dev < bic_avg_tol);

        bool pass = sac_pass && bic_pass;

        std::cout << "\n-- Verdict --\n";
        std::cout << "Quality tier    : ";
        if (crypto_sac && crypto_bic) {
            std::cout << "CRYPTOGRAPHIC\n";
        } else if (sac_pass && bic_pass) {
            std::cout << "GOOD\n";
        } else {
            std::cout << "POOR\n";
        }

        std::cout << "Result: SAC=" << (sac_pass ? "OK" : "FAIL")
                << " BIC=" << (bic_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 11: MAURER'S UNIVERSAL TEST
    // ========================================================
    bool test_maurer_universal() {
        std::cout << "\n==== TEST 11: MAURER'S UNIVERSAL TEST ====\n";

        constexpr int L = 8;
        constexpr uint64_t Q = 10 * (1ULL << L);
        constexpr uint64_t K = (OES_MEM_SIZE <= 16) ? (SAMPLES * OES_MEM_SIZE / L) : (1ULL << 24);

        auto p = prng::PRNG(static_cast<m_block>(0x77889900ULL));

        Vec<uint64_t> T(1ULL << L, 0);

        auto get_block = [](const m_block &val, int block_idx, int block_size) -> uint64_t {
            int bit_start = block_idx * block_size;
            uint64_t mask = (1ULL << block_size) - 1;
            if constexpr (OES_MEM_SIZE <= 64) {
                return (static_cast<uint64_t>(val) >> bit_start) & mask;
            } else {
                if (bit_start < 64) {
                    return (to_u64(val) >> bit_start) & mask;
                } else {
                    return (to_u64_high(val) >> (bit_start - 64)) & mask;
                }
            }
        };

        constexpr int BLOCKS_PER_OUTPUT = OES_MEM_SIZE / L;

        uint64_t block_counter = 0;
        while (block_counter < Q) {
            m_block val = p.next();
            for (int b = 0; b < BLOCKS_PER_OUTPUT && block_counter < Q; ++b) {
                uint64_t block = get_block(val, b, L);
                T[block] = block_counter;
                ++block_counter;
            }
        }

        double sum = 0.0;
        uint64_t test_blocks = 0;
        clock_t start = clock();

        while (test_blocks < K) {
            m_block val = p.next();
            for (int b = 0; b < BLOCKS_PER_OUTPUT && test_blocks < K; ++b) {
                uint64_t block = get_block(val, b, L);
                uint64_t current_pos = Q + test_blocks;

                if (T[block] > 0 || block == 0) {
                    uint64_t distance = current_pos - T[block];
                    sum += std::log2(static_cast<double>(distance));
                }

                T[block] = current_pos;
                ++test_blocks;
            }

            if ((test_blocks & 0xFFFFFULL) == 0) {
                show_progress(test_blocks, K, start);
            }
        }
        clear_progress();

        double fn = sum / static_cast<double>(K);

        constexpr double expected_fn = 7.1836656;
        constexpr double variance_c = 3.238;
        double variance = variance_c * (std::pow(0.7 - 0.8 / L + (1.6 + 12.8 / L) / K, 2) +
                                        std::pow(std::sqrt(variance_c / K), 2));
        double stddev = std::sqrt(variance);

        double z_score = (fn - expected_fn) / stddev;

        std::cout << "Block size L    : " << L << " bits\n";
        std::cout << "Init blocks Q   : " << Q << "\n";
        std::cout << "Test blocks K   : " << K << "\n";
        std::cout << "Computed fn     : " << std::setprecision(6) << fn << "\n";
        std::cout << "Expected fn     : " << std::setprecision(6) << expected_fn << "\n";
        std::cout << "Std deviation   : " << std::setprecision(6) << stddev << "\n";
        std::cout << "Z-score         : " << std::setprecision(3) << z_score << "\n";

        bool pass = std::abs(z_score) < 3.0;
        std::cout << "Result          : " << (pass ? "[PASS]\n" : "[FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 12: SPECTRAL TEST (DFT)
    // ========================================================
    bool test_spectral() {
        std::cout << "\n==== TEST 12: SPECTRAL TEST (DFT) ====\n";

        constexpr uint64_t N = (OES_MEM_SIZE <= 16) ? SAMPLES : (1ULL << 18);

        auto p = prng::PRNG(static_cast<m_block>(0xABCDEF01ULL));

        Vec<double> bits(static_cast<size_t>(N));
        uint64_t collected = 0;

        while (collected < N) {
            m_block val = p.next();
            for (int b = 0; b < OES_MEM_SIZE && collected < N; ++b) {
                bits[collected++] = get_bit(val, b) ? 1.0 : -1.0;
            }
        }

        constexpr int NUM_FREQS = 100;
        Vec<double> magnitudes(NUM_FREQS);

        std::cout << "Samples         : " << N << "\n";
        std::cout << "Computing DFT for " << NUM_FREQS << " frequencies...\n";

        clock_t start = clock();

        for (int k = 1; k <= NUM_FREQS; ++k) {
            double real_sum = 0.0, imag_sum = 0.0;
            double freq = 2.0 * M_PI * k / static_cast<double>(N);

            for (uint64_t n = 0; n < N; ++n) {
                real_sum += bits[n] * std::cos(freq * n);
                imag_sum += bits[n] * std::sin(freq * n);
            }

            magnitudes[k - 1] = std::sqrt(real_sum * real_sum + imag_sum * imag_sum);

            if ((k % 10) == 0) show_progress(k, NUM_FREQS, start);
        }
        clear_progress();

        double expected_mag = std::sqrt(static_cast<double>(N));
        double threshold = expected_mag * 3.0;

        double max_mag = 0.0;
        int max_freq = 0;
        int peaks_above_threshold = 0;

        for (int k = 0; k < NUM_FREQS; ++k) {
            if (magnitudes[k] > max_mag) {
                max_mag = magnitudes[k];
                max_freq = k + 1;
            }
            if (magnitudes[k] > threshold) {
                ++peaks_above_threshold;
            }
        }

        double mag_ratio = max_mag / expected_mag;

        std::cout << "Expected mag    : " << std::setprecision(2) << expected_mag << "\n";
        std::cout << "Max magnitude   : " << std::setprecision(2) << max_mag
                << " at freq " << max_freq << "\n";
        std::cout << "Max/Expected    : " << std::setprecision(3) << mag_ratio << "x\n";
        std::cout << "Peaks > 3x      : " << peaks_above_threshold << "/" << NUM_FREQS << "\n";

        bool pass = (mag_ratio < 4.0) && (peaks_above_threshold <= 2);
        std::cout << "Result          : " << (pass ? "[PASS]\n" : "[FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 13: COMPRESSION TEST
    // ========================================================
    bool test_compression() {
        std::cout << "\n==== TEST 13: COMPRESSION TEST ====\n";

        constexpr uint64_t TEST_BYTES = (OES_MEM_SIZE <= 16)
                                            ? (SAMPLES * OES_MEM_SIZE / 8)
                                            : (1ULL << 22);

        auto p = prng::PRNG(static_cast<m_block>(0x13579BDFULL));

        Vec<uint8_t> data;
        data.reserve(TEST_BYTES);
        constexpr int BYTES_PER_BLOCK = OES_MEM_SIZE / 8;

        while (data.size() < TEST_BYTES) {
            m_block val = p.next();
            for (int b = 0; b < BYTES_PER_BLOCK && data.size() < TEST_BYTES; ++b) {
                uint8_t byte_val;
                if constexpr (OES_MEM_SIZE <= 64) {
                    byte_val = static_cast<uint8_t>((val >> (b * 8)) & 0xFFULL);
                } else {
                    if (b < 8) {
                        byte_val = static_cast<uint8_t>((to_u64(val) >> (b * 8)) & 0xFFULL);
                    } else {
                        byte_val = static_cast<uint8_t>((to_u64_high(val) >> ((b - 8) * 8)) & 0xFFULL);
                    }
                }
                data.push_back(byte_val);
            }
        }

        uint64_t total_matches = 0;
        uint64_t total_match_length = 0;
        constexpr int WINDOW_SIZE = 256;
        constexpr int MIN_MATCH = 3;

        for (size_t i = WINDOW_SIZE; i < data.size() - MIN_MATCH; ++i) {
            int best_match_len = 0;

            for (size_t j = i - WINDOW_SIZE; j < i; ++j) {
                int match_len = 0;
                while (match_len < 16 && i + match_len < data.size() &&
                       data[j + match_len] == data[i + match_len]) {
                    ++match_len;
                }
                if (match_len >= MIN_MATCH && match_len > best_match_len) {
                    best_match_len = match_len;
                }
            }

            if (best_match_len >= MIN_MATCH) {
                ++total_matches;
                total_match_length += best_match_len;
            }
        }

        uint64_t rle_runs = 0;
        uint64_t rle_total_len = 0;
        uint8_t prev = data[0];
        int run_len = 1;

        for (size_t i = 1; i < data.size(); ++i) {
            if (data[i] == prev) {
                ++run_len;
            } else {
                if (run_len >= 3) {
                    ++rle_runs;
                    rle_total_len += run_len;
                }
                run_len = 1;
                prev = data[i];
            }
        }

        double match_ratio = static_cast<double>(total_matches) / static_cast<double>(data.size() - WINDOW_SIZE);
        double avg_match_len = (total_matches > 0)
                                   ? static_cast<double>(total_match_length) / total_matches
                                   : 0.0;
        double rle_ratio = static_cast<double>(rle_runs) / static_cast<double>(data.size());

        double expected_match_ratio = 1.0 / 256.0;

        std::cout << "Bytes tested    : " << data.size() << "\n\n";
        std::cout << "-- LZ77-style Analysis --\n";
        std::cout << "Matches found   : " << total_matches << "\n";
        std::cout << "Match ratio     : " << std::setprecision(4) << (match_ratio * 100) << "%\n";
        std::cout << "Avg match len   : " << std::setprecision(2) << avg_match_len << "\n";
        std::cout << "Expected ratio  : ~" << std::setprecision(2) << (expected_match_ratio * 100) << "%\n";

        std::cout << "\n-- RLE Analysis --\n";
        std::cout << "Runs >= 3       : " << rle_runs << "\n";
        std::cout << "RLE ratio       : " << std::setprecision(4) << (rle_ratio * 100) << "%\n";

        bool lz_pass = (match_ratio < expected_match_ratio * 3.0);
        bool rle_pass = (rle_ratio < 0.005);

        bool pass = lz_pass && rle_pass;
        std::cout << "\nResult: LZ=" << (lz_pass ? "OK" : "FAIL")
                << " RLE=" << (rle_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 14: SEED SENSITIVITY TEST
    // ========================================================
    bool test_seed_sensitivity() {
        std::cout << "\n==== TEST 14: SEED SENSITIVITY ====\n";

        constexpr int TRIALS = 10000;
        constexpr int OUTPUTS_PER_SEED = 10;

        Vec<int> hamming_distances;
        hamming_distances.reserve(TRIALS * OUTPUTS_PER_SEED);

        for (int t = 0; t < TRIALS; ++t) {
            m_block seed1 = make_seed(t);
            m_block seed2 = seed1 + static_cast<m_block>(1);

            auto p1 = prng::PRNG(seed1);
            auto p2 = prng::PRNG(seed2);

            for (int i = 0; i < OUTPUTS_PER_SEED; ++i) {
                m_block out1 = p1.next();
                m_block out2 = p2.next();
                int hd = popcount_mblock(out1 ^ out2);
                hamming_distances.push_back(hd);
            }
        }

        double hd_mean = std::accumulate(hamming_distances.begin(), hamming_distances.end(), 0.0)
                         / hamming_distances.size();
        int hd_min = *std::min_element(hamming_distances.begin(), hamming_distances.end());
        int hd_max = *std::max_element(hamming_distances.begin(), hamming_distances.end());

        double expected_hd = OES_MEM_SIZE / 2.0;
        double hd_ratio = hd_mean / expected_hd;

        bool reproducible = true;
        for (int t = 0; t < 100 && reproducible; ++t) {
            m_block seed = make_seed(t + 50000);
            auto p1 = prng::PRNG(seed);
            auto p2 = prng::PRNG(seed);

            for (int i = 0; i < 100; ++i) {
                if (p1.next() != p2.next()) {
                    reproducible = false;
                    break;
                }
            }
        }

        bool extreme_seeds_ok = true;
        {
            auto zero_seed = static_cast<m_block>(0);
            m_block max_seed = ~static_cast<m_block>(0);

            auto p_zero = prng::PRNG(zero_seed);
            auto p_max = prng::PRNG(max_seed);

            m_block out_zero = p_zero.next();
            m_block out_max = p_max.next();

            if (out_zero == out_max || out_zero == 0 || out_max == 0) {
                extreme_seeds_ok = false;
            }

            int pop_zero = popcount_mblock(out_zero);
            int pop_max = popcount_mblock(out_max);

            if (pop_zero < OES_MEM_SIZE / 4 || pop_zero > 3 * OES_MEM_SIZE / 4 ||
                pop_max < OES_MEM_SIZE / 4 || pop_max > 3 * OES_MEM_SIZE / 4) {
                extreme_seeds_ok = false;
            }
        }

        std::cout << "Trials          : " << TRIALS << "\n";
        std::cout << "Outputs/seed    : " << OUTPUTS_PER_SEED << "\n\n";

        std::cout << "-- Hamming Distance (adjacent seeds) --\n";
        std::cout << "Mean HD         : " << std::setprecision(2) << hd_mean
                << " (expected " << expected_hd << ")\n";
        std::cout << "Range           : [" << hd_min << ", " << hd_max << "]\n";
        std::cout << "Mean/Expected   : " << std::setprecision(3) << hd_ratio << "\n";

        std::cout << "\n-- Reproducibility --\n";
        std::cout << "Same seed = same output: " << (reproducible ? "YES" : "NO") << "\n";

        std::cout << "\n-- Extreme Seeds --\n";
        std::cout << "Zero/Max seeds work: " << (extreme_seeds_ok ? "YES" : "NO") << "\n";

        bool hd_pass = (hd_ratio > 0.95 && hd_ratio < 1.05);

        bool repro_pass = reproducible;
        bool extreme_pass = extreme_seeds_ok;

        bool pass = hd_pass && repro_pass && extreme_pass;
        std::cout << "\nResult: HD=" << (hd_pass ? "OK" : "FAIL")
                << " repro=" << (repro_pass ? "OK" : "FAIL")
                << " extreme=" << (extreme_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 15: COLLISION TEST
    // ========================================================
    bool test_collisions() {
        std::cout << "\n==== TEST 15: COLLISION TEST ====\n";

        if constexpr (OES_MEM_SIZE < 32) {
            constexpr uint64_t TEST_SAMPLES = SAMPLES;

            auto p = prng::PRNG(static_cast<m_block>(0xC0111510ULL));

            std::set<m_block> seen;
            uint64_t first_collision = 0;
            uint64_t total_collisions = 0;

            for (uint64_t i = 0; i < TEST_SAMPLES; ++i) {
                m_block val = p.next();
                if (seen.count(val)) {
                    if (first_collision == 0) first_collision = i;
                    ++total_collisions;
                } else {
                    seen.insert(val);
                }
            }

            double expected_first = std::sqrt(M_PI / 2.0) * std::pow(2.0, OES_MEM_SIZE / 2.0);

            std::cout << "Block size      : " << OES_MEM_SIZE << " bits (small)\n";
            std::cout << "Samples         : " << TEST_SAMPLES << "\n";
            std::cout << "Unique values   : " << seen.size() << "\n";
            std::cout << "First collision : " << first_collision
                    << " (expected ~" << static_cast<uint64_t>(expected_first) << ")\n";
            std::cout << "Total collisions: " << total_collisions << "\n";

            double collision_ratio = (first_collision > 0)
                                         ? static_cast<double>(first_collision) / expected_first
                                         : 1.0;
            bool pass = (collision_ratio > 0.3 && collision_ratio < 3.0);
            std::cout << "Result          : " << (pass ? "[PASS]\n" : "[FAIL]\n");
            return pass;
        } else {
            constexpr uint64_t TEST_SAMPLES = 1ULL << 24;

            auto p = prng::PRNG(static_cast<m_block>(0xC0111510ULL));

            uint64_t suspicious_patterns = 0;

            clock_t start = clock();

            for (uint64_t i = 0; i < TEST_SAMPLES; ++i) {
                m_block val = p.next();
                uint64_t lo = to_u64(val);

                if (lo == 0 || lo == UINT64_MAX) ++suspicious_patterns;
                if (popcount_mblock(val) < 10 || popcount_mblock(val) > OES_MEM_SIZE - 10) {
                    ++suspicious_patterns;
                }

                if ((i & 0xFFFFFULL) == 0) show_progress(i, TEST_SAMPLES, start);
            }
            clear_progress();

            double suspicious_ratio = static_cast<double>(suspicious_patterns) / TEST_SAMPLES;

            std::cout << "Block size      : " << OES_MEM_SIZE << " bits (large)\n";
            std::cout << "Samples         : " << TEST_SAMPLES << "\n";
            std::cout << "Suspicious vals : " << suspicious_patterns
                    << " (" << std::setprecision(6) << (suspicious_ratio * 100) << "%)\n";

            bool pass = (suspicious_ratio < 0.0001);
            std::cout << "Result          : " << (pass ? "[PASS]\n" : "[FAIL]\n");
            return pass;
        }
    }


    // ========================================================
    // TEST 2: RUNS TEST (Enhanced)
    // ========================================================
    bool test_runs() {
        std::cout << "\n==== TEST: RUNS UP/DOWN ====\n";

        // Numero di campioni - adattato alla dimensione del blocco
        constexpr uint64_t SAMPLES = (OES_MEM_SIZE <= 16)
                                         ? (1ULL << 24)
                                         : // 16M
                                         (OES_MEM_SIZE <= 32)
                                             ? (1ULL << 26)
                                             : // 67M
                                             (1ULL << 26); // 67M

        // Massima lunghezza run da tracciare (oltre questo, raggruppiamo)
        constexpr int MAX_RUN_LEN = 12;

        // Contatori
        uint64_t runs_up = 0;
        uint64_t runs_down = 0;
        uint64_t ties = 0;
        Vec<uint64_t> run_lengths_up(MAX_RUN_LEN + 1, 0); // [1..MAX_RUN_LEN], [0] unused, [MAX_RUN_LEN] = overflow
        Vec<uint64_t> run_lengths_down(MAX_RUN_LEN + 1, 0);
        uint64_t max_run_observed = 0;

        auto prng = prng::PRNG(make_seed(12345));

        m_block prev = prng.next();
        int current_run_len = 1;
        int current_direction = 0; // 1 = up, -1 = down, 0 = none yet

        clock_t start = clock();

        for (uint64_t i = 1; i < SAMPLES; ++i) {
            m_block curr = prng.next();

            int dir;
            if (curr > prev) {
                dir = 1; // up
            } else if (curr < prev) {
                dir = -1; // down
            } else {
                // Tie: termina run corrente, conta come tie
                ties++;
                if (current_direction != 0 && current_run_len > 0) {
                    int idx = std::min(current_run_len, MAX_RUN_LEN);
                    if (current_direction == 1) {
                        run_lengths_up[idx]++;
                        runs_up++;
                    } else {
                        run_lengths_down[idx]++;
                        runs_down++;
                    }
                    max_run_observed = std::max(max_run_observed, static_cast<uint64_t>(current_run_len));
                }
                current_run_len = 0;
                current_direction = 0;
                prev = curr;
                continue;
            }

            if (dir == current_direction) {
                // Continua la run
                current_run_len++;
            } else {
                // Cambio direzione: termina run precedente
                if (current_direction != 0 && current_run_len > 0) {
                    int idx = std::min(current_run_len, MAX_RUN_LEN);
                    if (current_direction == 1) {
                        run_lengths_up[idx]++;
                        runs_up++;
                    } else {
                        run_lengths_down[idx]++;
                        runs_down++;
                    }
                    max_run_observed = std::max(max_run_observed, static_cast<uint64_t>(current_run_len));
                }
                // Inizia nuova run
                current_run_len = 1;
                current_direction = dir;
            }

            prev = curr;

            if ((i & 0xFFFFFF) == 0) show_progress(i, SAMPLES, start);
        }

        // Chiudi ultima run
        if (current_direction != 0 && current_run_len > 0) {
            int idx = std::min(current_run_len, MAX_RUN_LEN);
            if (current_direction == 1) {
                run_lengths_up[idx]++;
                runs_up++;
            } else {
                run_lengths_down[idx]++;
                runs_down++;
            }
            max_run_observed = std::max(max_run_observed, static_cast<uint64_t>(current_run_len));
        }

        clear_progress();

        // Combina up e down per analisi (dovrebbero essere simmetrici)
        Vec<uint64_t> run_lengths_total(MAX_RUN_LEN + 1, 0);
        for (int i = 1; i <= MAX_RUN_LEN; ++i) {
            run_lengths_total[i] = run_lengths_up[i] + run_lengths_down[i];
        }

        uint64_t total_runs = runs_up + runs_down;
        double n = static_cast<double>(SAMPLES - ties); // campioni effettivi (esclusi ties)

        // ============ Valori attesi ============
        // Per una sequenza casuale di n elementi, il numero atteso di run di lunghezza k è:
        // E[runs of length k] = 2 * (k^2 + 3k + 1) * (n - k - 2)! * n / ((k + 3)! * (n - 1)!)
        //
        // Approssimazione asintotica per n grande:
        // E[runs of length k] ≈ 2 * n * (k^2 + 3k + 1) / (k + 3)!
        //
        // Numero totale atteso di run ≈ (2n - 1) / 3

        Vec<double> expected(MAX_RUN_LEN + 1, 0.0);

        auto factorial = [](int x) -> double {
            double f = 1.0;
            for (int i = 2; i <= x; ++i) f *= i;
            return f;
        };

        double expected_total_runs = (2.0 * n - 1.0) / 3.0;

        for (int k = 1; k < MAX_RUN_LEN; ++k) {
            // Formula esatta per run di lunghezza esattamente k
            double num = 2.0 * (k * k + 3.0 * k + 1.0);
            double denom = factorial(k + 3);
            expected[k] = n * num / denom;
        }

        // L'ultimo bin raccoglie tutte le run >= MAX_RUN_LEN
        double sum_expected = 0;
        for (int k = 1; k < MAX_RUN_LEN; ++k) {
            sum_expected += expected[k];
        }
        expected[MAX_RUN_LEN] = expected_total_runs - sum_expected;
        if (expected[MAX_RUN_LEN] < 0) expected[MAX_RUN_LEN] = 0;

        // ============ Chi-quadro ============
        double chi_sq = 0.0;
        int df = 0;

        for (int k = 1; k <= MAX_RUN_LEN; ++k) {
            if (expected[k] >= 5.0) {
                double diff = static_cast<double>(run_lengths_total[k]) - expected[k];
                chi_sq += (diff * diff) / expected[k];
                df++;
            }
        }

        // Z-score normalizzato (approssimazione normale per chi-quadro)
        // Chi-sq con df gradi di libertà: media = df, varianza = 2*df
        double z_score = (df > 0) ? (chi_sq - df) / std::sqrt(2.0 * df) : 0.0;

        // ============ Output ============
        std::cout << "Samples         : " << SAMPLES << "\n";
        std::cout << "Ties            : " << ties << " ("
                << std::fixed << std::setprecision(4) << (100.0 * ties / SAMPLES) << "%)\n";
        std::cout << "Runs up         : " << runs_up << "\n";
        std::cout << "Runs down       : " << runs_down << "\n";

        double ratio = (runs_down > 0) ? static_cast<double>(runs_up) / runs_down : 0;
        std::cout << "Up/Down ratio   : " << std::setprecision(4) << ratio << " (expected ~1.0)\n";

        std::cout << "Total runs      : " << total_runs << "\n";
        std::cout << "Expected runs   : " << static_cast<uint64_t>(expected_total_runs) << "\n";
        std::cout << "Max run length  : " << max_run_observed << "\n\n";

        std::cout << "Run length distribution:\n";
        std::cout << "  Len |   Observed   |   Expected   |  Diff %  |  (O-E)²/E\n";
        std::cout << "------+--------------+--------------+----------+-----------\n";

        for (int k = 1; k <= MAX_RUN_LEN; ++k) {
            double obs = static_cast<double>(run_lengths_total[k]);
            double exp = expected[k];
            double diff_pct = (exp > 0) ? 100.0 * (obs - exp) / exp : 0;
            double chi_contrib = (exp >= 5.0) ? (obs - exp) * (obs - exp) / exp : 0;

            std::cout << std::setw(4) << (k == MAX_RUN_LEN ? std::to_string(k) + "+" : std::to_string(k))
                    << "  | " << std::setw(12) << run_lengths_total[k]
                    << " | " << std::setw(12) << static_cast<uint64_t>(exp)
                    << " | " << std::setw(7) << std::setprecision(2) << diff_pct << "%"
                    << " | " << std::setw(9) << std::setprecision(2) << chi_contrib
                    << (exp < 5.0 ? " (excluded)" : "") << "\n";
        }

        std::cout << "\nChi-square      : " << std::setprecision(2) << chi_sq << " (df=" << df << ")\n";
        std::cout << "Z-score         : " << std::setprecision(3) << z_score << " (|z| < 3 = OK)\n";

        // ============ Criteri di pass/fail ============
        // 1. Up/down ratio vicino a 1
        bool ratio_ok = (ratio > 0.98 && ratio < 1.02);

        // 2. Numero totale run entro 1% dell'atteso
        double run_count_diff = std::abs(total_runs - expected_total_runs) / expected_total_runs;
        bool run_count_ok = (run_count_diff < 0.01);

        // 3. Z-score ragionevole (|z| < 3 per 99.7% confidence)
        bool chi_ok = (std::abs(z_score) < 3.0);

        // 4. Ties dovrebbero essere rari per blocchi grandi
        // expected_tie_rate = 1 / 2^bits, ma evitiamo overflow per bits >= 64
        double expected_tie_rate = std::exp2(-static_cast<double>(OES_MEM_SIZE));
        double observed_tie_rate = static_cast<double>(ties) / SAMPLES;
        // Permettiamo fino a 10x l'atteso (per varianza statistica), minimo 1e-9
        bool ties_ok = (observed_tie_rate < std::max(expected_tie_rate * 10.0, 1e-9));

        std::cout << "\n--- Results ---\n";
        std::cout << "Up/Down ratio   : " << (ratio_ok ? "OK" : "FAIL") << "\n";
        std::cout << "Run count       : " << (run_count_ok ? "OK" : "FAIL")
                << " (diff=" << std::setprecision(3) << (run_count_diff * 100) << "%)\n";
        std::cout << "Chi-square test : " << (chi_ok ? "OK" : "FAIL") << "\n";
        std::cout << "Ties            : " << (ties_ok ? "OK" : "FAIL") << "\n";

        bool pass = ratio_ok && run_count_ok && chi_ok && ties_ok;
        std::cout << "\nOverall: " << (pass ? "[PASS]" : "[FAIL]") << "\n";

        return pass;
    }

    // ========================================================
    // TEST 3: BIT FREQUENCY (Enhanced)
    // ========================================================
    bool test_bit_frequency() {
        std::cout << "\n==== TEST 3: BIT FREQUENCY (Enhanced) ====\n";

        constexpr uint64_t TEST_SAMPLES = (OES_MEM_SIZE <= 16) ? SAMPLES : FAST_SAMPLES;

        auto p = prng::PRNG(static_cast<m_block>(0xCAFEBABEULL));
        clock_t start = clock();

        Vec<uint64_t> bit_counts(static_cast<size_t>(OES_MEM_SIZE), 0ULL);
        Vec<std::array<uint64_t, 4> > bit_pairs(static_cast<size_t>(OES_MEM_SIZE - 1));
        for (auto &arr: bit_pairs) arr = {0, 0, 0, 0};

        Vec<uint64_t> transitions_01(static_cast<size_t>(OES_MEM_SIZE), 0ULL);
        Vec<uint64_t> transitions_10(static_cast<size_t>(OES_MEM_SIZE), 0ULL);

        m_block prev = p.next();

        for (uint64_t i = 0; i < TEST_SAMPLES; ++i) {
            m_block val = p.next();

            for (int b = 0; b < OES_MEM_SIZE; ++b) {
                bool curr_bit = get_bit(val, b);
                bool prev_bit = get_bit(prev, b);

                if (curr_bit) ++bit_counts[static_cast<size_t>(b)];

                if (!prev_bit && curr_bit) ++transitions_01[static_cast<size_t>(b)];
                if (prev_bit && !curr_bit) ++transitions_10[static_cast<size_t>(b)];

                if (b < OES_MEM_SIZE - 1) {
                    bool next_bit = get_bit(val, b + 1);
                    int pair_idx = (curr_bit ? 2 : 0) + (next_bit ? 1 : 0);
                    ++bit_pairs[static_cast<size_t>(b)][pair_idx];
                }
            }

            prev = val;
            if ((i & 0xFFFFFULL) == 0) show_progress(i, TEST_SAMPLES, start);
        }
        clear_progress();

        const double expected = static_cast<double>(TEST_SAMPLES) * 0.5;
        const double stddev = std::sqrt(static_cast<double>(TEST_SAMPLES)) / 2.0;
        const double tolerance_4sigma = 4.0 * stddev;

        double max_deviation = 0.0;
        int worst_bit = 0;
        int failed_bits = 0;

        for (int b = 0; b < OES_MEM_SIZE; ++b) {
            const double deviation = std::abs(static_cast<double>(bit_counts[static_cast<size_t>(b)]) - expected);
            if (deviation > max_deviation) {
                max_deviation = deviation;
                worst_bit = b;
            }
            if (deviation > tolerance_4sigma) ++failed_bits;
        }

        const double expected_pair = static_cast<double>(TEST_SAMPLES) * 0.25;
        double max_pair_deviation = 0.0;
        int worst_pair_pos = 0;

        for (int b = 0; b < OES_MEM_SIZE - 1; ++b) {
            for (int pp = 0; pp < 4; ++pp) {
                double dev = std::abs(static_cast<double>(bit_pairs[static_cast<size_t>(b)][pp]) - expected_pair) /
                             expected_pair;
                if (dev > max_pair_deviation) {
                    max_pair_deviation = dev;
                    worst_pair_pos = b;
                }
            }
        }

        const double expected_trans = static_cast<double>(TEST_SAMPLES) * 0.25;
        double max_trans_deviation = 0.0;

        for (int b = 0; b < OES_MEM_SIZE; ++b) {
            double dev_01 = std::abs(static_cast<double>(transitions_01[static_cast<size_t>(b)]) - expected_trans) /
                            expected_trans;
            double dev_10 = std::abs(static_cast<double>(transitions_10[static_cast<size_t>(b)]) - expected_trans) /
                            expected_trans;
            max_trans_deviation = std::max(max_trans_deviation, std::max(dev_01, dev_10));
        }

        const double worst_pct = max_deviation / expected * 100.0;
        const double worst_sigma = max_deviation / stddev;

        std::cout << "Samples         : " << TEST_SAMPLES << "\n";
        std::cout << "Expected 1s     : " << static_cast<uint64_t>(expected) << " per bit\n";
        std::cout << "Tolerance(4σ)   : ± " << static_cast<uint64_t>(tolerance_4sigma) << "\n";
        std::cout << "Worst bit       : " << worst_bit << " (" << std::setprecision(3)
                << worst_pct << "%, " << std::setprecision(2) << worst_sigma << "σ)\n";
        std::cout << "Failed bits     : " << failed_bits << "/" << OES_MEM_SIZE << "\n";
        std::cout << "Max pair dev    : " << std::setprecision(2) << (max_pair_deviation * 100.0)
                << "% at pos " << worst_pair_pos << "\n";
        std::cout << "Max trans dev   : " << std::setprecision(2) << (max_trans_deviation * 100.0) << "%\n";

        std::cout << "Bit 0 pairs     : ";
        for (int i = 0; i < 4; ++i) {
            std::cout << std::setprecision(1) << (100.0 * bit_pairs[0][i] / TEST_SAMPLES) << "% ";
        }
        std::cout << "(expected 25% each)\n";

        bool freq_pass = (failed_bits == 0) && (worst_pct < 1.0);
        bool pair_pass = (max_pair_deviation < 0.05);
        bool trans_pass = (max_trans_deviation < 0.05);

        bool pass = freq_pass && pair_pass && trans_pass;
        std::cout << "Result: freq=" << (freq_pass ? "OK" : "FAIL")
                << " pairs=" << (pair_pass ? "OK" : "FAIL")
                << " trans=" << (trans_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 4: GAP TEST (with K-S)
    // ========================================================
    bool test_gaps() {
        std::cout << "\n==== TEST 4: GAP TEST (CHI-SQUARE, DISCRETE) ====\n";

        constexpr uint64_t TEST_SAMPLES =
                (OES_MEM_SIZE <= 16) ? SAMPLES : FAST_SAMPLES;

        auto p = prng::PRNG(static_cast<m_block>(0xFEEDFACEULL));

        constexpr int MAX_GAP = 128; // last bin is tail: >= MAX_GAP
        std::array<uint64_t, MAX_GAP + 1> gap_counts{};
        uint64_t total_gaps = 0;
        uint64_t current_gap = 0;

        constexpr int BITS_TO_TEST =
                (OES_MEM_SIZE <= 16) ? OES_MEM_SIZE : 8;

        Vec<uint64_t> bit_ones(BITS_TO_TEST, 0);
        Vec<uint64_t> bit_total(BITS_TO_TEST, 0);

        for (uint64_t i = 0; i < TEST_SAMPLES; ++i) {
            const m_block val = p.next();

            bool hit = get_bit(val, OES_MEM_SIZE - 1);
            if (hit) {
                size_t idx = (current_gap >= MAX_GAP)
                                 ? MAX_GAP
                                 : static_cast<size_t>(current_gap);
                ++gap_counts[idx];
                ++total_gaps;
                current_gap = 0;
            } else {
                ++current_gap;
            }

            for (int b = 0; b < BITS_TO_TEST; ++b) {
                if (get_bit(val, b * (OES_MEM_SIZE / BITS_TO_TEST)))
                    ++bit_ones[b];
                ++bit_total[b];
            }
        }

        std::cout << "Samples         : " << TEST_SAMPLES << "\n";
        std::cout << "Total gaps      : " << total_gaps << "\n";
        std::cout << "Gap distribution (observed vs expected):\n";

        // --- Chi-square test ---
        double chi_sq = 0.0;
        int df = 0;

        for (int k = 0; k < MAX_GAP; ++k) {
            double expected =
                    static_cast<double>(total_gaps) * std::pow(0.5, k + 1);
            double observed = static_cast<double>(gap_counts[k]);

            if (expected >= 5.0) {
                double diff = observed - expected;
                chi_sq += (diff * diff) / expected;
                ++df;
            }

            if (k <= 10) {
                std::cout << "  Gap " << std::setw(2) << k << ": "
                        << std::setw(8) << gap_counts[k]
                        << " (exp: " << static_cast<uint64_t>(expected) << ")\n";
            }
        }

        // Tail bin: gap >= MAX_GAP
        double tail_prob = std::pow(0.5, MAX_GAP);
        double expected_tail =
                static_cast<double>(total_gaps) * tail_prob;
        double observed_tail =
                static_cast<double>(gap_counts[MAX_GAP]);

        if (expected_tail >= 5.0) {
            double diff = observed_tail - expected_tail;
            chi_sq += (diff * diff) / expected_tail;
            ++df;
        }

        double chi_sq_norm =
                (df > 0) ? chi_sq / static_cast<double>(df) : 0.0;

        // --- Bit balance sanity check ---
        double max_bit_dev = 0.0;
        for (int b = 0; b < BITS_TO_TEST; ++b) {
            double ratio =
                    static_cast<double>(bit_ones[b]) /
                    static_cast<double>(bit_total[b]);
            max_bit_dev = std::max(max_bit_dev, std::abs(ratio - 0.5));
        }

        std::cout << "Chi-sq norm     : "
                << std::setprecision(4) << chi_sq_norm << "\n";
        std::cout << "Max bit dev     : "
                << std::setprecision(4) << max_bit_dev << "\n";

        bool chi_pass = (chi_sq_norm < 3.0);
        bool bit_pass = (max_bit_dev < 0.02);

        bool pass = chi_pass && bit_pass;

        std::cout << "Result: chi=" << (chi_pass ? "OK" : "FAIL")
                << " bits=" << (bit_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }


    // ========================================================
    // TEST 5: AUTOCORRELATION (Enhanced)
    // ========================================================
    bool test_autocorrelation() {
        std::cout << "\n==== TEST 5: AUTOCORRELATION (Enhanced) ====\n";

        constexpr uint64_t AC_SAMPLES = (OES_MEM_SIZE <= 16) ? SAMPLES : (1ULL << 24);
        constexpr int MAX_LAG = 64;

        auto p = prng::PRNG(static_cast<m_block>(0xABCD1234ULL));

        Vec<m_block> outputs(static_cast<size_t>(AC_SAMPLES));
        for (uint64_t i = 0; i < AC_SAMPLES; ++i) {
            outputs[static_cast<size_t>(i)] = p.next();
        }

        std::cout << "Samples         : " << AC_SAMPLES << "\n";
        std::cout << "Testing lags 1-" << MAX_LAG << "...\n";

        constexpr int BITS_TO_TEST = (OES_MEM_SIZE <= 16) ? OES_MEM_SIZE : 16;
        Vec<double> max_corr_per_bit(BITS_TO_TEST, 0.0);
        Vec<int> worst_lag_per_bit(BITS_TO_TEST, 0);

        double overall_max_corr = 0.0;
        int overall_worst_lag = 0;
        int overall_worst_bit = 0;

        for (int bit = 0; bit < BITS_TO_TEST; ++bit) {
            int test_bit = bit * (OES_MEM_SIZE / BITS_TO_TEST);

            for (int lag = 1; lag <= MAX_LAG; ++lag) {
                int64_t sum = 0;
                const uint64_t count = AC_SAMPLES - static_cast<uint64_t>(lag);

                for (uint64_t i = 0; i < count; ++i) {
                    int b1 = get_bit(outputs[static_cast<size_t>(i)], test_bit) ? 1 : -1;
                    int b2 = get_bit(outputs[static_cast<size_t>(i + lag)], test_bit) ? 1 : -1;
                    sum += b1 * b2;
                }

                double correlation = std::abs(static_cast<double>(sum) / static_cast<double>(count));

                if (correlation > max_corr_per_bit[bit]) {
                    max_corr_per_bit[bit] = correlation;
                    worst_lag_per_bit[bit] = lag;
                }

                if (correlation > overall_max_corr) {
                    overall_max_corr = correlation;
                    overall_worst_lag = lag;
                    overall_worst_bit = test_bit;
                }
            }
        }

        double max_cross_corr = 0.0;
        int cross_bit1 = 0, cross_bit2 = 0;

        for (int b1 = 0; b1 < std::min(8, OES_MEM_SIZE); ++b1) {
            for (int b2 = b1 + 1; b2 < std::min(8, OES_MEM_SIZE); ++b2) {
                int64_t sum = 0;
                for (uint64_t i = 0; i < AC_SAMPLES; ++i) {
                    int v1 = get_bit(outputs[static_cast<size_t>(i)], b1) ? 1 : -1;
                    int v2 = get_bit(outputs[static_cast<size_t>(i)], b2) ? 1 : -1;
                    sum += v1 * v2;
                }
                double corr = std::abs(static_cast<double>(sum) / static_cast<double>(AC_SAMPLES));
                if (corr > max_cross_corr) {
                    max_cross_corr = corr;
                    cross_bit1 = b1;
                    cross_bit2 = b2;
                }
            }
        }

        double threshold = 3.0 / std::sqrt(static_cast<double>(AC_SAMPLES));

        std::cout << "Max lag corr    : " << std::setprecision(6) << overall_max_corr
                << " at lag " << overall_worst_lag << ", bit " << overall_worst_bit << "\n";
        std::cout << "Threshold (3σ)  : " << std::setprecision(6) << threshold << "\n";
        std::cout << "Max cross-corr  : " << std::setprecision(6) << max_cross_corr
                << " (bits " << cross_bit1 << "," << cross_bit2 << ")\n";

        int suspect_count = 0;
        for (int bit = 0; bit < BITS_TO_TEST; ++bit) {
            if (max_corr_per_bit[bit] > threshold) {
                ++suspect_count;
                if (suspect_count <= 3) {
                    std::cout << "  Suspect: bit " << bit * (OES_MEM_SIZE / BITS_TO_TEST)
                            << " lag " << worst_lag_per_bit[bit]
                            << " corr " << std::setprecision(6) << max_corr_per_bit[bit] << "\n";
                }
            }
        }

        std::cout << "Suspect bits    : " << suspect_count << "/" << BITS_TO_TEST << "\n";

        bool lag_pass = (overall_max_corr < threshold * 2.0);
        bool cross_pass = (max_cross_corr < threshold * 2.0);
        bool suspect_pass = (suspect_count <= BITS_TO_TEST / 4);

        bool pass = lag_pass && cross_pass && suspect_pass;
        std::cout << "Result: lag=" << (lag_pass ? "OK" : "FAIL")
                << " cross=" << (cross_pass ? "OK" : "FAIL")
                << " suspect=" << (suspect_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 6: BIRTHDAY SPACING (Enhanced)
    // ========================================================
    bool test_birthday_spacing() {
        std::cout << "\n==== TEST 6: BIRTHDAY SPACING (Enhanced) ====\n";

        if constexpr (OES_MEM_SIZE < 32) {
            std::cout << "Skipped for small block size\n";
            return true;
        }

        auto p = prng::PRNG(static_cast<m_block>(0x98765432ULL));

        constexpr uint64_t N = (OES_MEM_SIZE >= 64) ? (1ULL << 20) : (1ULL << 18);
        constexpr int BITS_USED = (OES_MEM_SIZE >= 64) ? 48 : (OES_MEM_SIZE == 32) ? 28 : 40;
        constexpr uint64_t SPACE = 1ULL << BITS_USED;
        constexpr uint64_t VALUE_MASK = SPACE - 1;

        Vec<uint64_t> values(N);
        for (uint64_t i = 0; i < N; ++i) {
            values[i] = to_u64(p.next()) & VALUE_MASK;
        }

        std::sort(values.begin(), values.end());

        uint64_t collisions = 0;
        Vec<uint64_t> spacings;
        spacings.reserve(static_cast<size_t>(N));

        for (uint64_t i = 1; i < N; ++i) {
            if (values[static_cast<size_t>(i)] == values[static_cast<size_t>(i - 1)]) {
                ++collisions;
            }
            spacings.push_back(values[static_cast<size_t>(i)] - values[static_cast<size_t>(i - 1)]);
        }

        const double expected_collisions = static_cast<double>(N) * static_cast<double>(N) /
                                           (2.0 * static_cast<double>(SPACE));

        std::sort(spacings.begin(), spacings.end());

        const double q25 = static_cast<double>(spacings[spacings.size() / 4]);
        const double median = static_cast<double>(spacings[spacings.size() / 2]);
        const double q75 = static_cast<double>(spacings[3 * spacings.size() / 4]);
        const double expected_spacing = static_cast<double>(SPACE) / static_cast<double>(N);

        uint64_t spacing_collisions = 0;
        for (size_t i = 1; i < spacings.size(); ++i) {
            if (spacings[i] == spacings[i - 1]) ++spacing_collisions;
        }

        std::cout << "Samples         : " << N << "\n";
        std::cout << "Space           : 2^" << BITS_USED << "\n";
        std::cout << "\n-- First-order --\n";
        std::cout << "Collisions      : " << collisions
                << " (expected ~" << std::setprecision(1) << expected_collisions << ")\n";
        std::cout << "Spacing Q25     : " << static_cast<uint64_t>(q25) << "\n";
        std::cout << "Spacing median  : " << static_cast<uint64_t>(median)
                << " (expected ~" << static_cast<uint64_t>(expected_spacing) << ")\n";
        std::cout << "Spacing Q75     : " << static_cast<uint64_t>(q75) << "\n";

        std::cout << "\n-- Second-order --\n";
        std::cout << "Spacing collisions: " << spacing_collisions << "\n";

        const double collision_ratio = (expected_collisions > 0.1)
                                           ? static_cast<double>(collisions) / expected_collisions
                                           : 1.0;
        const double spacing_ratio = median / expected_spacing;

        std::cout << "\nCollision ratio : " << std::setprecision(3) << collision_ratio << "\n";
        std::cout << "Spacing ratio   : " << std::setprecision(3) << spacing_ratio << "\n";

        bool collision_pass = (collision_ratio > 0.1 && collision_ratio < 10.0) || expected_collisions < 1.0;
        bool spacing_pass = (spacing_ratio > 0.5 && spacing_ratio < 2.0);
        bool iqr_pass = (q75 / q25 > 1.5 && q75 / q25 < 10.0);

        bool pass = collision_pass && spacing_pass && iqr_pass;
        std::cout << "Result: coll=" << (collision_pass ? "OK" : "FAIL")
                << " spacing=" << (spacing_pass ? "OK" : "FAIL")
                << " IQR=" << (iqr_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 7: AVALANCHE TEST (Enhanced)
    // ========================================================
    bool test_avalanche() {
        std::cout << "\n==== TEST 7: AVALANCHE TEST (Enhanced) ====\n";

        constexpr int TRIALS = (OES_MEM_SIZE <= 16) ? 50000 : (OES_MEM_SIZE <= 32) ? 30000 : 20000;
        constexpr int OUTPUTS_TO_CHECK = (OES_MEM_SIZE <= 16) ? 5 : 3;

        constexpr auto OES_MEM_SIZE_BLOCK_MASK = static_cast<m_block>(-1);

        // SAC matrices: [output][input_bit][output_bit]
        Vec<Vec<Vec<uint64_t> > > sac_matrices(OUTPUTS_TO_CHECK);
        for (int out = 0; out < OUTPUTS_TO_CHECK; ++out) {
            sac_matrices[out].resize(OES_MEM_SIZE, Vec<uint64_t>(OES_MEM_SIZE, 0));
        }

        Vec<uint64_t> total_flips_per_output(OUTPUTS_TO_CHECK, 0);

        clock_t start = clock();

        for (int t = 0; t < TRIALS; ++t) {
            const m_block seed = make_seed(t);

            for (int flip_bit = 0; flip_bit < OES_MEM_SIZE; ++flip_bit) {
                const m_block seed_flipped = seed ^ (static_cast<m_block>(1) << flip_bit);

                auto p1 = prng::PRNG(seed);
                auto p2 = prng::PRNG(seed_flipped);

                for (int out_idx = 0; out_idx < OUTPUTS_TO_CHECK; ++out_idx) {
                    const m_block out1 = p1.next();
                    const m_block out2 = p2.next();

                    // Mask diff to actual block size
                    const m_block diff = (out1 ^ out2) & OES_MEM_SIZE_BLOCK_MASK;

                    // Count total flips
                    total_flips_per_output[out_idx] += popcount_mblock(diff);

                    // Fill SAC matrix
                    for (int out_bit = 0; out_bit < OES_MEM_SIZE; ++out_bit) {
                        if (get_bit(diff, out_bit)) {
                            ++sac_matrices[out_idx][flip_bit][out_bit];
                        }
                    }
                }
            }

            if ((t & 0xFFF) == 0) show_progress(t, TRIALS, start);
        }
        clear_progress();

        std::cout << "Trials          : " << TRIALS << "\n";
        std::cout << "Block size      : " << OES_MEM_SIZE << " bits\n\n";

        Vec<double> flip_ratios(OUTPUTS_TO_CHECK);
        Vec<double> max_deviations(OUTPUTS_TO_CHECK);
        Vec<double> avg_deviations(OUTPUTS_TO_CHECK);

        const double expected = static_cast<double>(TRIALS) * 0.5;

        for (int out = 0; out < OUTPUTS_TO_CHECK; ++out) {
            double total_comparisons = static_cast<double>(TRIALS) * OES_MEM_SIZE;
            double avg_output_bits_flipped = static_cast<double>(total_flips_per_output[out]) / total_comparisons;
            flip_ratios[out] = avg_output_bits_flipped / OES_MEM_SIZE; // ratio in [0,1]

            double max_dev = 0.0;
            double sum_dev = 0.0;

            for (int i = 0; i < OES_MEM_SIZE; ++i) {
                for (int j = 0; j < OES_MEM_SIZE; ++j) {
                    double observed = static_cast<double>(sac_matrices[out][i][j]);
                    double dev = std::abs(observed - expected) / expected;
                    max_dev = std::max(max_dev, dev);
                    sum_dev += dev;
                }
            }

            max_deviations[out] = max_dev;
            avg_deviations[out] = sum_dev / (OES_MEM_SIZE * OES_MEM_SIZE);

            std::cout << "Output " << (out + 1) << ": "
                    << std::fixed << std::setprecision(2) << (flip_ratios[out] * 100.0) << "% flip, "
                    << std::setprecision(2) << (max_deviations[out] * 100.0) << "% max dev, "
                    << std::setprecision(2) << (avg_deviations[out] * 100.0) << "% avg dev\n";
        }

        // ============ DEBUG: SAC Matrix heatmap per primo output ============
        std::cout << "\n--- SAC Matrix for Output 1 (flip counts, expected="
                << static_cast<int>(expected) << ") ---\n";
        std::cout << "Rows = input bit flipped, Cols = output bit affected\n";

        if (OES_MEM_SIZE <= 16) {
            std::cout << "     ";
            for (int j = 0; j < OES_MEM_SIZE; ++j) {
                std::cout << std::setw(6) << j;
            }
            std::cout << "\n";

            for (int i = 0; i < OES_MEM_SIZE; ++i) {
                std::cout << std::setw(3) << i << ": ";
                for (int j = 0; j < OES_MEM_SIZE; ++j) {
                    uint64_t val = sac_matrices[0][i][j];
                    double dev_pct = 100.0 * (static_cast<double>(val) - expected) / expected;
                    // Mostra deviazione percentuale
                    std::cout << std::setw(5) << std::setprecision(0) << std::fixed << dev_pct << "%";
                }
                std::cout << "\n";
            }
        } else {
            std::cout << "(Matrix too large to display, showing corner 8x8)\n";
            std::cout << "     ";
            for (int j = 0; j < 8; ++j) {
                std::cout << std::setw(6) << j;
            }
            std::cout << "\n";

            for (int i = 0; i < 8; ++i) {
                std::cout << std::setw(3) << i << ": ";
                for (int j = 0; j < 8; ++j) {
                    uint64_t val = sac_matrices[0][i][j];
                    double dev_pct = 100.0 * (static_cast<double>(val) - expected) / expected;
                    std::cout << std::setw(5) << std::setprecision(0) << std::fixed << dev_pct << "%";
                }
                std::cout << "\n";
            }
        }
        std::cout << "--- END SAC Matrix ---\n\n";
        // ============ FINE DEBUG SAC ============

        int final_idx = OUTPUTS_TO_CHECK - 1;
        double final_ratio = flip_ratios[final_idx];
        double final_max_dev = max_deviations[final_idx];
        double final_avg_dev = avg_deviations[final_idx];

        double ratio_tolerance = (OES_MEM_SIZE <= 16) ? 0.08 : 0.05;
        double max_dev_tolerance = (OES_MEM_SIZE <= 16) ? 0.12 : 0.08;
        double avg_dev_tolerance = (OES_MEM_SIZE <= 16) ? 0.05 : 0.03;

        bool improving = (max_deviations[final_idx] <= max_deviations[0] * 1.2) ||
                         (max_deviations[final_idx] < max_dev_tolerance);

        bool ratio_pass = (final_ratio > 0.5 - ratio_tolerance && final_ratio < 0.5 + ratio_tolerance);
        bool max_dev_pass = (final_max_dev < max_dev_tolerance);
        bool avg_dev_pass = (final_avg_dev < avg_dev_tolerance);

        bool pass = ratio_pass && max_dev_pass && avg_dev_pass && improving;

        std::cout << "Thresholds: ratio " << std::setprecision(0) << (50 - ratio_tolerance * 100)
                << "-" << (50 + ratio_tolerance * 100) << "%, max_dev <"
                << (max_dev_tolerance * 100) << "%, avg_dev <" << (avg_dev_tolerance * 100) << "%\n";
        std::cout << "Result: ratio=" << (ratio_pass ? "OK" : "FAIL")
                << " max_dev=" << (max_dev_pass ? "OK" : "FAIL")
                << " avg_dev=" << (avg_dev_pass ? "OK" : "FAIL")
                << " improve=" << (improving ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // TEST 8: ENTROPY (Multiple Estimators)
    // ========================================================
    bool test_entropy() {
        std::cout << "\n==== TEST 8: ENTROPY (Multiple Estimators) ====\n";

        auto p = prng::PRNG(static_cast<m_block>(0x11223344ULL));

        std::array<uint64_t, 256> byte_counts = {};
        Vec<uint64_t> word_counts(65536, 0);
        std::array<uint64_t, 65536> bigram_counts = {};

        constexpr uint64_t TARGET_BYTES = (OES_MEM_SIZE <= 16)
                                              ? (1ULL << 22) // 4MB invece di 128KB
                                              : (1ULL << 24);

        uint64_t bytes_processed = 0;
        uint8_t prev_byte = 0;
        constexpr int BYTES_PER_BLOCK = OES_MEM_SIZE / 8;

        while (bytes_processed < TARGET_BYTES) {
            m_block val = p.next();

            for (int b = 0; b < BYTES_PER_BLOCK && bytes_processed < TARGET_BYTES; ++b) {
                uint8_t byte_val;
                if constexpr (OES_MEM_SIZE <= 64) {
                    byte_val = static_cast<uint8_t>((val >> (b * 8)) & 0xFFULL);
                } else {
                    if (b < 8) {
                        byte_val = static_cast<uint8_t>((to_u64(val) >> (b * 8)) & 0xFFULL);
                    } else {
                        byte_val = static_cast<uint8_t>((to_u64_high(val) >> ((b - 8) * 8)) & 0xFFULL);
                    }
                }

                ++byte_counts[byte_val];

                if (bytes_processed > 0) {
                    uint16_t bigram = (static_cast<uint16_t>(prev_byte) << 8) | byte_val;
                    ++bigram_counts[bigram];
                }

                if ((b & 1) == 1 && b > 0) {
                    uint8_t prev_b;
                    if constexpr (OES_MEM_SIZE <= 64) {
                        prev_b = static_cast<uint8_t>((val >> ((b - 1) * 8)) & 0xFFULL);
                    } else {
                        if (b - 1 < 8) {
                            prev_b = static_cast<uint8_t>((prng_tests::to_u64(val) >> ((b - 1) * 8)) & 0xFFULL);
                        } else {
                            prev_b = static_cast<uint8_t>(
                                (prng_tests::to_u64_high(val) >> ((b - 1 - 8) * 8)) & 0xFFULL);
                        }
                    }
                    uint16_t word = (static_cast<uint16_t>(prev_b) << 8) | byte_val;
                    ++word_counts[word];
                }

                prev_byte = byte_val;
                ++bytes_processed;
            }
        }

        double byte_entropy = 0.0;
        for (int i = 0; i < 256; ++i) {
            if (byte_counts[i] > 0) {
                double prob = static_cast<double>(byte_counts[i]) / static_cast<double>(bytes_processed);
                byte_entropy -= prob * std::log2(prob);
            }
        }

        double bigram_entropy = 0.0;
        uint64_t bigram_total = bytes_processed - 1;
        for (int i = 0; i < 65536; ++i) {
            if (bigram_counts[i] > 0) {
                double prob = static_cast<double>(bigram_counts[i]) / static_cast<double>(bigram_total);
                bigram_entropy -= prob * std::log2(prob);
            }
        }
        double bigram_entropy_per_byte = bigram_entropy / 2.0;

        double word_entropy = 0.0;
        uint64_t word_total = bytes_processed / 2;
        for (int i = 0; i < 65536; ++i) {
            if (word_counts[i] > 0) {
                double prob = static_cast<double>(word_counts[i]) / static_cast<double>(word_total);
                word_entropy -= prob * std::log2(prob);
            }
        }
        double word_entropy_per_byte = word_entropy / 2.0;

        double chi_sq_bytes = 0.0;
        double expected_bytes = static_cast<double>(bytes_processed) / 256.0;
        for (int i = 0; i < 256; ++i) {
            double diff = static_cast<double>(byte_counts[i]) - expected_bytes;
            chi_sq_bytes += (diff * diff) / expected_bytes;
        }
        double chi_sq_bytes_norm = chi_sq_bytes / 255.0;

        uint64_t max_byte_count = *std::max_element(byte_counts.begin(), byte_counts.end());
        double max_prob = static_cast<double>(max_byte_count) / static_cast<double>(bytes_processed);
        double min_entropy = -std::log2(max_prob);

        std::cout << "Bytes analyzed  : " << bytes_processed << "\n\n";
        std::cout << "-- Shannon Entropy --\n";
        std::cout << "Byte entropy    : " << std::setprecision(6) << byte_entropy << " bits/byte (max 8.0)\n";
        std::cout << "Bigram entropy  : " << std::setprecision(6) << bigram_entropy_per_byte << " bits/byte\n";
        std::cout << "Word entropy    : " << std::setprecision(6) << word_entropy_per_byte << " bits/byte\n";
        std::cout << "Min-entropy     : " << std::setprecision(6) << min_entropy << " bits/byte\n\n";

        std::cout << "-- Uniformity --\n";
        std::cout << "Byte chi-sq     : " << std::setprecision(4) << chi_sq_bytes_norm << "\n";
        std::cout << "Efficiency      : " << std::setprecision(4) << (byte_entropy / 8.0 * 100.0) << "%\n";

        bool byte_pass = (byte_entropy > 7.99);
        bool bigram_pass = (bigram_entropy_per_byte > 7.98);
        bool min_pass = (min_entropy > 7.9);
        bool chi_pass = (chi_sq_bytes_norm > 0.8 && chi_sq_bytes_norm < 1.2);

        bool pass = byte_pass && bigram_pass && min_pass && chi_pass;
        std::cout << "\nResult: byte=" << (byte_pass ? "OK" : "FAIL")
                << " bigram=" << (bigram_pass ? "OK" : "FAIL")
                << " min=" << (min_pass ? "OK" : "FAIL")
                << " chi=" << (chi_pass ? "OK" : "FAIL")
                << (pass ? " [PASS]\n" : " [FAIL]\n");

        return pass;
    }

    // ========================================================
    // RUN ALL TESTS
    // ========================================================
    void run_all() {
        std::cout << "================================================================\n";
        std::cout << "       PRNG CRYPTOGRAPHIC TEST SUITE - ENHANCED\n";
        std::cout << "================================================================\n";
        std::cout << "  Block size      : " << OES_MEM_SIZE << " bits\n";
        std::cout << "  m_block type    : " << sizeof(m_block) * 8 << " bits\n";
        std::cout << "  Full period test: " << (FULL_PERIOD_POSSIBLE ? "YES" : "NO (statistical)") << "\n";
        std::cout << "  Base samples    : " << SAMPLES << "\n";
        std::cout << "================================================================\n";

        clock_t start = clock();

        int passed = 0;
        constexpr int total = 15;

        struct TestResult {
            const char *name;
            const char *phase;
            bool passed;
            double time_sec;
        };
        std::vector<TestResult> results;
        results.reserve(total);

        auto run_test = [&](const char *name, const char *phase, std::function<bool()> test_fn) {
            clock_t t_start = clock();
            bool result = test_fn();
            double t_elapsed = static_cast<double>(clock() - t_start) / CLOCKS_PER_SEC;
            results.push_back({name, phase, result, t_elapsed});
            if (result) ++passed;
            return result;
        };

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              PHASE 1: DISTRIBUTION TESTS                     ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        run_test("Serial Correlation", "Distribution", test_serial_correlation);
        run_test("Runs Test", "Distribution", test_runs);
        run_test("Bit Frequency", "Distribution", test_bit_frequency);
        run_test("Gap Test", "Distribution", test_gaps);

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              PHASE 2: CORRELATION TESTS                      ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        run_test("Autocorrelation", "Correlation", test_autocorrelation);
        run_test("Birthday Spacing", "Correlation", test_birthday_spacing);

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              PHASE 3: DIFFUSION TESTS                        ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        run_test("Avalanche Effect", "Diffusion", test_avalanche);
        run_test("SAC & BIC", "Diffusion", test_sac);
        run_test("Seed Sensitivity", "Diffusion", test_seed_sensitivity);

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              PHASE 4: COMPLEXITY TESTS                       ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        run_test("Entropy Analysis", "Complexity", test_entropy);
        run_test("Linear Complexity", "Complexity", test_linear_complexity);
        run_test("Maurer Universal", "Complexity", test_maurer_universal);

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              PHASE 5: STRUCTURE TESTS                        ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        run_test("Spectral (DFT)", "Structure", test_spectral);
        run_test("Compression", "Structure", test_compression);
        run_test("Collision", "Structure", test_collisions);

        double elapsed = static_cast<double>(clock() - start) / CLOCKS_PER_SEC;

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        SUMMARY                               ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

        std::cout << "  ┌─────────────────────────┬──────────────┬────────┬─────────┐\n";
        std::cout << "  │ Test Name               │ Phase        │ Result │ Time(s) │\n";
        std::cout << "  ├─────────────────────────┼──────────────┼────────┼─────────┤\n";

        for (const auto &r: results) {
            std::cout << "  │ " << std::left << std::setw(23) << r.name
                    << " │ " << std::setw(12) << r.phase
                    << " │ " << std::setw(6) << (r.passed ? "PASS" : "FAIL")
                    << " │ " << std::right << std::setw(7) << std::fixed
                    << std::setprecision(2) << r.time_sec << " │\n";
        }

        std::cout << "  └─────────────────────────┴──────────────┴────────┴─────────┘\n\n";

        double score = static_cast<double>(passed) / static_cast<double>(total) * 100.0;

        std::cout << "  ┌────────────────────────────────────────────────────────────┐\n";
        std::cout << "  │  FINAL SCORE: " << std::setw(2) << passed << "/" << total
                << " (" << std::fixed << std::setprecision(1) << score << "%)";

        std::string rating;
        std::string stars;
        if (passed == total) {
            rating = "PERFECT";
            stars = "★★★★★";
        } else if (passed >= 14) {
            rating = "EXCELLENT";
            stars = "★★★★☆";
        } else if (passed >= 12) {
            rating = "VERY GOOD";
            stars = "★★★☆☆";
        } else if (passed >= 10) {
            rating = "GOOD";
            stars = "★★☆☆☆";
        } else if (passed >= 7) {
            rating = "MARGINAL";
            stars = "★☆☆☆☆";
        } else {
            rating = "POOR";
            stars = "☆☆☆☆☆";
        }

        std::cout << "  " << stars << "  " << rating;
        int padding = 60 - 35 - static_cast<int>(rating.length());
        for (int i = 0; i < padding; ++i) std::cout << " ";
        std::cout << "│\n";
        std::cout << "  │  Total time: " << std::setw(8) << std::setprecision(2) << elapsed
                << " seconds                                   │\n";
        std::cout << "  └────────────────────────────────────────────────────────────┘\n\n";

        std::cout << "  Phase Breakdown:\n";
        std::map<std::string, std::pair<int, int> > phase_stats;
        for (const auto &r: results) {
            phase_stats[r.phase].second++;
            if (r.passed) phase_stats[r.phase].first++;
        }

        for (const auto &[phase, stats]: phase_stats) {
            std::cout << "    " << std::left << std::setw(14) << phase << ": "
                    << stats.first << "/" << stats.second;
            if (stats.first == stats.second) {
                std::cout << " ✓";
            } else {
                std::cout << " ✗";
            }
            std::cout << "\n";
        }

        std::cout << "\n";
        bool has_failures = false;
        for (const auto &r: results) {
            if (!r.passed) {
                if (!has_failures) {
                    std::cout << "  ⚠ FAILED TESTS:\n";
                    has_failures = true;
                }
                std::cout << "    - " << r.name << " (" << r.phase << ")\n";
            }
        }

        std::cout << "\n";
        std::cout << "  ┌────────────────────────────────────────────────────────────┐\n";
        std::cout << "  │                      ASSESSMENT                            │\n";
        std::cout << "  └────────────────────────────────────────────────────────────┘\n\n";

        if (passed == total) {
            std::cout << "  ✓ All statistical tests passed\n";
            std::cout << "  ✓ Excellent randomness quality\n";
            std::cout << "  ✓ Strong diffusion properties (SAC & BIC satisfied)\n";
            std::cout << "  ✓ No detectable patterns or correlations\n";
            std::cout << "  ✓ High entropy and linear complexity\n";
            std::cout << "  ✓ Resistant to compression attacks\n\n";

            std::cout << "  ╔════════════════════════════════════════════════════════╗\n";
            std::cout << "  ║  STATISTICAL QUALITY: CRYPTOGRAPHIC GRADE              ║\n";
            std::cout << "  ╚════════════════════════════════════════════════════════╝\n\n";

            std::cout << "  For production CRYPTOGRAPHIC use, additionally verify:\n";
            std::cout << "    □ State recovery resistance (given N outputs)\n";
            std::cout << "    □ Forward secrecy (backtracking resistance)\n";
            std::cout << "    □ Differential cryptanalysis resistance\n";
            std::cout << "    □ Linear cryptanalysis resistance\n";
            std::cout << "    □ Side-channel attack resistance\n";
            std::cout << "    □ Formal security proof or peer review\n";
            std::cout << "    □ NIST SP 800-22 full test suite\n";
        } else if (passed >= 12) {
            std::cout << "  ✓ Good overall randomness quality\n";
            std::cout << "  ✓ Most statistical tests passed\n";
            std::cout << "  △ Minor weaknesses detected\n\n";

            std::cout << "  Recommendations:\n";
            std::cout << "    - Review failed tests for specific weaknesses\n";
            std::cout << "    - May be suitable for non-cryptographic applications\n";
            std::cout << "    - Consider additional mixing rounds\n";
        } else if (passed >= 8) {
            std::cout << "  △ Moderate randomness quality\n";
            std::cout << "  ✗ Several tests failed\n\n";

            std::cout << "  Recommendations:\n";
            std::cout << "    - Significant improvement needed\n";
            std::cout << "    - Review mixing function design\n";
            std::cout << "    - Check for biases and correlations\n";
            std::cout << "    - Not recommended for security applications\n";
        } else {
            std::cout << "  ✗ Poor randomness quality\n";
            std::cout << "  ✗ Multiple critical failures\n\n";

            std::cout << "  Recommendations:\n";
            std::cout << "    - Fundamental redesign required\n";
            std::cout << "    - Review state update mechanism\n";
            std::cout << "    - Ensure proper diffusion in mixing function\n";
            std::cout << "    - Not suitable for any sensitive application\n";
        }

        std::cout << "\n================================================================\n";
        std::cout << "                    END OF TEST REPORT\n";
        std::cout << "================================================================\n";
    }
}
