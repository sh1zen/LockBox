#ifndef PRNG_H
#define PRNG_H

#include "defines.h"
#include "m_block.h"
#include "constants.h"

namespace prng {
    class PRNG {
        static constexpr int R1 = (OES_MEM_SIZE * 07) / 64 + 1;
        static constexpr int R2 = (OES_MEM_SIZE * 17) / 64 + 1;
        static constexpr int R3 = (OES_MEM_SIZE * 29) / 64 + 1;
        static constexpr int R4 = (OES_MEM_SIZE * 43) / 64 + 1;

        static constexpr int S1 = (OES_MEM_SIZE * 30) / 64 + 1;
        static constexpr int S2 = (OES_MEM_SIZE * 27) / 64 + 1;
        static constexpr int S3 = (OES_MEM_SIZE * 32) / 64 + 1;

        static constexpr int ROT1 = (OES_MEM_SIZE <= 16) ? OES_MEM_SIZE / 4 : OES_MEM_SIZE / 2;
        static constexpr int ROT2 = (OES_MEM_SIZE <= 8) ? 1 : (OES_MEM_SIZE <= 16) ? 3 : OES_MEM_SIZE / 8 * 3;
        static constexpr int ROT3 = (OES_MEM_SIZE <= 8) ? 3 : (OES_MEM_SIZE <= 16) ? 2 : OES_MEM_SIZE / 4;
        static constexpr int ROT4 = (OES_MEM_SIZE <= 8)
                                        ? 2
                                        : (OES_MEM_SIZE <= 16)
                                              ? 1
                                              : (OES_MEM_SIZE <= 32)
                                                    ? 7
                                                    : (OES_MEM_SIZE <= 64)
                                                          ? 7
                                                          : 13;

        static constexpr int FEISTEL_ROUNDS = (OES_MEM_SIZE <= 16) ? 4 : (OES_MEM_SIZE <= 32) ? 2 : 1;

        static constexpr m_block LCG_MULT = (OES_MEM_SIZE <= 8)
                                                ? static_cast<m_block>(141)
                                                : (OES_MEM_SIZE <= 16)
                                                      ? static_cast<m_block>(25173)
                                                      : (OES_MEM_SIZE <= 32)
                                                            ? static_cast<m_block>(1664525)
                                                            : (OES_MEM_SIZE <= 64)
                                                                  ? static_cast<m_block>(6364136223846793005ULL)
                                                                  : PRNG_MULT1;

        static constexpr m_block LCG_INC = (OES_MEM_SIZE <= 8)
                                               ? static_cast<m_block>(77)
                                               : (OES_MEM_SIZE <= 16)
                                                     ? static_cast<m_block>(13849)
                                                     : (OES_MEM_SIZE <= 32)
                                                           ? static_cast<m_block>(1013904223)
                                                           : (OES_MEM_SIZE <= 64)
                                                                 ? static_cast<m_block>(1442695040888963407ULL)
                                                                 : (PRNG_SEED | 1);

        alignas(64) static inline
        constexpr uint8_t SBOX16[16] = {
            0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
        };

        alignas(64) static inline
        constexpr uint8_t SBOX256[256] = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
            0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
            0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
            0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
            0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
            0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
            0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
            0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
            0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
            0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
            0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
            0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
            0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
            0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };

        alignas(64) m_block state[16]{};
        alignas(64) uint8_t col_idx[16]{};
        alignas(64) uint8_t diag_idx[16]{};

        m_block counter;
        m_block accumulator;

        static inline m_block apply_sbox(m_block x);

        static inline void quarter_round(m_block &a, m_block &b, m_block &c, m_block &d);

    public:
        // Constructor (requires seed)
        explicit PRNG(const m_block seed) : state{}, col_idx{}, diag_idx{}, counter(0), accumulator(0) {
            init(seed);
        }

        // Copy constructor (clone)
        PRNG(const PRNG &other) : counter(other.counter) {
            std::memcpy(state, other.state, sizeof(state));
            std::memcpy(col_idx, other.col_idx, sizeof(col_idx));
            std::memcpy(diag_idx, other.diag_idx, sizeof(diag_idx));
        }

        // Copy assignment operator (clone)
        PRNG &operator=(const PRNG &other) {
            if (this != &other) {
                counter = other.counter;
                std::memcpy(state, other.state, sizeof(state));
                std::memcpy(col_idx, other.col_idx, sizeof(col_idx));
                std::memcpy(diag_idx, other.diag_idx, sizeof(diag_idx));
            }
            return *this;
        }

        // Move constructor
        PRNG(PRNG &&other) noexcept : counter(other.counter) {
            std::memcpy(state, other.state, sizeof(state));
            std::memcpy(col_idx, other.col_idx, sizeof(col_idx));
            std::memcpy(diag_idx, other.diag_idx, sizeof(diag_idx));
            other.clear();
        }

        // Move assignment operator
        PRNG &operator=(PRNG &&other) noexcept {
            if (this != &other) {
                counter = other.counter;
                std::memcpy(state, other.state, sizeof(state));
                std::memcpy(col_idx, other.col_idx, sizeof(col_idx));
                std::memcpy(diag_idx, other.diag_idx, sizeof(diag_idx));
                other.clear();
            }
            return *this;
        }

        // Destructor
        ~PRNG() {
            clear();
        }

        // Public methods
        void init(m_block seed);

        m_block next();

        void clear();
    };
}

namespace prng_tests {
    void run_all();
}

#endif // PRNG_H
