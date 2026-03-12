#include "prng.h"

#include <chrono>

#include "raw-layer.h"

namespace prng {
    m_block time_seed() {
        using clock = std::chrono::high_resolution_clock;

        const auto t =
                static_cast<uint64_t>(
                    clock::now().time_since_epoch().count()
                );

        if constexpr (OES_MEM_SIZE <= 64) {
            return static_cast<m_block>(t);
        } else if constexpr (OES_MEM_SIZE == 128) {
            // Estensione semplice a 128 bit
            m_block seed = 0;
            seed |= static_cast<m_block>(t);
            seed |= static_cast<m_block>(t) << 64;
            return seed;
        }
    }

    // Secure clear
    void PRNG::clear() {
        std::memset(state, 0, sizeof(state));
        counter = 0;
        accumulator = 0;
    }

    // Private methods
    inline m_block PRNG::apply_sbox(const m_block x) {
        if constexpr (OES_MEM_SIZE == 8) {
            return static_cast<m_block>(SBOX256[static_cast<uint8_t>(x)]);
        } else if constexpr (OES_MEM_SIZE == 16) {
            return static_cast<m_block>(SBOX256[static_cast<uint8_t>(x & 0xFF)])
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 8) & 0xFF)]) << 8);
        } else if constexpr (OES_MEM_SIZE == 32) {
            return static_cast<m_block>(SBOX256[static_cast<uint8_t>(x & 0xFF)])
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 8) & 0xFF)]) << 8)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 16) & 0xFF)]) << 16)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 24) & 0xFF)]) << 24);
        } else if constexpr (OES_MEM_SIZE == 64) {
            return static_cast<m_block>(SBOX256[static_cast<uint8_t>(x & 0xFF)])
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 8) & 0xFF)]) << 8)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 16) & 0xFF)]) << 16)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 24) & 0xFF)]) << 24)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 32) & 0xFF)]) << 32)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 40) & 0xFF)]) << 40)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 48) & 0xFF)]) << 48)
                   | (static_cast<m_block>(SBOX256[static_cast<uint8_t>((x >> 56) & 0xFF)]) << 56);
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
    }

    // Public methods
    void PRNG::init(const m_block seed) {
        counter = 0;
        accumulator = 0;
        m_block *st = state;

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
        for (int pass = 0; pass < 8; pass++) {
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
                m_block si = apply_sbox(s ^ h);
                si *= DIFFUSE_CONST;
                si ^= si >> S1;
                st[i] = si;

                // Diffusione cross-state (aumentata per 32/64 bit)
                const m_block siRot1 = mBlock::rotl(si, ROT1);
                const m_block siRot2 = mBlock::rotl(si, ROT2);
                st[(i + 1) & 15] ^= siRot1;
                st[(i + 7) & 15] ^= siRot2;

                if constexpr (OES_MEM_SIZE >= 32) {
                    st[(i + 11) & 15] ^= mBlock::rotl(si, ROT3);
                    st[(i + 13) & 15] ^= mBlock::rotl(si, ROT4);
                }

                // Quarter round ogni 4 elementi
                if ((i & 3) == 3) {
                    quarter_round(st[i - 3], st[i - 2], st[i - 1], st[i]);
                }
            }

            // Column mixing per blocchi >= 32 bit (stile ChaCha)
            if constexpr (OES_MEM_SIZE >= 32) {
                for (int col = 0; col < 4; col++) {
                    quarter_round(st[col], st[col + 4], st[col + 8], st[col + 12]);
                }
                // Diagonal mixing
                quarter_round(st[0], st[5], st[10], st[15]);
                quarter_round(st[1], st[6], st[11], st[12]);
                quarter_round(st[2], st[7], st[8], st[13]);
                quarter_round(st[3], st[4], st[9], st[14]);
            }
        }
    }

    m_block PRNG::next() {
        m_block ctr = (counter++) * PRNG_MULT1;
        ctr ^= ctr >> OES_HALF_MEM_SIZE;
        const size_t ctrIdx = static_cast<size_t>(ctr) & 15;
        m_block *st = state;

        // Inizializzazione da counter e state
        m_block L = st[ctrIdx] ^ ctr ^ accumulator;
        m_block R = st[(ctrIdx + 7) & 15] ^ (LCG_MULT * ctr + LCG_INC);
        //R ^= R >> S1;

        // Costanti ottimizzate per dimensione
        constexpr int ROUNDS = (OES_MEM_SIZE <= 16) ? 6 : (OES_MEM_SIZE <= 32) ? 8 : 10;

#pragma unroll
        for (int r = 0; r < ROUNDS; r++) {
            const size_t b0 = (ctrIdx + static_cast<size_t>(r)) & 15;
            const size_t b1 = (static_cast<size_t>(r) + 2) & 15;

            L ^= mBlock::rotl(st[b0], ROT1);
            R ^= mBlock::rotl(st[b1], static_cast<size_t>(ctr));

            L ^= mBlock::rotl(st[(b0 + 1) & 15], ROT1 + 1);
            R ^= mBlock::rotl(st[(b1 + 1) & 15], static_cast<size_t>(ctr + 1));

            L ^= mBlock::rotl(st[(b0 + 2) & 15], ROT1 + 2);
            R ^= mBlock::rotl(st[(b1 + 2) & 15], static_cast<size_t>(ctr + 2));

            L ^= mBlock::rotl(st[(b0 + 3) & 15], ROT1 + 3);
            R ^= mBlock::rotl(st[(b1 + 3) & 15], static_cast<size_t>(ctr + 3));

            // Mixing moltiplicativo
            L *= PRNG_MULT1;
            L ^= L >> S1;

            // Rotazioni per diffusione completa
            L = mBlock::rotl(L, ROT3);
            R = mBlock::rotl(R, ROT2);

            // Cross-mixing (cruciale per avalanche)
            L ^= mBlock::rotl(R, (r + 1) & OES_MEM_SIZE_MASK);
            R ^= mBlock::rotl(L, (r + 3) & OES_MEM_SIZE_MASK);
            L += R;
            R ^= mBlock::rotl(L, ROT3);

            // Iniezione addizionale ogni 4 round
            if ((r & 3) == 3) {
                L ^= st[(ctrIdx + static_cast<size_t>(r)) & 15];
                R *= PRNG_MULT2;
                R ^= R >> S2;
            }
        }

        // === Final non-bijective whitening ===
        m_block result = L ^ R;
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
        if ((static_cast<uint64_t>(ctr) & 3) == 0) {
            st[static_cast<size_t>((ctr >> 2) & 15)] ^= accumulator;
        }

        return result;
    }
}
