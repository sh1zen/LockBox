#include <cstdio>

#include "hashing.h"
#include "constants.h"
#include "oesMath.h"
#include "raw-layer.h"

alignas(64) constexpr uint8_t OESHasher::SBOX64[64] = {
    0x02, 0x03, 0x23, 0x3C, 0x33, 0x29, 0x1D, 0x2E,
    0x3B, 0x27, 0x36, 0x1E, 0x2C, 0x2A, 0x14, 0x1B,
    0x3F, 0x34, 0x31, 0x25, 0x18, 0x21, 0x0C, 0x1A,
    0x15, 0x0D, 0x16, 0x20, 0x09, 0x37, 0x2F, 0x04,
    0x3D, 0x00, 0x19, 0x17, 0x3A, 0x0B, 0x30, 0x11,
    0x0F, 0x2D, 0x32, 0x07, 0x05, 0x1C, 0x0E, 0x2B,
    0x28, 0x06, 0x24, 0x10, 0x08, 0x1F, 0x13, 0x3E,
    0x26, 0x0A, 0x39, 0x38, 0x35, 0x12, 0x01, 0x22
};

alignas(64) constexpr uint8_t OESHasher::ROT3D[4][4][4] = {
    {{52, 9, 51, 6}, {33, 2, 13, 53}, {47, 50, 49, 7}, {18, 48, 35, 14}},
    {{4, 21, 3, 62}, {41, 38, 32, 46}, {42, 57, 25, 30}, {45, 39, 11, 44}},
    {{43, 55, 23, 26}, {10, 40, 54, 5}, {61, 56, 60, 0}, {15, 16, 1, 34}},
    {{36, 63, 19, 59}, {17, 29, 12, 22}, {31, 20, 24, 37}, {28, 27, 58, 8}}
};

alignas(64) constexpr uint8_t OESHasher::PI_BOX[64] = {
    3, 4, 18, 30, 57, 40, 17, 13, 11, 16, 36, 54, 43, 1, 6, 12,
    23, 24, 27, 21, 22, 58, 26, 29, 47, 46, 53, 44, 37, 38, 39, 48,
    9, 31, 62, 56, 60, 50, 42, 35, 19, 45, 8, 41, 25, 10, 15, 32,
    55, 5, 33, 34, 49, 28, 61, 52, 63, 51, 0, 14, 20, 2, 59, 7
};

alignas(64) constexpr m_block OESHasher::ROUND_CONSTANTS[32] = {
    MASK_TO_BLOCK_SIZE(0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL), // ∛2, ∛3
    MASK_TO_BLOCK_SIZE(0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL), // ∛5, ∛7
    MASK_TO_BLOCK_SIZE(0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL), // ∛11, ∛13
    MASK_TO_BLOCK_SIZE(0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL), // ∛17, ∛19
    MASK_TO_BLOCK_SIZE(0xD807AA98A3030242ULL, 0x12835B0145706FBEULL), // ∛23, ∛29
    MASK_TO_BLOCK_SIZE(0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL), // ∛31, ∛37
    MASK_TO_BLOCK_SIZE(0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL), // ∛41, ∛43
    MASK_TO_BLOCK_SIZE(0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL), // ∛47, ∛53
    MASK_TO_BLOCK_SIZE(0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL), // ∛59, ∛61
    MASK_TO_BLOCK_SIZE(0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL), // ∛67, ∛71
    MASK_TO_BLOCK_SIZE(0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL), // ∛73, ∛79
    MASK_TO_BLOCK_SIZE(0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL), // ∛83, ∛89
    MASK_TO_BLOCK_SIZE(0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL), // ∛97, ∛101
    MASK_TO_BLOCK_SIZE(0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL), // ∛103, ∛107
    MASK_TO_BLOCK_SIZE(0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL), // ∛109, ∛113
    MASK_TO_BLOCK_SIZE(0x06CA6351E003826FULL, 0x142929670A0E6E70ULL), // ∛127, ∛131
    MASK_TO_BLOCK_SIZE(0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL), // ∛137, ∛139
    MASK_TO_BLOCK_SIZE(0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL), // ∛149, ∛151
    MASK_TO_BLOCK_SIZE(0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL), // ∛157, ∛163
    MASK_TO_BLOCK_SIZE(0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL), // ∛167, ∛173
    MASK_TO_BLOCK_SIZE(0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL), // ∛179, ∛181
    MASK_TO_BLOCK_SIZE(0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL), // ∛191, ∛193
    MASK_TO_BLOCK_SIZE(0xD192E819D6EF5218ULL, 0xD69906245565A910ULL), // ∛197, ∛199
    MASK_TO_BLOCK_SIZE(0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL), // ∛211, ∛223
    MASK_TO_BLOCK_SIZE(0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL), // ∛227, ∛229
    MASK_TO_BLOCK_SIZE(0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL), // ∛233, ∛239
    MASK_TO_BLOCK_SIZE(0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL), // ∛241, ∛251
    MASK_TO_BLOCK_SIZE(0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL), // ∛257, ∛263
    MASK_TO_BLOCK_SIZE(0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL), // ∛269, ∛271
    MASK_TO_BLOCK_SIZE(0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL), // ∛277, ∛281
    MASK_TO_BLOCK_SIZE(0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL), // ∛283, ∛293
    MASK_TO_BLOCK_SIZE(0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL) // ∛307, ∛311
};

// Shift proporzionali alla dimensione (evita 0)
constexpr size_t SMIX_S1 = (OES_MEM_SIZE * 30) / 64 + 1;
constexpr size_t SMIX_S2 = (OES_MEM_SIZE * 27) / 64 + 1;
constexpr size_t SMIX_S3 = (OES_MEM_SIZE * 31) / 64 + 1;


// ============================================================================
// COSTRUTTORE
// ============================================================================

OESHasher::OESHasher() {
    initHashConstants();
    resetState();
}

// ============================================================================
// FUNZIONI DI MIXING
// ============================================================================

m_block OESHasher::smix(m_block x) {
    x += SMIX_ADD;
    x = (x ^ (x >> SMIX_S1)) * SMIX_MUL1;
    x = (x ^ (x >> SMIX_S2)) * SMIX_MUL2;
    return x ^ (x >> SMIX_S3);
}

// ============================================================================
// INIZIALIZZAZIONE
// ============================================================================

void OESHasher::initHashConstants() {
#pragma unroll
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        m_hashConstants[i] = smix(i * INIT_MUL);
    }
}

void OESHasher::resetState() {
#pragma unroll
    for (m_block &i: m_state) {
        i = static_cast<m_block>(0);
    }
    resetCarry();
    m_domainCount = 0;  // <-- Aggiungi questo reset
}

// ============================================================================
// GESTIONE CARRY VETTORIALE
// ============================================================================

void OESHasher::resetCarry() {
#pragma unroll
    for (m_block &i: m_carry) {
        i = static_cast<m_block>(0);
    }
}

void OESHasher::initCarry(const size_t dataLen, const size_t hashLen, const m_block pad) {
    const m_block base = (hashLen ^ dataLen) * PHI_CONST;

    m_carry[0] = smix(base ^ STATE_SIZE);
    m_carry[1] = smix(mBlock::rotr(base, 17) ^ pad);
    m_carry[2] = smix(mBlock::rotl(base, 23) ^ (pad * PHI_CONST));
    m_carry[3] = smix(base ^ pad ^ ROUND_CONSTANTS[0]);
}

inline m_block OESHasher::derivePositionalCarry(size_t j) const {
    constexpr size_t mask = CARRY_SIZE - 1;
    const size_t idx = j & mask;

    const m_block c0 = m_carry[idx];
    const m_block c1 = m_carry[(idx + 1) & mask];
    const m_block c2 = m_carry[(idx + 2) & mask];
    const m_block c3 = m_carry[(idx + 3) & mask];

    const auto r1 = j * 7 & OES_MEM_SIZE_MASK;
    const auto r2 = j * 11 & OES_MEM_SIZE_MASK;

    return (mBlock::rotl(c0, r1) ^ mBlock::rotl(c1, r2)) + (c2 & c3);
}


void OESHasher::evolveCarry(const size_t round) {
    const size_t base = (round * 4) & STATE_MASK;

    m_block tmp[CARRY_SIZE];

    // Ogni carry si evolve con elementi diversi dello stato
    tmp[0] = m_carry[0] + (m_state[base] & m_state[(base + 1) & STATE_MASK]);
    tmp[0] ^= ~m_state[(base + 2) & STATE_MASK] & m_state[(base + 3) & STATE_MASK];

    tmp[1] = m_carry[1] ^ (m_state[(base + 16) & STATE_MASK] * (m_state[(base + 17) & STATE_MASK] | 1));
    tmp[1] += m_state[(base + 18) & STATE_MASK] | m_state[(base + 19) & STATE_MASK];

    tmp[2] = m_carry[2] + (m_state[(base + 32) & STATE_MASK] ^ m_state[(base + 33) & STATE_MASK]);
    tmp[2] ^= mBlock::rotl(m_state[(base + 34) & STATE_MASK], 13) & m_state[(base + 35) & STATE_MASK];

    tmp[3] = m_carry[3] ^ (~m_state[(base + 48) & STATE_MASK] & m_state[(base + 49) & STATE_MASK]);
    tmp[3] += mBlock::rotr(m_state[(base + 50) & STATE_MASK], 17) ^ m_state[(base + 51) & STATE_MASK];

    // Cross-mixing: ogni carry dipende dal precedente
    m_carry[0] = mBlock::rotr(tmp[0] ^ tmp[3], 7) + tmp[1];
    m_carry[1] = mBlock::rotr(tmp[1] ^ tmp[0], 13) ^ tmp[2];
    m_carry[2] = mBlock::rotr(tmp[2] ^ tmp[1], 19) + tmp[3];
    m_carry[3] = mBlock::rotr(tmp[3] ^ tmp[2], 31) ^ tmp[0];
}

m_block OESHasher::getFinalCarry() const {
    return m_carry[0] ^ m_carry[1] ^ m_carry[2] ^ m_carry[3];
}

// ============================================================================
// FASI DELL'HASHING
// ============================================================================

void OESHasher::absorbData(const MBLOCK *data, size_t dataLen, m_block pad) {
    for (size_t i = 0; i < MAX(closestMultiple(dataLen, 4), STATE_SIZE); i += 4) {
        auto d0 = (i < dataLen ? data->getBlock(i) : pad);
        auto d1 = (i + 1 < dataLen ? data->getBlock(i + 1) : pad);
        auto d2 = (i + 2 < dataLen ? data->getBlock(i + 2) : pad);
        auto d3 = (i + 3 < dataLen ? data->getBlock(i + 3) : pad);

        d0 = mBlock::rotr(d0, d1 & (OES_MEM_SIZE - 1));
        d1 = mBlock::rotr(d1, d2 & (OES_MEM_SIZE - 1));
        d2 = mBlock::rotr(d2, d3 & (OES_MEM_SIZE - 1));
        d3 = mBlock::rotr(d3, (i * 7 + 13) & (OES_MEM_SIZE - 1));

        const m_block route = i ^ m_state[(i + 7) & STATE_MASK] ^
                              mBlock::rotl(m_state[(i + 19) & STATE_MASK], 11) ^
                              (d0 | 1) * PHI_CONST;

        const auto r0 = SBOX64[route & STATE_MASK];
        const auto r1 = SBOX64[(route + 1) & STATE_MASK];
        const auto r2 = SBOX64[(route + 2) & STATE_MASK];
        const auto r3 = SBOX64[(route + 3) & STATE_MASK];

        m_state[r0] += ((m_hashConstants[r1] + d0) ^ (~d1 & d2)) * PHI_CONST;
        m_state[r1] ^= (m_hashConstants[r0] * d1) ^ (~d2 & d3);
        m_state[r2] ^= (m_hashConstants[r3] + d2) ^ (~d3 & d0);
        m_state[r3] += (m_hashConstants[r2] * d3) ^ (~d0 & d1);
    }
}

void OESHasher::applyDomainSeparation() {
    ++m_domainCount;

    m_state[0] ^= 0x1F ^ smix(m_domainCount);
    m_state[STATE_MASK] ^= 0x80 ^ smix(m_domainCount);
}

// ============================================================================
// PERMUTAZIONE (θ, π, ρ, χ)
// ============================================================================

inline void OESHasher::thetaMixColumns(m_block *s) {
    m_block C[8], D[8];

#pragma unroll
    for (size_t x = 0; x < 8; x++) {
        const m_block *col = s + x;
        C[x] = col[0] ^ col[8] ^ col[16] ^ col[24] ^ col[32] ^ col[40] ^ col[48] ^ col[56];
    }

#pragma unroll
    for (size_t x = 0; x < 8; x++) {
        D[x] = mBlock::rotl(C[(x + 1) & 7], 1) ^ C[(x + 7) & 7];
    }

#pragma unroll
    for (size_t y = 0; y < 8; y++) {
        m_block *row = s + (y << 3);
        for (size_t x = 0; x < 8; ++x) {
            row[x] ^= D[x];
        }
    }
}

inline void OESHasher::piRhoTransform(m_block *s, m_block *tmp) {
#pragma unroll
    for (size_t i = 0; i < 64; ++i) {
        const uint8_t rot = ROT3D[i >> 4][(i >> 2) & 3][i & 3];
        tmp[PI_BOX[i]] = mBlock::rotl(s[i], rot);
    }
}

inline void OESHasher::chiNonlinear(m_block *s, const m_block *tmp) {
    m_block t[8];

#pragma unroll
    for (size_t y = 0; y < 8; y++) {
        const size_t row = y << 3;

#pragma unroll
        for (size_t i = 0; i < 8; i++) {
            const m_block chi_row = mBlock::rotl(
                tmp[row + i] ^ (~tmp[row + ((i + 1) & 7)] & tmp[row + ((i + 2) & 7)]),
                (i * 7 + 3) & (OES_MEM_SIZE - 1)
            );

            const m_block chi_col = tmp[y * 8 + i] ^ (~tmp[((y + 1) & 7) * 8 + i] & tmp[((y + 2) & 7) * 8 + i]);

            t[i] = (chi_row * (tmp[row + i] | 1)) ^ mBlock::rotl(chi_col, (i * 7 + row) & 63) + (chi_row & chi_col);
        }

#pragma unroll
        for (size_t i = 0; i < 8; i++) {
            s[row + i] = t[i];
        }
    }
}

inline void OESHasher::permute(const size_t round) {
    m_block tmp[STATE_SIZE];

    m_state[0] ^= ROUND_CONSTANTS[round & 31];

    thetaMixColumns(m_state);
    piRhoTransform(m_state, tmp);
    chiNonlinear(m_state, tmp);
}

inline void OESHasher::squeezeRounds(m_block *hash, size_t hashLen) {
    for (size_t i = 0; i < NUM_ROUNDS; i++) {
        permute(i);

        if ((i & 3) == 3) {
            m_block feedback = 0;

            for (size_t j = 0; j < hashLen; j++) {
                // Carry unico per questa posizione
                const m_block localCarry = derivePositionalCarry(j) ^ feedback;

                // Aggiorna hash
                hash[j] ^= m_state[j & STATE_MASK] ^ localCarry;

                // Feedback per prossima posizione (dipendenza seriale)
                feedback = mBlock::rotl(feedback ^ hash[j], 5);
            }

            // Inietta feedback nei carry
            m_carry[i & (CARRY_SIZE - 1)] ^= feedback;
        }

        // Evolvi carry ad ogni round
        evolveCarry(i);
    }
}

inline void OESHasher::finalize(m_block *hash, size_t hashLen) {
    permute(NUM_ROUNDS);

    const m_block finalCarry = getFinalCarry();

    for (size_t i = 0; i < hashLen; ++i) {
        const m_block posCarry = derivePositionalCarry(i);

        hash[i] ^= m_state[i & STATE_MASK];
        hash[i] += mBlock::rotr(posCarry ^ m_state[(i + 32) & STATE_MASK], (i * 7) & (OES_MEM_SIZE - 1));

        // Mixing finale extra con carry combinato
        hash[i] ^= mBlock::rotl(finalCarry, (i * 11) & 63);
    }
}

inline void OESHasher::mixIV(m_block *hash, size_t hashLen, MBLOCK **iv) {
    if (!iv || !*iv || (*iv)->isNull()) return;

    m_state[0] ^= 0xA4; // DOMAIN_IV

    MBLOCK *ivBlock = *iv;
    const size_t ivLen = ivBlock->getLen();

    if (ivLen == 0) return;

    for (size_t i = 0; i < hashLen; ++i) {
        const m_block v = ivBlock->getBlock(i % ivLen);
        hash[i] ^= mBlock::rotr(v, static_cast<uint32_t>(i & (OES_MEM_SIZE - 1)));
    }

    for (size_t i = 0; i < ivLen; ++i) {
        const m_block v = ivBlock->getBlock(i) + hash[i % hashLen];
        ivBlock->setBlock(i, mBlock::rotr(v, 13) ^ hash[(i + 1) % hashLen]);
    }
}

// ============================================================================
// API PUBBLICA
// ============================================================================

MBLOCK *OESHasher::hash(const MBLOCK *data, size_t hashLen, MBLOCK **iv) {
    if (!data || data->isNull() || hashLen == 0) return nullptr;

    const size_t dataLen = data->getLen();
    if (dataLen == 0 || hashLen > MAX_HASH_LEN) {
        return nullptr;
    }

    // Reset e inizializzazione
    resetState();

    auto *hashOut = new m_block[hashLen](static_cast<m_block>(0));

    const m_block pad = MASK_TO_BLOCK_SIZE(0x8000000000000000, 0x0000000000000000) ^
                        static_cast<m_block>(dataLen) ^
                        (static_cast<m_block>(hashLen) << 1 | 1);

    // Inizializza carry vettoriale
    initCarry(dataLen, hashLen, pad);

    permute(0);
    permute(1);
    permute(dataLen + 2);
    permute(hashLen + 3);


    // Pipeline di hashing
    absorbData(data, dataLen, pad);
    applyDomainSeparation();
    squeezeRounds(hashOut, hashLen);
    finalize(hashOut, hashLen);
    applyDomainSeparation();
    mixIV(hashOut, hashLen, iv);

    return new MBLOCK(hashOut, hashLen, true);
}

// ============================================================================
// DEBUG
// ============================================================================

void OESHasher::dumpState(const char *label) const {
    printf("\n");
    if (label) {
        printf("=== %s ===\n", label);
    }

    printf("    ");
    for (int x = 0; x < 8; ++x) {
        printf("   Col%d    ", x);
    }
    printf("\n");

    for (int y = 0; y < 8; ++y) {
        printf("R%d: ", y);
        for (int x = 0; x < 8; ++x) {
            printf("%10lu ", static_cast<unsigned long>(m_state[y * 8 + x]));
        }
        printf("\n");
    }

    printf("\nCarry[4]: ");
    for (m_block i: m_carry) {
        printf("%10lu ", static_cast<unsigned long>(i));
        printf(" ");
    }
    printf("\n");
}
