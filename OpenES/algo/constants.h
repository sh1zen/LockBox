#pragma once

constexpr m_block PHI_CONST = MASK_TO_BLOCK_SIZE(0x9E3779B97F4A7C15ULL, 0xF39CC0605CEDC834ULL);

// High: frac(√11) * 2^64, Low: frac(√13) * 2^64
// Peso combinato ~64/128
constexpr m_block DIFFUSE_CONST = MASK_TO_BLOCK_SIZE(0x54A6B2C94D5A6C3BULL, 0x6A4D3B2A5C6D7E8FULL);

constexpr m_block SMIX_ADD = MASK_TO_BLOCK_SIZE(0x6A09E667F3BCC908ULL, 0x510E527FADE682D1ULL);
constexpr m_block SMIX_MUL1 = MASK_TO_BLOCK_SIZE(0xBB67AE8584CAA73BULL, 0x9B05688C2B3E6C1FULL) | 1;
constexpr m_block SMIX_MUL2 = MASK_TO_BLOCK_SIZE(0x3C6EF372FE94F82BULL, 0x1F83D9ABFB41BD6BULL) | 1;
constexpr m_block INIT_MUL = MASK_TO_BLOCK_SIZE(0xA54FF53A5F1D36F1ULL, 0x5BE0CD19137E2179ULL) | 1;

constexpr m_block PRNG_SEED = MASK_TO_BLOCK_SIZE(0xB5AD4ECEDA1CE2A9ULL, 0x6A09E667F3BCC908ULL);

#if OES_MEM_SIZE == 8
// x^8 + x^4 + x^3 + x + 1 (AES S-box, Rijndael)
// Primitivo, peso 5, standard
constexpr m_block RED_POLY = 0x1B; // 0x11B senza bit 8

// √3 * 2^8 ≈ 219, 6 bit set
constexpr m_block PERM_CONST = 0xDB;

constexpr m_block PRNG_MULT1 = 0x65; // 101 = 4*25+1, dispari, buoni bit
constexpr m_block PRNG_MULT2 = 0x5D; // 93 = 4*23+1, dispari
constexpr m_block MIX_CONST = 0x9B; // 10011011 - irregolare, 5 bit set

#elif OES_MEM_SIZE == 16
// x^16 + x^12 + x^3 + x + 1
// Primitivo, peso 5
constexpr m_block RED_POLY = 0x100B; // 0x1100B senza bit 16

// √3 * 2^16, 11 bit set
constexpr m_block PERM_CONST = 0xDDB3;

constexpr m_block PRNG_MULT1 = 0x7D65; // 32101 = 4*8025+1
constexpr m_block PRNG_MULT2 = 0x5E5D; // 24157 = 4*6039+1
constexpr m_block MIX_CONST = 0x9B6D; // irregolare, buona densità

#elif OES_MEM_SIZE == 32
// x^32 + x^7 + x^3 + x^2 + 1 (CRC-32C iSCSI, Castagnoli)
// Primitivo, peso 5, supporto hardware (SSE4.2)
constexpr m_block RED_POLY = 0x8D; // 0x1'0000'008D senza bit 32

// √3 * 2^32, 18 bit set
constexpr m_block PERM_CONST = 0xDDB3D742;

constexpr m_block PRNG_MULT1 = 0x93D765D5; // ≡ 1 (mod 4), SplitMix-like
constexpr m_block PRNG_MULT2 = 0x7FEB3525; // ≡ 1 (mod 4)
constexpr m_block MIX_CONST = 0xB5297A4D; // alta densità, pattern irregolare

#elif OES_MEM_SIZE == 64
// x^64 + x^4 + x^3 + x + 1 (GCM, GHASH)
// Primitivo, peso 5, standard NIST
constexpr m_block RED_POLY = 0x1BULL; // 0x1'0000'0000'0000'001B senza bit 64

// √3 * 2^64
constexpr m_block PERM_CONST = 0xDDB3D742C265539EULL;

constexpr m_block PRNG_MULT1 = 0xBF58476D1CE4E5B9ULL; // da SplitMix64
constexpr m_block PRNG_MULT2 = 0x94D049BB133111EBULL; // da SplitMix64
constexpr m_block MIX_CONST = 0x9E3779B97F4A7C15ULL; // golden ratio * 2^64

#else // OES_MEM_SIZE == 128
// x^128 + x^7 + x^2 + x + 1 (GCM-128, GHASH)
// Primitivo, peso 5, standard NIST SP 800-38D
constexpr m_block RED_POLY = MASK_TO_BLOCK_SIZE(0x0ULL, 0x87ULL); // solo low bits

constexpr m_block PERM_CONST = MASK_TO_BLOCK_SIZE(0xDDB3D742C265539EULL, 0x9E3779B97F4A7C15ULL);

constexpr m_block PRNG_MULT1 = MASK_TO_BLOCK_SIZE(0xBF58476D1CE4E5B9ULL, 0x94D049BB133111EBULL);
constexpr m_block PRNG_MULT2 = MASK_TO_BLOCK_SIZE(0x94D049BB133111EBULL, 0xBF58476D1CE4E5B9ULL);
constexpr m_block MIX_CONST = MASK_TO_BLOCK_SIZE(0x9E3779B97F4A7C15ULL, 0xF39CC0605CEDC834ULL);

#endif
