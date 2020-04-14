#include "oesMath.h"

// ============================================================================
//  Utility: Align to closest upper multiple
// ============================================================================
size_t closestMultiple(size_t near, size_t multiple) {

    if (multiple == 0)
        return near; // Non possiamo dividere per zero

    const size_t remainder = near % multiple;
    return remainder == 0 ? near : (near + (multiple - remainder));
}

// ============================================================================
//  Count how many chunks of size "of" are needed to contain "number" bytes
// ============================================================================
size_t calcPairsOfSize(size_t number, size_t of) {
    if (of == 0) return 0; // Evitare divisione per zero
    return closestMultiple(number, of) / of;
}

// ============================================================================
//  Padding needed to complete block size "multiple"
// ============================================================================
uint8_t requestedPadding(size_t dataLen, uint8_t multiple) {
    if (multiple == 0) return 0; // edge-case
    return static_cast<uint8_t>((multiple - (dataLen % multiple)) % multiple);
}

// ============================================================================
//  Check if k-th bit is set (k = 1..bit_count)
// ============================================================================
bool isKthBitSet(m_block n, uint8_t k) {
    if (k == 0 || k > (sizeof(m_block) * 8))
        return false;
    return (n & (m_block(1) << (k - 1))) != 0;
}

// ============================================================================
//  Simple random generator with shuffle table (xorshift-like)
// ============================================================================
m_block randomGenerator(const m_block seed) {

    static m_block shuffle_table[4] = {0};
    static bool initialized = false;

    if (!initialized) {
        shuffle_table[0] = seed;
        shuffle_table[1] = deterministicRandomXorShift(seed);
        shuffle_table[2] = shuffle_table[0] ^ shuffle_table[1];
        shuffle_table[3] = shuffle_table[1] + shuffle_table[2];
        initialized = true;
    }

    m_block s1 = shuffle_table[0];
    const m_block s0 = shuffle_table[1];
    const m_block result = s0 + s1;

    shuffle_table[0] = s0;

    // Migliore distribuzione degli shift
    s1 ^= s1 << (OES_BYTES_X_BLOCK * 6 - 1);
    shuffle_table[1] = s1 ^ s0 ^
                       (s1 >> (OES_BYTES_X_BLOCK * 4 + 2)) ^
                       (s0 >> (OES_BYTES_X_BLOCK + 1));

    return result;
}

// ============================================================================
//  Deterministic xorshift (kept simple)
// ============================================================================
m_block deterministicRandomXorShift(m_block seed) {

    seed ^= seed << (OES_BYTES_X_BLOCK * 3 + 1);
    seed ^= seed >> (OES_BYTES_X_BLOCK * 2 - 1);
    seed ^= seed << (OES_BYTES_X_BLOCK * 4 + 1);
    return seed;
}

// ============================================================================
//  xTime (AES-like multiply-by-2 over each byte independently)
// ============================================================================
void xTimeMBlock(m_block *w)
{
    m_block a = *w;

    // Maschera bit più significativo di ogni byte
    m_block high = a & m_block(0x8080808080808080ULL);

    // Shift a sinistra per x2
    m_block shifted = (a & m_block(0x7F7F7F7F7F7F7F7FULL)) << 1;

    // Riduzione AES (0x1B su overflow di byte)
    m_block reduction = (high >> 7) * m_block(0x1B);

    *w = shifted ^ reduction;
}
