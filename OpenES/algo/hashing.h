#pragma once

#include "m_block.h"

class OESHasher {
public:
    // Costanti
    static constexpr size_t STATE_SIZE = 64;
    static constexpr size_t STATE_MASK = STATE_SIZE - 1;
    static constexpr size_t NUM_ROUNDS = 32;
    static constexpr size_t MAX_HASH_LEN = 2048;
    static constexpr size_t CARRY_SIZE = 4;

    // Costruttore
    OESHasher();

    // API Pubblica
    MBLOCK* hash(const MBLOCK* data, size_t hashLen, MBLOCK** iv = nullptr);

    // Debug
    void dumpState(const char* label = nullptr) const;

private:
    // Stato interno
    m_block m_state[STATE_SIZE]{};
    m_block m_hashConstants[STATE_SIZE]{};
    m_block m_carry[CARRY_SIZE]{};  // Carry vettoriale invece di scalare

    size_t m_domainCount = 0;

    // Tabelle statiche
    static const uint8_t SBOX64[64];
    static const uint8_t ROT3D[4][4][4];
    static const uint8_t PI_BOX[64];
    static const m_block ROUND_CONSTANTS[32];

    // Funzioni di mixing
    static m_block smix(m_block x);

    // Inizializzazione
    void initHashConstants();
    void resetState();

    // Gestione Carry Vettoriale
    void resetCarry();
    void initCarry(size_t dataLen, size_t hashLen, m_block pad);
    [[nodiscard]] m_block derivePositionalCarry(size_t j) const;
    void evolveCarry(size_t round);
    [[nodiscard]] m_block getFinalCarry() const;

    // Fasi dell'hashing
    void absorbData(const MBLOCK* data, size_t dataLen, m_block pad);
    void applyDomainSeparation();

    // Permutazione
    static void thetaMixColumns(m_block* s);
    static void piRhoTransform(m_block* s, m_block* tmp);
    static void chiNonlinear(m_block* s, const m_block* tmp);
    void permute(size_t round);

    // Output
    void squeezeRounds(m_block* hash, size_t hashLen);
    void finalize(m_block* hash, size_t hashLen);
    void mixIV(m_block* hash, size_t hashLen, MBLOCK** iv);
};
