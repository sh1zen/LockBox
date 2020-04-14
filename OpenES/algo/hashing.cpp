#include <memory>
#include <cstdlib>

#include "hashing.h"


m_block *oes_raw_hash(const m_block *data, size_t dataLen, size_t hashLen, OES_BLOCK *iv) {
    const size_t pageSize = MAX(dataLen, OES_BLOCK_SIZE);

    // allocate w[]
    std::unique_ptr<m_block[]> w(new(std::nothrow) m_block[pageSize]);
    if (!w) return nullptr;
    std::fill_n(w.get(), pageSize, 0);

    mBlock_clone(w.get(), data, dataLen);

    // allocate hash[]
    std::unique_ptr<m_block[]> hash(new(std::nothrow) m_block[hashLen]);
    if (!hash) return nullptr;
    std::fill_n(hash.get(), hashLen, 0);

    // Translator come variabili locali (massima ottimizzazione)
    m_block t0 = 0x6a09e667;
    m_block t1 = 0xbb67ae85;
    m_block t2 = 0x3c6ef372;
    m_block t3 = 0xa54ff53a;
    m_block t4 = 0x510e527f;
    m_block t5 = 0x9b05688c;
    m_block t6 = 0x1f83d9ab;
    m_block t7 = 0x5be0cd19;

    // extend message schedule
    for (size_t i = 16; i < pageSize; ++i) {
        const m_block w15 = w[i - 15];
        const m_block w2 = w[i - 2];

        const m_block s0 = mBlock_rotr(w15, 7) ^ mBlock_rotr(w15, 18) ^ (w15 >> 3);
        const m_block s1 = mBlock_rotr(w2, 17) ^ mBlock_rotr(w2, 19) ^ (w2 >> 10);

        w[i] = w[i] + w[i - 16] + w[i - 7] + s0 + s1;
    }

    const size_t maxIter = MAX(pageSize, hashLen);

    for (size_t i = 0; i < maxIter; ++i) {
        const size_t wp = i % pageSize;
        const size_t hp = i % hashLen;

        const m_block k = w[wp];

        // Calcoli SHA-like
        const m_block S1 = mBlock_rotr(t4, 6) ^ mBlock_rotr(t4, 11) ^ mBlock_rotr(t4, 25);
        const m_block ch = (t4 & t5) ^ ((~t4) & t6);

        const m_block S0 = mBlock_rotr(t0, 2) ^ mBlock_rotr(t0, 13) ^ mBlock_rotr(t0, 22);
        const m_block maj = (t0 & t1) ^ (t0 & t2) ^ (t1 & t2);

        const m_block temp1 = t7 + S1 + ch + k;
        const m_block temp2 = S0 + maj;

        // rotate translator (molto più veloce su variabili locali)
        t7 = t6;
        t6 = t5; // FIX #4 corretto
        t5 = t4;
        t4 = t3 + temp1;
        t3 = t2;
        t2 = t1;
        t1 = t0;
        t0 = temp1 + temp2;

        // Aggiornamento hash (stessa logica con rotazione limitata)
        const uint32_t rot = (i & 31);
        hash[hp] = mBlock_rotr(hash[hp], rot) + t0;
    }

    // Optional IV mix
    if (iv && *iv) {
        OES_BLOCK blk = *iv;
        m_block *ivData = blk->data;
        const size_t ivLen = blk->len;

        for (size_t i = 0; i < hashLen; ++i) {
            const size_t ip = i % ivLen;
            mBlock_rotr_vec(ivData, ivLen, ip);
            hash[i] ^= ivData[ip];
        }

        for (size_t i = 0; i < ivLen; ++i) {
            m_block v = ivData[i];
            const m_block h = hash[i % hashLen];

            v = (v + mBlock_rotr(h, (i % 17))) ^ (h + mBlock_rotr(v, (i % 11)));
            ivData[i] = v;
        }
    }

    return hash.release();
}


m_block *oes_raw_hmac(const m_block *key, size_t keyLen, const m_block *data, size_t dataLen, size_t hmacLen) {
    if (!key || keyLen == 0 || !data || dataLen == 0 || hmacLen == 0)
        return nullptr;

    // 1) Hash della chiave per ottenere una chiave di lunghezza fissa
    m_block *h_key = oes_raw_hash(key, keyLen, hmacLen, nullptr);
    if (!h_key) {
        return nullptr;
    }

    // 2) Creazione pad
    m_block *ipad = mBlock_create(hmacLen, 0x36363636);
    m_block *opad = mBlock_create(hmacLen, 0x5c5c5c5c);

    if (!ipad || !opad) {
        delete[] h_key;
        free(ipad);
        free(opad);
        return nullptr;
    }

    // 3) XOR con la chiave hashed
    mBlock_xor(ipad, h_key, hmacLen);
    mBlock_xor(opad, h_key, hmacLen);

    // 4) Concatenazione (ipad || data)
    m_block *inner_concat = mBlock_concat(ipad, hmacLen, data, dataLen);
    if (!inner_concat) {
        delete[] h_key;
        free(ipad);
        free(opad);
        return nullptr;
    }

    // 5) inner_hash = hash(ipad || data)
    m_block *inner_hash = oes_raw_hash(inner_concat, hmacLen + dataLen, hmacLen, nullptr);
    free(inner_concat);

    if (!inner_hash) {
        delete[] h_key;
        free(ipad);
        free(opad);
        return nullptr;
    }

    // 6) outer_concat = opad || inner_hash
    m_block *outer_concat = mBlock_concat(opad, hmacLen, inner_hash, hmacLen);
    if (!outer_concat) {
        delete[] h_key;
        free(ipad);
        free(opad);
        delete[] inner_hash;
        return nullptr;
    }

    // 7) HMAC finale = hash(opad || inner_hash)
    m_block *final_hmac = oes_raw_hash(outer_concat, hmacLen * 2, hmacLen, nullptr);

    // --- cleanup ---
    free(outer_concat);
    delete[] inner_hash;
    delete[] h_key;
    free(ipad);
    free(opad);

    return final_hmac; // caller deve fare free (o delete[])
}
