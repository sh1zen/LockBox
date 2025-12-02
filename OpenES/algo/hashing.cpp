#include <memory>

#include "hashing.h"


MBLOCK *oes_raw_hash(const MBLOCK *data, size_t hashLen, MBLOCK **iv) {
    if (!data || data->isNull() || hashLen == 0) return nullptr;

    size_t dataLen = data->getLen();
    const size_t pageSize = MAX(dataLen, OES_NUM_OF_BLOCK);

    // --- Allocate temporary buffers ---
    auto *w = new m_block[pageSize]();
    auto *hash = new m_block[hashLen]();

    // Copy input data into w
    for (size_t i = 0; i < dataLen; ++i) {
        w[i] = data->getBlock(i);
    }

    // --- Translator local variables ---
    m_block t0 = MASK_TO_BLOCK_SIZE(0x6a09e667, 0x6a09e667);
    m_block t1 = MASK_TO_BLOCK_SIZE(0xbb67ae85, 0xbb67ae85);
    m_block t2 = MASK_TO_BLOCK_SIZE(0x3c6ef372, 0x3c6ef372);
    m_block t3 = MASK_TO_BLOCK_SIZE(0xa54ff53a, 0xa54ff53a);
    m_block t4 = MASK_TO_BLOCK_SIZE(0x510e527f, 0x510e527f);
    m_block t5 = MASK_TO_BLOCK_SIZE(0x9b05688c, 0x9b05688c);
    m_block t6 = MASK_TO_BLOCK_SIZE(0x1f83d9ab, 0x1f83d9ab);
    m_block t7 = MASK_TO_BLOCK_SIZE(0x5be0cd19, 0x5be0cd19);

    // --- Extend message schedule ---
    for (size_t i = 16; i < pageSize; ++i) {
        const m_block w15 = w[i - 15];
        const m_block w2 = w[i - 2];

        const m_block s0 = mBlock_rotr(w15, 7) ^ mBlock_rotr(w15, 18) ^ (w15 >> 3);
        const m_block s1 = mBlock_rotr(w2, 17) ^ mBlock_rotr(w2, 19) ^ (w2 >> 10);

        w[i] = w[i - 16] + w[i - 7] + s0 + s1;
    }

    // --- Compression rounds ---
    const size_t maxIter = MAX(pageSize, hashLen);
    for (size_t i = 0; i < maxIter; ++i) {
        const size_t wp = i % pageSize;
        const size_t hp = i % hashLen;

        const m_block k = w[wp];

        const m_block S1 = mBlock_rotr(t4, 6) ^ mBlock_rotr(t4, 11) ^ mBlock_rotr(t4, 25);
        const m_block ch = (t4 & t5) ^ ((~t4) & t6);

        const m_block S0 = mBlock_rotr(t0, 2) ^ mBlock_rotr(t0, 13) ^ mBlock_rotr(t0, 22);
        const m_block maj = (t0 & t1) ^ (t0 & t2) ^ (t1 & t2);

        const m_block temp1 = t7 + S1 + ch + k;
        const m_block temp2 = S0 + maj;

        t7 = t6;
        t6 = t5;
        t5 = t4;
        t4 = t3 + temp1;
        t3 = t2;
        t2 = t1;
        t1 = t0;
        t0 = temp1 + temp2;

        hash[hp] = mBlock_rotr(hash[hp], i & 31) + t0;
    }

    // --- Optional IV mix ---
    if (iv && *iv && !(*iv)->isNull()) {
        MBLOCK *ivBlock = *iv;
        const size_t ivLen = ivBlock->getLen();

        for (size_t i = 0; i < hashLen; ++i) {
            ivBlock->rotr(i % ivLen);
            hash[i] ^= ivBlock->getBlock(i % ivLen);
        }

        for (size_t i = 0; i < ivLen; ++i) {
            m_block v = ivBlock->getBlock(i);
            const m_block h = hash[i % hashLen];

            v = (v + mBlock_rotr(h, i % 17)) ^ (h + mBlock_rotr(v, i % 11));
            ivBlock->setBlock(i, v);
        }
    }

    // --- Free temporary buffer ---
    delete[] w;

    // --- Create MBLOCK result ---
    return new MBLOCK(hash, hashLen, true);
}


MBLOCK *oes_raw_hmac(const MBLOCK *key, const MBLOCK *data, size_t hmacLen) {
    if (!key || key->isNull() || !data || data->isNull() || hmacLen == 0) {
        return nullptr;
    }

    // 1) Hash del key per ottenere una chiave fissa
    std::unique_ptr<MBLOCK> h_key(oes_raw_hash(key, hmacLen, nullptr));
    if (!h_key) {
        return nullptr;
    }

    // 2) Creazione dei pad
    std::unique_ptr<MBLOCK> ipad(MBLOCK::create(hmacLen, MASK_TO_BLOCK_SIZE(0x36363636, 0x36363636)));
    std::unique_ptr<MBLOCK> opad(MBLOCK::create(hmacLen, MASK_TO_BLOCK_SIZE(0x5c5c5c5c, 0x5c5c5c5c)));

    if (!ipad || !opad) {
        return nullptr;
    }

    // 3) XOR con la chiave hashata
    ipad->xor_with(*h_key);
    opad->xor_with(*h_key);

    // 4) Concatenazione (ipad || data)
    std::unique_ptr<MBLOCK> inner_concat(MBLOCK::concat(*ipad, *data));
    if (!inner_concat) {
        return nullptr;
    }

    // 5) inner_hash = hash(ipad || data)
    std::unique_ptr<MBLOCK> inner_hash(oes_raw_hash(inner_concat.get(), hmacLen, nullptr));
    if (!inner_hash) {
        return nullptr;
    }

    // 6) outer_concat = opad || inner_hash
    std::unique_ptr<MBLOCK> outer_concat(MBLOCK::concat(*opad, *inner_hash));
    if (!outer_concat) {
        return nullptr;
    }

    // 7) Final HMAC = hash(opad || inner_hash)
    MBLOCK *final_hmac = oes_raw_hash(outer_concat.get(), hmacLen, nullptr);

    // Tutti gli MBLOCK temporanei vengono distrutti automaticamente
    return final_hmac;
}
