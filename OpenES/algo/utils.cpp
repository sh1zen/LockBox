#include <memory>

#include "hashing.h"
#include "m_block.h"
#include "raw-layer.h"
#include "constants.h"

/**
 * Mix function ottimizzata
 */
static inline m_block mix(m_block x) {
    x = pseudoHadamardT(x);
    return x ^ mBlock::rotl(x, 7) ^ mBlock::rotr(x, 11);
}

/**
 * Global diffusion
 */
void global_diffuse(MBLOCK *data, const m_block seed) {
    if (!data || data->isNull()) return;

    const size_t len = data->getLen();
    if (len < 2) return;

    const m_block k0 = seed;
    const m_block k1 = seed ^ DIFFUSE_CONST;
    const m_block k2 = seed ^ mBlock::rotl(DIFFUSE_CONST, 1);

    // Pass 1: forward
    m_block prev = k0;
    for (size_t i = 0; i < len; ++i) {
        const m_block cur = data->getBlock(i);
        data->setBlock(i, cur ^ mix(prev));
        prev = cur;
    }

    // Pass 2: backward
    m_block next = k1;
    for (size_t i = len; i-- > 0;) {
        const m_block cur = data->getBlock(i);
        data->setBlock(i, cur ^ mix(next));
        next = cur;
    }

    // Pass 3: forward
    prev = k2;
    for (size_t i = 0; i < len; ++i) {
        const m_block cur = data->getBlock(i);
        data->setBlock(i, cur ^ mix(prev));
        prev = cur;
    }
}

/**
 * Inverse diffusion
 */
void global_diffuse_inv(MBLOCK *data, m_block seed) {
    if (!data || data->isNull()) return;

    const size_t len = data->getLen();
    if (len < 2) return;

    const m_block k0 = seed;
    const m_block k1 = seed ^ DIFFUSE_CONST;
    const m_block k2 = seed ^ mBlock::rotl(DIFFUSE_CONST, 1);

    // Undo pass 3
    m_block prev = k2;
    for (size_t i = 0; i < len; ++i) {
        const m_block cur = data->getBlock(i) ^ mix(prev);
        data->setBlock(i, cur);
        prev = cur;
    }

    // Undo pass 2
    m_block next = k1;
    for (size_t i = len; i-- > 0;) {
        const m_block cur = data->getBlock(i) ^ mix(next);
        data->setBlock(i, cur);
        next = cur;
    }

    // Undo pass 1
    prev = k0;
    for (size_t i = 0; i < len; ++i) {
        const m_block cur = data->getBlock(i) ^ mix(prev);
        data->setBlock(i, cur);
        prev = cur;
    }
}

MBLOCK* oes_raw_hmac(const MBLOCK* key, const MBLOCK* data, const size_t hmacLen) {
    if (!key || key->isNull() || !data || data->isNull() || hmacLen == 0) {
        return nullptr;
    }

    OESHasher hasher;

    // 1) Hash della chiave per ottenere una chiave fissa
    const std::unique_ptr<MBLOCK> h_key(hasher.hash(key, hmacLen, nullptr));
    if (!h_key) return nullptr;

    // 2) Creazione dei pad
    const std::unique_ptr<MBLOCK> ipad(MBLOCK::create(hmacLen, REPLICATE_BITS(0x3636)));
    const std::unique_ptr<MBLOCK> opad(MBLOCK::create(hmacLen, REPLICATE_BITS(0x5c5c)));
    if (!ipad || !opad) return nullptr;

    // 3) XOR con la chiave hashata
    ipad->xor_with(*h_key);
    opad->xor_with(*h_key);

    // 4) inner_hash = hash(ipad || data)
    const std::unique_ptr<MBLOCK> inner_concat(MBLOCK::concat(*ipad, *data));
    if (!inner_concat) return nullptr;

    const std::unique_ptr<MBLOCK> inner_hash(hasher.hash(inner_concat.get(), hmacLen, nullptr));
    if (!inner_hash) return nullptr;

    // 5) Final HMAC = hash(opad || inner_hash)
    const std::unique_ptr<MBLOCK> outer_concat(MBLOCK::concat(*opad, *inner_hash));
    if (!outer_concat) return nullptr;

    return hasher.hash(outer_concat.get(), hmacLen, nullptr);
}
