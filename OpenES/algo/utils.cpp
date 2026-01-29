#include "utils.h"

#include <memory>

#include "hashing.h"
#include "m_block.h"

MBLOCK *oes_raw_hmac(const MBLOCK *key, const MBLOCK *data, const size_t hmacLen) {
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
