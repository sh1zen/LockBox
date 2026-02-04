#include "utils.h"

#include <cstring>
#include <iostream>
#include <memory>

#include "hashing.h"
#include "m_block.h"
#include "support.h"

namespace {
    constexpr m_block HMAC_IPAD = REPLICATE_BITS(0x3636);
    constexpr m_block HMAC_OPAD = REPLICATE_BITS(0x5c5c);

    bool hmac_from_prehashed_into_impl(OESHasher &hasher,
                                       const MBLOCK *prehashedKey,
                                       const MBLOCK *data,
                                       const size_t hmacLen,
                                       m_block *out) {
        if (!prehashedKey || prehashedKey->isNull() || !data || data->isNull() || !out || hmacLen == 0) {
            return false;
        }
        if (prehashedKey->getLen() != hmacLen) {
            return false;
        }

        const size_t dataLen = data->getLen();
        std::unique_ptr<MBLOCK> innerConcat(MBLOCK::create(hmacLen + dataLen, 0));
        std::unique_ptr<MBLOCK> outerConcat(MBLOCK::create(hmacLen + hmacLen, 0));
        if (!innerConcat || !outerConcat) {
            return false;
        }

        m_block *innerPtr = innerConcat->getDataRef();
        m_block *outerPtr = outerConcat->getDataRef();
        const m_block *hKeyPtr = const_cast<MBLOCK *>(prehashedKey)->getDataRef();
        const m_block *dataPtr = const_cast<MBLOCK *>(data)->getDataRef();

        for (size_t i = 0; i < hmacLen; ++i) {
            const m_block hk = hKeyPtr[i];
            innerPtr[i] = hk ^ HMAC_IPAD;
            outerPtr[i] = hk ^ HMAC_OPAD;
        }
        std::memcpy(innerPtr + hmacLen, dataPtr, dataLen * sizeof(m_block));

        std::unique_ptr<m_block[]> innerHash(new m_block[hmacLen]);
        if (!hasher.hash_into(innerConcat.get(), hmacLen, innerHash.get(), nullptr)) {
            secure_memzero(innerHash.get(), hmacLen * sizeof(m_block));
            return false;
        }
        std::memcpy(outerPtr + hmacLen, innerHash.get(), hmacLen * sizeof(m_block));
        secure_memzero(innerHash.get(), hmacLen * sizeof(m_block));

        if (!hasher.hash_into(outerConcat.get(), hmacLen, out, nullptr)) {
            secure_memzero(out, hmacLen * sizeof(m_block));
            return false;
        }

        return true;
    }

    MBLOCK *hmac_from_prehashed_impl(OESHasher &hasher,
                                     const MBLOCK *prehashedKey,
                                     const MBLOCK *data,
                                     const size_t hmacLen) {
        auto *finalHash = new m_block[hmacLen];
        if (!hmac_from_prehashed_into_impl(hasher, prehashedKey, data, hmacLen, finalHash)) {
            secure_memzero(finalHash, hmacLen * sizeof(m_block));
            delete[] finalHash;
            return nullptr;
        }
        return new MBLOCK(finalHash, hmacLen, true);
    }
} // namespace

MBLOCK *oes_raw_hmac(const MBLOCK *key, const MBLOCK *data, const size_t hmacLen) {
    if (!key || key->isNull() || !data || data->isNull()) {
        std::cerr << "[HMAC] invalid key or data" << std::endl;
        return nullptr;
    }

    if (hmacLen == 0 || hmacLen > OES_MEM_SIZE * OES_NUM_OF_BLOCKS) {
        std::cerr << "[HMAC] invalid hmac length" << std::endl;
        return nullptr;
    }

    OESHasher hasher;

    // Pre-hash della chiave una sola volta.
    const std::unique_ptr<MBLOCK> hKey(hasher.hash(key, hmacLen, nullptr));
    if (!hKey) {
        std::cerr << "[HMAC] invalid key hash" << std::endl;
        return nullptr;
    }

    MBLOCK *result = hmac_from_prehashed_impl(hasher, hKey.get(), data, hmacLen);
    if (!result) {
        std::cerr << "[HMAC] invalid hmac computation" << std::endl;
    }
    return result;
}

bool oes_raw_hmac_prehashed_into(const MBLOCK *prehashedKey, const MBLOCK *data, const size_t hmacLen, m_block *out) {
    if (!prehashedKey || prehashedKey->isNull() || !data || data->isNull() || !out) {
        std::cerr << "[HMAC] invalid prehashed key/data/output" << std::endl;
        return false;
    }

    if (hmacLen == 0 || hmacLen > OES_MEM_SIZE * OES_NUM_OF_BLOCKS || prehashedKey->getLen() != hmacLen) {
        std::cerr << "[HMAC] invalid hmac length/prehashed key" << std::endl;
        return false;
    }

    OESHasher hasher;
    if (!hmac_from_prehashed_into_impl(hasher, prehashedKey, data, hmacLen, out)) {
        std::cerr << "[HMAC] invalid prehashed hmac computation" << std::endl;
        return false;
    }

    return true;
}

bool oes_raw_hmac_prehashed_into(OESHasher &hasher,
                                 const MBLOCK *prehashedKey,
                                 const MBLOCK *data,
                                 const size_t hmacLen,
                                 m_block *out) {
    if (!prehashedKey || prehashedKey->isNull() || !data || data->isNull() || !out) {
        std::cerr << "[HMAC] invalid prehashed key/data/output" << std::endl;
        return false;
    }

    if (hmacLen == 0 || hmacLen > OES_MEM_SIZE * OES_NUM_OF_BLOCKS || prehashedKey->getLen() != hmacLen) {
        std::cerr << "[HMAC] invalid hmac length/prehashed key" << std::endl;
        return false;
    }

    if (!hmac_from_prehashed_into_impl(hasher, prehashedKey, data, hmacLen, out)) {
        std::cerr << "[HMAC] invalid prehashed hmac computation" << std::endl;
        return false;
    }

    return true;
}

