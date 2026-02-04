#include "key_management.h"

#include <memory>
#include <algorithm>
#include <cstring>

#include <OpenES/layer/raw-layer.h>
#include <OpenES/algo/constants.h>
#include <OpenES/algo/hashing.h>
#include <OpenES/support/oesMath.h>
#include <OpenES/algo/utils.h>

static constexpr size_t MAX_HASH_OUTPUT = OES_NUM_OF_BLOCKS * OES_MEM_SIZE;

// ============================================================================
//  INLINE BULK OPERATIONS
// ============================================================================

#define UNROLL_THRESHOLD 8

static inline void bulk_copy(m_block* __restrict dst, const m_block* __restrict src, size_t n) {
    std::memcpy(dst, src, n * sizeof(m_block));
}

static inline void bulk_xor(m_block* __restrict dst, const m_block* __restrict src, size_t n) {
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        dst[i]   ^= src[i];   dst[i+1] ^= src[i+1];
        dst[i+2] ^= src[i+2]; dst[i+3] ^= src[i+3];
        dst[i+4] ^= src[i+4]; dst[i+5] ^= src[i+5];
        dst[i+6] ^= src[i+6]; dst[i+7] ^= src[i+7];
    }
    for (; i < n; ++i) dst[i] ^= src[i];
}

// XOR + accumula in un solo pass: dst ^= src, acc ^= src
static inline void bulk_xor_dual(m_block* __restrict dst, m_block* __restrict acc,
                                  const m_block* __restrict src, size_t n) {
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        m_block s0 = src[i], s1 = src[i+1], s2 = src[i+2], s3 = src[i+3];
        dst[i]   ^= s0; dst[i+1] ^= s1; dst[i+2] ^= s2; dst[i+3] ^= s3;
        acc[i]   ^= s0; acc[i+1] ^= s1; acc[i+2] ^= s2; acc[i+3] ^= s3;
    }
    for (; i < n; ++i) {
        m_block s = src[i];
        dst[i] ^= s;
        acc[i] ^= s;
    }
}

// ============================================================================
//  PREALLOCATED HMAC EXPANSION CONTEXT
// ============================================================================

struct HmacExpandCtx {
    std::unique_ptr<MBLOCK> iterInput;  // data || counter buffer
    const MBLOCK* prehashedKey = nullptr;
    OESHasher hasher;
    size_t dataLen;
    m_block* inputPtr;

    bool init(const MBLOCK* hKey, const MBLOCK* data) {
        prehashedKey = hKey;
        if (!prehashedKey || prehashedKey->isNull() || !data || data->isNull()) return false;
        dataLen = data->getLen();
        iterInput.reset(MBLOCK::create(dataLen + 1, 0));
        if (!iterInput) return false;
        inputPtr = iterInput->getDataRef();
        bulk_copy(inputPtr, const_cast<MBLOCK*>(data)->getDataRef(), dataLen);
        return true;
    }

    // Genera HMAC con counter, scrive direttamente in dst+offset
    bool generate(m_block counter, m_block* dst, size_t len) {
        inputPtr[dataLen] = counter;
        return oes_raw_hmac_prehashed_into(hasher, prehashedKey, iterInput.get(), len, dst);
    }
};

// Versione ottimizzata che scrive direttamente nel buffer di output
static bool expand_into(const MBLOCK* prehashedKey, const MBLOCK* data, m_block* outPtr, size_t outLen) {
    if (!prehashedKey || prehashedKey->isNull() || !data || data->isNull() || !outPtr || outLen == 0) {
        return false;
    }

    const size_t prehashedLen = prehashedKey->getLen();
    if (prehashedLen == 0 || prehashedLen > MAX_HASH_OUTPUT) {
        return false;
    }
    if ((outLen <= MAX_HASH_OUTPUT && prehashedLen != outLen) ||
        (outLen > MAX_HASH_OUTPUT && prehashedLen != MAX_HASH_OUTPUT)) {
        return false;
    }

    if (outLen <= MAX_HASH_OUTPUT) {
        return oes_raw_hmac_prehashed_into(prehashedKey, data, outLen, outPtr);
    }

    HmacExpandCtx ctx;
    if (!ctx.init(prehashedKey, data)) return false;
    std::unique_ptr<m_block[]> chunkBuf(new m_block[MAX_HASH_OUTPUT]);
    m_block* chunkBufPtr = chunkBuf.get();

    size_t generated = 0;
    m_block counter = 1;

    while (generated < outLen) {
        const size_t chunkLen = std::min(outLen - generated, MAX_HASH_OUTPUT);
        if (!ctx.generate(counter, chunkBufPtr, MAX_HASH_OUTPUT)) return false;
        bulk_copy(outPtr + generated, chunkBufPtr, chunkLen);
        generated += chunkLen;
        ++counter;
    }
    return true;
}

static MBLOCK* key_expansion_with_prehashed(const MBLOCK* key,
                                            const MBLOCK* prehashedKey,
    const size_t outLen,
    const m_block salt,
    const size_t iterations) {
    if (!key || key->isNull() || outLen == 0) return nullptr;
    if (iterations == 0) return key->clone();
    if (!prehashedKey || prehashedKey->isNull()) return nullptr;

    const size_t prehashedLen = prehashedKey->getLen();
    if (prehashedLen == 0 || prehashedLen > MAX_HASH_OUTPUT) return nullptr;
    if ((outLen <= MAX_HASH_OUTPUT && prehashedLen != outLen) ||
        (outLen > MAX_HASH_OUTPUT && prehashedLen != MAX_HASH_OUTPUT)) {
        return nullptr;
    }

    std::unique_ptr<MBLOCK> out(MBLOCK::create(outLen, 0));
    if (!out) return nullptr;
    m_block* outPtr = out->getDataRef();

    // Costruisci salt || 1
    std::unique_ptr<MBLOCK> counterSalt(MBLOCK::create(2, 0));
    if (!counterSalt) return nullptr;
    m_block* cs = counterSalt->getDataRef();
    cs[0] = salt;
    cs[1] = 1;

    if (!expand_into(prehashedKey, counterSalt.get(), outPtr, outLen)) return nullptr;

    if (iterations == 1) return out.release();

    // Buffer U riusato per tutte le iterazioni
    std::unique_ptr<MBLOCK> U(MBLOCK::create(outLen, 0));
    if (!U) return nullptr;
    m_block* uPtr = U->getDataRef();

    // Copia U1 in U per prima iterazione
    bulk_copy(uPtr, outPtr, outLen);

    // Context HMAC pre-allocato (evita riallocazioni nel loop)
    HmacExpandCtx ctx;
    const bool needCtx = (outLen > MAX_HASH_OUTPUT);
    std::unique_ptr<m_block[]> chunkBuf;
    m_block* chunkBufPtr = nullptr;
    std::unique_ptr<m_block[]> uNextSmall;
    m_block* uNextSmallPtr = nullptr;
    OESHasher smallPathHasher;

    if (needCtx) {
        if (!ctx.init(prehashedKey, U.get())) return nullptr;
        chunkBuf.reset(new m_block[MAX_HASH_OUTPUT]);
        chunkBufPtr = chunkBuf.get();
    } else {
        uNextSmall.reset(new m_block[outLen]);
        uNextSmallPtr = uNextSmall.get();
    }

    for (size_t iter = 2; iter <= iterations; ++iter) {
        if (outLen <= MAX_HASH_OUTPUT) {
            if (!oes_raw_hmac_prehashed_into(smallPathHasher, prehashedKey, U.get(), outLen, uNextSmallPtr)) {
                return nullptr;
            }
            bulk_xor(outPtr, uNextSmallPtr, outLen);
            bulk_copy(uPtr, uNextSmallPtr, outLen);
        } else {
            bulk_copy(ctx.inputPtr, uPtr, ctx.dataLen);

            size_t generated = 0;
            m_block counter = 1;
            while (generated < outLen) {
                const size_t chunkLen = std::min(outLen - generated, MAX_HASH_OUTPUT);
                if (!ctx.generate(counter, chunkBufPtr, MAX_HASH_OUTPUT)) return nullptr;
                bulk_xor_dual(outPtr + generated, uPtr + generated, chunkBufPtr, chunkLen);
                generated += chunkLen;
                ++counter;
            }
        }
    }

    return out.release();
}

// ============================================================================
//  KEY EXPANSION - VERSIONE ULTRA OTTIMIZZATA
// ============================================================================

MBLOCK* key_expansion(const MBLOCK* key, const size_t outLen, const m_block salt, const size_t iterations) {
    if (!key || key->isNull() || outLen == 0) return nullptr;
    if (iterations == 0) return key->clone();

    OESHasher hasher;
    const size_t prehashLen = std::min(outLen, MAX_HASH_OUTPUT);
    std::unique_ptr<MBLOCK> prehashedKey(hasher.hash(key, prehashLen, nullptr));
    if (!prehashedKey) return nullptr;

    return key_expansion_with_prehashed(key, prehashedKey.get(), outLen, salt, iterations);
}

// ============================================================================
//  KEY SCHEDULER - LOOP FUSION
// ============================================================================

static inline m_block oesRcon(size_t session, size_t index) {
    m_block x = DIFFUSE_CONST ^ session ^ static_cast<m_block>(index);
    x = mBlock::rotl(x, (index * 7) % OES_MEM_SIZE);
    x ^= xtime(x);
    x ^= mBlock::rotl(x, 13);
    x ^= xtime(x);
    return x;
}

MBLOCK* key_scheduler(const MBLOCK* key, const size_t outLen, size_t session) {
    if (!key || key->isNull() || outLen == 0) return nullptr;

    MBLOCK* roundKey = (key->getLen() != outLen)
        ? key_expansion(key, outLen, session, 1)
        : key->clone();

    if (!roundKey) return nullptr;

    m_block* data = roundKey->getDataRef();
    m_block feedback = DIFFUSE_CONST ^ session;

    const size_t memSize = OES_MEM_SIZE;
    const size_t s5 = session;

    // Precalcola (i*5 + session) % memSize per pattern comuni
    for (size_t i = 0; i < outLen; ++i) {
        const size_t shift = (i * 5 + s5) % memSize;
        const m_block rcon = oesRcon(session, i);

        m_block b = data[i];
        b ^= mBlock::rotl(feedback, shift) ^ rcon ^ feedback;
        feedback = xtime(b) ^ b;
        data[i] = b;
    }

    roundKey->rotr((session * 11 + outLen) % (outLen * memSize));
    return roundKey;
}
