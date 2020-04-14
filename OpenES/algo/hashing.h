#ifndef LOCKBOX_HASHING_H
#define LOCKBOX_HASHING_H

#include <OpenES/layer/raw-layer.h>

m_block *oes_raw_hash(const m_block *data, size_t dataLen, size_t hashLen, OES_BLOCK *iv = nullptr);

m_block *oes_raw_hmac(const m_block *key, size_t keyLen, const m_block *data, size_t dataLen, size_t hmacLen);


#endif //LOCKBOX_HASHING_H
