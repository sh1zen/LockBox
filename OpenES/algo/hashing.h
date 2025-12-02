#ifndef LOCKBOX_HASHING_H
#define LOCKBOX_HASHING_H

#include <OpenES/layer/raw-layer.h>

MBLOCK *oes_raw_hash(const MBLOCK *data, size_t hashLen, MBLOCK **iv);

MBLOCK *oes_raw_hmac(const MBLOCK *key, const MBLOCK *data, size_t hmacLen);

#endif //LOCKBOX_HASHING_H
