#ifndef LOCKBOX_KEY_MANAGMENT_H
#define LOCKBOX_KEY_MANAGMENT_H

m_block **PBKDF(const m_block *key, size_t keyLen, size_t outLen, size_t count, m_block salt = m_block(0xa54ff53a), size_t iterations = 10);

m_block *key_expansion(const m_block *key, size_t keyLen, size_t outLen, m_block salt = m_block(0xa54ff53a), uint16_t iterations = 10);

m_block *key_scheduler(const m_block *key, size_t keyLen, size_t outLen, size_t session);

void cleanup_pbkdf_keys(m_block** roundKey, size_t count, size_t keyLen);

#endif //LOCKBOX_KEY_MANAGMENT_H
