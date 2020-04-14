#ifndef LOCKBOX_CONVERTER_H
#define LOCKBOX_CONVERTER_H

#include <tuple>
#include "oes_common.h"

/**
 * Convert byte array to m_block array with padding
 * @param data Input byte data
 * @param nByte Number of bytes
 * @return Pair of (m_block array, length). Caller must free the array.
 */
std::pair<m_block *, size_t> toMBlock(const void *data, size_t nByte);

/**
 * Extract a single byte from m_block at given position
 * @param block m_block to extract from
 * @param pos Byte position (0 = LSB)
 * @return Extracted byte
 */
uint8_t getByte(m_block block, uint8_t pos);

/**
 * Convert m_block array to byte array with padding removal
 * @param t Input m_block array
 * @param len Length of m_block array
 * @return Pair of (byte array, actual length without padding). Caller must free.
 */
std::pair<uint8_t *, size_t> toBytes(const m_block *t, size_t len = 0);

/**
 * Convert m_block array to byte array (raw, no padding removal)
 * @param t Input m_block array
 * @param len Length of m_block array
 * @param extraSize Extra bytes to allocate
 * @return Pair of (byte array, length). Caller must free.
 */
std::pair<uint8_t *, size_t> toByte_raw(const m_block *t, size_t len, size_t extraSize = 0);

/**
 * Concatenate two m_block arrays
 * @param a First array
 * @param a_len Length of first array
 * @param b Second array
 * @param b_len Length of second array
 * @return Concatenated array (caller must free)
 */
m_block *mBlock_concat(const m_block *a, size_t a_len, const m_block *b, size_t b_len);

/**
 * Clone m_block array
 * @param dst Destination buffer (allocated if NULL)
 * @param src Source buffer
 * @param len Number of m_blocks to copy
 * @return Pointer to destination buffer (caller must free if dst was NULL)
 */
m_block *mBlock_clone(m_block *dst, const m_block *src, size_t len);

/**
 * Create and optionally initialize m_block array
 * @param len Number of m_blocks to allocate
 * @param value Initial value (0 for zero-initialization)
 * @return Allocated array (caller must free)
 */
m_block *mBlock_create(size_t len, m_block value = 0);

/**
 * Safely free m_block array
 * @param ptr Pointer to free
 */
void mBlock_free(m_block *ptr);

/**
 * Securely zero and free m_block array (for sensitive data)
 * @param ptr Pointer to secure free
 * @param len Length of array
 */
void mBlock_secure_free(m_block *ptr, size_t len);

#endif //LOCKBOX_CONVERTER_H