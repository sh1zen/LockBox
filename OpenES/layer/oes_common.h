#ifndef OES_COMMON_H
#define OES_COMMON_H

#include "defines.h"

#define OES_LOGIC_BLOCK_SIZE 32

#if (OES_LOGIC_BLOCK_SIZE % 8 != 0 || OES_LOGIC_BLOCK_SIZE < 8 || OES_LOGIC_BLOCK_SIZE > 128)
#error "OES_LOGIC_BLOCK_SIZE must be a multpiple of 8"
#endif

#ifndef __SIZEOF_INT128__
#if OES_LOGIC_BLOCK_SIZE >= 128
#undef OES_LOGIC_BLOCK_SIZE
#define OES_LOGIC_BLOCK_SIZE = 64
#endif
#endif


#if OES_LOGIC_BLOCK_SIZE <= 16
#define OES_MEM_SIZE 16
__extension__ typedef uint16_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 32
#define OES_MEM_SIZE 32
__extension__ typedef uint32_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 64
#define OES_MEM_SIZE 64
__extension__ typedef uint64_t m_block;
#elif OES_LOGIC_BLOCK_SIZE <= 128
#define OES_MEM_SIZE 128
__extension__ typedef __uint128_t m_block;
#endif

#define OES_BYTES_X_BLOCK (OES_MEM_SIZE / 8)
#define OES_MID_BLOCK_SIZE (OES_MEM_SIZE >= 16 ? OES_MEM_SIZE / 2 : 8)

// OES_BLOCK structure
#ifndef OES_BLOCK
typedef struct oesblock* OES_BLOCK;
struct oesblock {
    m_block* data;
    size_t len;
};
#endif

// OES_KEY structure
#ifndef OES_KEY
typedef struct oeskey* OES_KEY;
struct oeskey {
    m_block* string;
    size_t len;
};
#endif

/**
 * Safely deallocate cipher/key structure
 */
void unset_cipher(OES_KEY* cipher);

/**
 * Safely deallocate block structure
 */
void unset_block(OES_BLOCK* block);

/**
 * Update block with new data (takes ownership of data)
 * If data is nullptr, clears the block
 */
void update_block(OES_BLOCK* block, m_block* data, size_t len);

/**
 * Update block from source block (transfer ownership from src)
 * After this call, src is set to nullptr
 */
void move_block(OES_BLOCK* block, OES_BLOCK src);

/**
 * Clone a block (deep copy)
 * Returns a new OES_BLOCK with copied data, or nullptr on failure
 */
OES_BLOCK clone_block(OES_BLOCK src);

#endif // OES_COMMON_H