#include <cstdlib>
#include <cstring>

#include "oes_common.h"
#include "support.h"


/**
 * Safely deallocate cipher/key structure
 */
void unset_cipher(OES_KEY *cipher) {
    if (!cipher || !*cipher) {
        return;
    }

    if ((*cipher)->string) {
        secure_memzero((*cipher)->string, (*cipher)->len * sizeof(m_block));
        free((*cipher)->string);
        (*cipher)->string = nullptr;
    }

    free(*cipher);
    *cipher = nullptr;
}

/**
 * Safely deallocate block structure
 */
void unset_block(OES_BLOCK *block) {
    if (!block || !*block) {
        return;
    }

    if ((*block)->data) {
        secure_memzero((*block)->data, (*block)->len * sizeof(m_block));
        free((*block)->data);
        (*block)->data = nullptr;
    }

    free(*block);
    *block = nullptr;
}

/**
 * Update block with new data transferring ownership
 * If data is nullptr, the block is cleared but still allocated
 */
void update_block(OES_BLOCK *block, m_block *data, size_t len) {
    if (!block) {
        return;
    }

    // Allocate block structure if needed
    if (!*block) {
        *block = static_cast<OES_BLOCK>(std::malloc(sizeof(oesblock)));
        if (!*block) {
            // If we can't allocate and were given data, we need to free it
            // to avoid memory leak since we're taking ownership
            if (data) {
                secure_memzero(data, len * sizeof(m_block));
                free(data);
            }
            return;
        }
        (*block)->data = nullptr;
        (*block)->len = 0;
    }

    // Free existing data if present
    if ((*block)->data) {
        secure_memzero((*block)->data, (*block)->len * sizeof(m_block));
        free((*block)->data);
    }

    // Take ownership of new data
    (*block)->data = data;
    (*block)->len = len;
}

/**
 * Update block from source block (transfer ownership)
 * Source block is freed after transfer
 */
void move_block(OES_BLOCK *dest, OES_BLOCK src) {
    if (!dest) {
        // If dest is null but src exists, we need to free src to avoid leak
        if (src) {
            unset_block(&src);
        }
        return;
    }

    // Free existing destination
    unset_block(dest);

    // Transfer ownership (just move the pointer)
    *dest = src;
    // Note: we don't set src to nullptr since it's passed by value
    // The caller should not use src after this call
}

/**
 * Clone a block (deep copy)
 */
OES_BLOCK clone_block(OES_BLOCK src) {
    if (!src || !src->data || src->len == 0) {
        return nullptr;
    }

    OES_BLOCK clone = static_cast<OES_BLOCK>(std::malloc(sizeof(oesblock)));
    if (!clone) {
        return nullptr;
    }

    clone->len = src->len;
    clone->data = static_cast<m_block*>(std::malloc(src->len * sizeof(m_block)));
    if (!clone->data) {
        free(clone);
        return nullptr;
    }

    std::memcpy(clone->data, src->data, src->len * sizeof(m_block));
    return clone;
}