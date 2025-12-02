#ifndef LOCKBOX_BLOCK_INTERFACE_H
#define LOCKBOX_BLOCK_INTERFACE_H

#include "m_block.h"

MBLOCK* toOESBlock(void *data, size_t len);

std::pair<void *, size_t> exportBlock(MBLOCK *block, int mode);

std::pair<char*, size_t> oes_export_block_to_hex_string(MBLOCK* block);

std::pair<char*, size_t> oes_export_block_to_string(MBLOCK* block);

std::pair<char*, size_t> oes_export_block_to_base64(MBLOCK* block);

MBLOCK* oes_import_block_from_hex_string(const char *hexString);

MBLOCK* oes_import_block_from_base64(const char *base64String);

void oes_block_dump(MBLOCK* block, bool printable = false);

#endif //LOCKBOX_BLOCK_INTERFACE_H