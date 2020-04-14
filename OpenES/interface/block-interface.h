#ifndef LOCKBOX_BLOCK_INTERFACE_H
#define LOCKBOX_BLOCK_INTERFACE_H

std::pair<char*, size_t> oes_export_block_to_hex_string(OES_BLOCK block);

std::pair<char*, size_t> oes_export_block_to_string(OES_BLOCK block);

std::pair<char*, size_t> oes_export_block_to_base64(OES_BLOCK block);

OES_BLOCK toOESBlock(void *data, size_t len);

void oes_block_dump(OES_BLOCK block, bool printable = false);

#endif //LOCKBOX_BLOCK_INTERFACE_H