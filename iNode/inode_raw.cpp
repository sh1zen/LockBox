#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>

#include "mman.h"
#include "Block.h"
#include "iNode.h"
#include "utility.h"
#include "io_helpers.h"

// Funzioni di supporto generiche per lockbox e mmap
size_t get_lockbox_size(int box) {
    if (box <= 0)
        return 0;
    return lseek64(box, 0, SEEK_END);
}

// Scrittura generica su lockbox
off64_t insert_to_lockbox(int box, void *buf, size_t size) {
    if (box <= 0)
        return 0;
    off64_t pos = get_lockbox_size(box);
    char *dst = (char *) mmap(nullptr, pos + size, PROT_WRITE, MAP_FILE, box, 0);
    if (dst == MAP_FAILED)
        return 0;
    memcpy(dst + pos, buf, size);
    msync(dst, size + pos, MS_SYNC);
    munmap(dst, size + pos);
    return pos;
}

bool write_to_lockbox(int box, void *buf, off64_t pos, size_t size) {
    if (box <= 0)
        return false;
    size_t length = get_lockbox_size(box);
    if (pos + size > length)
        return false;
    char *mapped_memory = (char *) mmap(nullptr, length, PROT_WRITE, MAP_FILE, box, 0);
    if (mapped_memory == MAP_FAILED)
        return false;
    memcpy(mapped_memory + pos, buf, size);
    munmap(mapped_memory, length);
    return true;
}

bool read_from_lockbox(int box, off64_t offset, void *buf, size_t size) {
    if (box <= 0 || buf == nullptr)
        return false;
    off64_t length = get_lockbox_size(box);
    char *mapped_memory = (char *) mmap(nullptr, length, PROT_READ, MAP_FILE, box, 0);
    if (mapped_memory == MAP_FAILED)
        return false;
    memcpy(buf, mapped_memory + offset, size);
    munmap(mapped_memory, length);
    return true;
}

// Operazioni sui blocchi tramite la classe Block
bool read_block(int box, off64_t offset, Block* block) {
    if (box < 0 || offset <= 0)
        return false;
    return read_from_lockbox(box, offset, reinterpret_cast<void*>(block), sizeof(Block));
}

off64_t insert_block(int box, Block* block) {
    return insert_to_lockbox(box, block, sizeof(Block));
}

bool update_block(int box, Block* block) {
    return write_to_lockbox(box, block, block->current, sizeof(Block));
}

bool replace_block(int box, off64_t pos, Block* block) {
    return write_to_lockbox(box, block, pos, sizeof(Block));
}

// Debug helper
void debug_block_info(Block* block, int lockbox) {
    std::cout << std::endl << "=====   DEBUG BLOCK  =====" << std::endl;
    std::cout << "Name: " << block->name << std::endl;
    if (lockbox > 0 && block->parent > 0) {
        Block parent;
        read_block(lockbox, block->parent, &parent);
        std::cout << "Parent name: " << parent.name << std::endl;
    }
    std::cout << "isFile: " << block->isFile << std::endl;
    std::cout << "Data pos: " << block->data_pos << std::endl;
    std::cout << "Data size: " << block->size << std::endl;
    std::cout << "==========================" << std::endl << std::endl;
}

// =================================================================
// Tutta la logica ad alto livello ora sta nelle classi iNode/Block!
// =================================================================