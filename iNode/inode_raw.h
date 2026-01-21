#pragma once

#include <string>
#include <vector>
#include <utility>

#include "Block.h"

class inode_raw {
public:
    // Costante per posizione non valida
    static constexpr size_t NPOS = static_cast<size_t>(-1);

    // ====================== Lifecycle ======================
    inode_raw();

    ~inode_raw();

    // Non copiabile, ma movibile
    inode_raw(const inode_raw &) = delete;

    inode_raw &operator=(const inode_raw &) = delete;

    inode_raw(inode_raw &&other) noexcept;

    inode_raw &operator=(inode_raw &&other) noexcept;

    // ====================== File Operations ======================
    bool open(const std::string &path);

    bool create(const std::string &path);

    void close();

    [[nodiscard]] bool isOpen() const;

    [[nodiscard]] const std::string &getPath() const;

    // ====================== Size & Space ======================
    [[nodiscard]] size_t getFileSize() const;

    [[nodiscard]] bool resize(size_t newSize) const;

    size_t allocate(size_t size);

    void free(size_t pos, size_t size);

    [[nodiscard]] size_t getFreeSpace() const;

    [[nodiscard]] size_t getFragmentCount() const;

    // ====================== Raw I/O ======================
    bool write(size_t pos, const void *data, size_t size) const;

    bool read(size_t pos, void *data, size_t size) const;

    // ====================== Block I/O ======================
    bool readBlock(size_t pos, Block *block) const;

    bool writeBlock(size_t pos, const Block *block) const;

    size_t appendBlock(const Block *block);

    // Modifica un blocco in-place con una callback
    template<typename Func>
    bool modifyBlock(size_t pos, Func &&modifier) {
        Block block;
        if (!readBlock(pos, &block)) return false;
        std::forward<Func>(modifier)(&block);
        return writeBlock(pos, &block);
    }

    // ====================== Free List Management ======================
    void defragmentFreeList();

    [[nodiscard]] const std::vector<std::pair<size_t, size_t> > &getFreeList() const;

private:
    int fd_;
    std::string path_;
    std::vector<std::pair<size_t, size_t> > freeList_; // {pos, size}

    size_t findFreeSpace(size_t size);

    void mergeFreeList();
};
