#pragma once

#include "Block.h"

class inode_raw {
public:
    static constexpr size_t PAGE_SIZE = 4096;
    static constexpr size_t NPOS = static_cast<size_t>(-1);

    // ==================== Lifecycle ====================
    inode_raw();

    ~inode_raw();

    inode_raw(const inode_raw &) = delete;

    inode_raw &operator=(const inode_raw &) = delete;

    inode_raw(inode_raw &&o) noexcept;

    inode_raw &operator=(inode_raw &&o) noexcept;

    // ==================== File Operations ====================
    bool open(const std::string &path);

    bool create(const std::string &path);

    void close();

    bool isOpen() const noexcept { return fd_ >= 0; }

    // ==================== Allocation ====================
    /// Alloca spazio alla fine del file, ritorna l'offset o NPOS
    size_t allocate(size_t size);

    /// Rialloca un blocco di dati. Può spostarlo se necessario.
    size_t reallocate(size_t oldPos, size_t oldSize, size_t newSize);

    // ==================== Defragmentation ====================
    /// Compatta il file: rimuove spazi vuoti e tronca
    bool defragment();

    // ==================== Raw I/O ====================
    bool write(size_t pos, const void *data, size_t size);

    bool read(size_t pos, void *data, size_t size) const;

    void *ptr(size_t pos) noexcept;

    const void *ptr(size_t pos) const noexcept;

    // ==================== Block I/O ====================
    bool readBlock(size_t pos, Block *block) const;

    bool writeBlock(size_t pos, const Block *block);

    size_t appendBlock(const Block *block);

    // ==================== Sync ====================
    void sync();

    // ==================== Queries ====================
    size_t size() const noexcept { return fileSize_; }
    size_t capacity() const noexcept { return allocSize_; }
    const std::string &path() const noexcept { return path_; }

    // ==================== Utilities ====================
    static constexpr size_t alignUp(size_t val, size_t align) noexcept {
        return (val + align - 1) & ~(align - 1);
    }

private:
    // ==================== Internal Helpers ====================
    size_t diskSize() const;

    void unmapFile();

    bool extendFile(size_t newAllocSize) const;

    bool remapFile(size_t newAllocSize);

    bool truncateToSize(size_t newSize);

    // ==================== Members ====================
    int fd_;
    std::string path_;
    void *mappedPtr_;
    size_t mappedSize_;
    size_t fileSize_; // Dimensione logica (dati validi)
    size_t allocSize_; // Dimensione allocata (mappata)
    bool dirty_;
};
