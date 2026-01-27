#pragma once

#include "Block.h"

class inode_raw {
public:
    static constexpr size_t NPOS = static_cast<size_t>(-1);
    static constexpr size_t PAGE_SIZE = 4096;

    inode_raw();

    ~inode_raw();

    inode_raw(const inode_raw &) = delete;

    inode_raw &operator=(const inode_raw &) = delete;

    inode_raw(inode_raw &&o) noexcept;

    inode_raw &operator=(inode_raw &&o) noexcept;

    // File operations
    bool open(const std::string &path);

    bool create(const std::string &path);

    void close();

    [[nodiscard]] bool isOpen() const noexcept { return fd_ >= 0; }
    [[nodiscard]] const std::string &getPath() const noexcept { return path_; }

    // Size management
    [[nodiscard]] size_t getFileSize() const noexcept { return fileSize_; }
    [[nodiscard]] size_t getAllocatedSize() const noexcept { return allocSize_; }

    // Reserve: estende la capacità allocata (non modifica fileSize_)
    bool reserve(size_t capacity);

    // Resize: imposta fileSize_ e alloca se necessario
    bool resize(size_t newSize);

    // Space allocation (free-list based)
    size_t allocate(size_t size);

    void free(size_t pos, size_t size);

    // Reallocation: gestisce update di file con dimensione diversa
    // Ritorna nuova posizione (può essere == pos se espanso in-place)
    size_t reallocate(size_t pos, size_t oldSize, size_t newSize);

    // Prova ad espandere in-place, ritorna true se riuscito
    bool tryExpand(size_t pos, size_t currentSize, size_t newSize);

    [[nodiscard]] size_t getFreeSpace() const noexcept;

    [[nodiscard]] size_t getFragmentCount() const noexcept { return freeList_.size(); }

    // Raw I/O - accesso diretto alla memoria mappata
    bool write(size_t pos, const void *data, size_t size);

    bool read(size_t pos, void *data, size_t size) const;

    // Zero-copy access (restituisce puntatore diretto alla memoria mappata)
    [[nodiscard]] void *ptr(size_t pos = 0) noexcept;

    [[nodiscard]] const void *ptr(size_t pos = 0) const noexcept;

    template<typename T>
    [[nodiscard]] T *ptrAs(size_t pos = 0) noexcept {
        return static_cast<T *>(ptr(pos));
    }

    template<typename T>
    [[nodiscard]] const T *ptrAs(size_t pos = 0) const noexcept {
        return static_cast<const T *>(ptr(pos));
    }

    // Block I/O
    bool readBlock(size_t pos, Block *block) const;

    bool writeBlock(size_t pos, const Block *block);

    size_t appendBlock(const Block *block);

    // Sync & maintenance
    void sync();

    void defragmentFreeList(); // merge + shrink trailing free space
    void compact(); // shrink file to minimum size
    [[nodiscard]] const std::vector<std::pair<size_t, size_t> > &getFreeList() const noexcept { return freeList_; }

private:
    int fd_;
    std::string path_;
    std::vector<std::pair<size_t, size_t> > freeList_; // (offset, size) sorted by offset

    void *mappedPtr_;
    size_t mappedSize_;
    size_t fileSize_; // logical size (actual data)
    size_t allocSize_; // physical allocated size
    bool dirty_;

    // Internal
    static size_t alignUp(size_t n, size_t align) noexcept {
        return (n + align - 1) & ~(align - 1);
    }

    bool extendFile(size_t newAllocSize);

    bool remapFile(size_t newAllocSize);

    bool shrinkFile(size_t newSize);

    void unmapFile();

    size_t diskSize() const;

    size_t findFree(size_t size);

    void mergeFree();

    // Trova blocco libero adiacente a pos+size (per espansione)
    std::vector<std::pair<size_t, size_t> >::iterator findAdjacentFree(size_t pos, size_t size);
};
