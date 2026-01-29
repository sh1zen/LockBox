#include "inode_raw.h"

#include <algorithm>
#include <fcntl.h>
#include <cstring>
#include <queue>
#include <set>
#include <sys/stat.h>

#ifdef _WIN32
#include "mman.h"

static int p_open(const char *p, int f, int m = 0) {
    return ::_open(p, f, m);
}

static int p_close(int fd) {
    return ::_close(fd);
}

static int64_t p_lseek(int fd, int64_t off, int w) {
    return ::_lseeki64(fd, off, w);
}

static int p_write(int fd, const void *b, unsigned n) {
    return ::_write(fd, b, n);
}

static int p_ftrunc(int fd, int64_t sz) {
    return ::_chsize_s(fd, sz);
}
#else
#include <unistd.h>
#include <sys/mman.h>
#include "mman.h"

static int p_open(const char *p, int f, int m = 0) {
    return ::open(p, f, m);
}
static int p_close(int fd) {
    return ::close(fd);
}
static off_t p_lseek(int fd, off_t off, int w) {
    return ::lseek(fd, off, w);
}
static ssize_t p_write(int fd, const void *b, size_t n) {
    return ::write(fd, b, n);
}
static int p_ftrunc(int fd, off_t sz) {
    return ::ftruncate(fd, sz);
}
#endif

// ==================== Lifecycle ====================

inode_raw::inode_raw()
    : fd_(-1)
      , mappedPtr_(nullptr)
      , mappedSize_(0)
      , fileSize_(0)
      , allocSize_(0)
      , dirty_(false) {
}

inode_raw::~inode_raw() {
    close();
}

inode_raw::inode_raw(inode_raw &&o) noexcept
    : fd_(o.fd_)
      , path_(std::move(o.path_))
      , mappedPtr_(o.mappedPtr_)
      , mappedSize_(o.mappedSize_)
      , fileSize_(o.fileSize_)
      , allocSize_(o.allocSize_)
      , dirty_(o.dirty_) {
    o.fd_ = -1;
    o.mappedPtr_ = nullptr;
    o.mappedSize_ = 0;
    o.fileSize_ = 0;
    o.allocSize_ = 0;
    o.dirty_ = false;
}

inode_raw &inode_raw::operator=(inode_raw &&o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        path_ = std::move(o.path_);
        mappedPtr_ = o.mappedPtr_;
        mappedSize_ = o.mappedSize_;
        fileSize_ = o.fileSize_;
        allocSize_ = o.allocSize_;
        dirty_ = o.dirty_;

        o.fd_ = -1;
        o.mappedPtr_ = nullptr;
        o.mappedSize_ = 0;
        o.fileSize_ = 0;
        o.allocSize_ = 0;
        o.dirty_ = false;
    }
    return *this;
}

// ==================== Internal Helpers ====================

size_t inode_raw::diskSize() const {
    if (fd_ < 0) return 0;
    auto cur = p_lseek(fd_, 0, SEEK_CUR);
    auto sz = p_lseek(fd_, 0, SEEK_END);
    p_lseek(fd_, cur, SEEK_SET);
    return static_cast<size_t>(sz);
}

void inode_raw::unmapFile() {
    if (mappedPtr_) {
        if (dirty_ && fileSize_ > 0) {
            mman::sync(mappedPtr_, fileSize_);
        }
        mman::unmap(mappedPtr_, mappedSize_);
        mappedPtr_ = nullptr;
        mappedSize_ = 0;
        dirty_ = false;
    }
}

bool inode_raw::extendFile(size_t newAllocSize) const {
    if (fd_ < 0 || newAllocSize == 0) return false;

    if (p_lseek(fd_, static_cast<int64_t>(newAllocSize - 1), SEEK_SET) == -1)
        return false;
    if (p_write(fd_, "", 1) != 1)
        return false;

    return true;
}

bool inode_raw::remapFile(size_t newAllocSize) {
    if (fd_ < 0) return false;

    if (mappedPtr_ && allocSize_ >= newAllocSize)
        return true;

    size_t targetAlloc = alignUp(newAllocSize, PAGE_SIZE);
    if (targetAlloc == 0) targetAlloc = PAGE_SIZE;

    unmapFile();

    if (!extendFile(targetAlloc))
        return false;

    auto res = mman::map(nullptr, targetAlloc,
                         mman::Prot::Read | mman::Prot::Write,
                         mman::MapFlags::Shared, fd_, 0);
    if (!res.ok()) return false;

    mappedPtr_ = res.ptr;
    mappedSize_ = targetAlloc;
    allocSize_ = targetAlloc;
    return true;
}

bool inode_raw::truncateToSize(size_t newSize) {
    if (fd_ < 0) return false;

    size_t alignedSize = alignUp(newSize, PAGE_SIZE);
    if (alignedSize == 0) alignedSize = PAGE_SIZE;

    if (alignedSize == allocSize_)
        return true;

    if (alignedSize > allocSize_)
        return remapFile(alignedSize);

    unmapFile();

    if (p_ftrunc(fd_, static_cast<int64_t>(alignedSize)) != 0) {
        remapFile(allocSize_);
        return false;
    }

    auto res = mman::map(nullptr, alignedSize,
                         mman::Prot::Read | mman::Prot::Write,
                         mman::MapFlags::Shared, fd_, 0);
    if (!res.ok()) {
        mappedPtr_ = nullptr;
        mappedSize_ = 0;
        allocSize_ = 0;
        return false;
    }

    mappedPtr_ = res.ptr;
    mappedSize_ = alignedSize;
    allocSize_ = alignedSize;
    return true;
}

// ==================== File Operations ====================

bool inode_raw::open(const std::string &path) {
    if (fd_ >= 0) close();

    fd_ = p_open(path.c_str(), O_RDWR);
    if (fd_ < 0) return false;

    path_ = path;
    fileSize_ = diskSize();
    allocSize_ = fileSize_;

    if (fileSize_ < sizeof(Block)) {
        close();
        return false;
    }

    if (!remapFile(fileSize_)) {
        close();
        return false;
    }

    return true;
}

bool inode_raw::create(const std::string &path) {
    if (fd_ >= 0) close();

#ifdef _WIN32
    fd_ = p_open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
#else
    fd_ = p_open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
#endif
    if (fd_ < 0) return false;

    path_ = path;
    fileSize_ = 0;
    allocSize_ = 0;

    if (!remapFile(PAGE_SIZE)) {
        close();
        return false;
    }

    return true;
}

void inode_raw::close() {
    sync();
    unmapFile();

    if (fd_ >= 0) {
        if (fileSize_ > 0) {
            p_ftrunc(fd_, static_cast<int64_t>(alignUp(fileSize_, PAGE_SIZE)));
        }
        p_close(fd_);
        fd_ = -1;
    }

    path_.clear();
    fileSize_ = 0;
    allocSize_ = 0;
}

// ==================== Allocation ====================

size_t inode_raw::allocate(size_t size) {
    if (size == 0) return NPOS;

    size_t alignedSize = alignUp(size, PAGE_SIZE);
    size_t pos = fileSize_;
    size_t newFileSize = pos + alignedSize;

    if (newFileSize > allocSize_) {
        if (!remapFile(newFileSize))
            return NPOS;
    }

    fileSize_ = newFileSize;
    dirty_ = true;
    return pos;
}

size_t inode_raw::reallocate(size_t oldPos, size_t oldSize, size_t newSize) {
    if (oldPos == NPOS)
        return allocate(newSize);

    if (newSize == 0)
        return NPOS;

    size_t oldAligned = alignUp(oldSize, PAGE_SIZE);
    size_t newAligned = alignUp(newSize, PAGE_SIZE);

    if (newAligned == oldAligned)
        return oldPos;

    if (oldPos + oldAligned == fileSize_) {
        if (newAligned > oldAligned) {
            const size_t newFileSize = oldPos + newAligned;
            if (newFileSize > allocSize_) {
                if (!remapFile(newFileSize))
                    return NPOS;
            }
            fileSize_ = newFileSize;
        } else {
            fileSize_ = oldPos + newAligned;
        }
        dirty_ = true;
        return oldPos;
    }

    const size_t newPos = allocate(newSize);
    if (newPos == NPOS) return NPOS;

    if (const size_t copySize = std::min(oldSize, newSize); mappedPtr_ && copySize > 0) {
        std::memcpy(static_cast<char *>(mappedPtr_) + newPos,
                    static_cast<char *>(mappedPtr_) + oldPos,
                    copySize);
    }

    dirty_ = true;
    return newPos;
}

// ==================== Defragmentation ====================

bool inode_raw::defragment() {
    if (fd_ < 0 || !mappedPtr_ || fileSize_ < sizeof(Block))
        return false;

    // ===== Step 1: BFS dalla root per trovare blocchi raggiungibili =====
    std::vector<size_t> validBlockOffsets;
    std::set<size_t> visited;
    std::queue<size_t> toVisit;

    auto enqueue = [&](size_t p) {
        if (p != 0 && p != NPOS &&
            p + sizeof(Block) <= fileSize_ &&
            !visited.contains(p)) {
            toVisit.push(p);
        }
    };

    // Root (posizione 0) è sempre inclusa
    const auto *root = static_cast<const Block *>(ptr(0));
    if (!root) return false;

    visited.insert(0);
    validBlockOffsets.push_back(0);

    // Accoda i collegamenti dalla root
    enqueue(root->next);
    enqueue(root->previous);
    enqueue(root->subdir_pos);
    // Per le directory, data_pos punta al primo file
    if (!root->isFile) {
        enqueue(root->data_pos);
    }

    // BFS
    while (!toVisit.empty()) {
        size_t pos = toVisit.front();
        toVisit.pop();

        if (visited.contains(pos))
            continue;

        const auto *blk = static_cast<const Block *>(ptr(pos));
        if (!blk)
            continue;

        visited.insert(pos);
        validBlockOffsets.push_back(pos);

        enqueue(blk->next);
        enqueue(blk->previous);
        enqueue(blk->parent);
        enqueue(blk->subdir_pos);

        // Per le directory, data_pos punta al primo file
        if (!blk->isFile) {
            enqueue(blk->data_pos);
        }
    }

    // Ordina per offset
    std::ranges::sort(validBlockOffsets.begin(), validBlockOffsets.end());

    // ===== Step 2: Raccogli blocchi, dati file, nomi esterni =====
    struct BlockEntry {
        size_t oldPos{};
        Block block;
    };

    struct DataEntry {
        size_t oldPos{};
        size_t size{};
        size_t alignedSize{};
        std::vector<uint8_t> data;
    };

    std::vector<BlockEntry> blocks;
    std::vector<DataEntry> fileDataEntries;
    std::vector<DataEntry> nameEntries;

    std::set<size_t> collectedData;
    std::set<size_t> collectedNames;

    blocks.reserve(validBlockOffsets.size());

    for (size_t oldPos: validBlockOffsets) {
        BlockEntry entry;
        entry.oldPos = oldPos;
        std::memcpy(&entry.block, ptr(oldPos), sizeof(Block));
        blocks.push_back(entry);

        const Block &blk = entry.block;

        // Raccogli dati file (SOLO per file, non directory!)
        // Per le directory, data_pos punta al primo file (già gestito nella BFS)
        if (blk.isFile && blk.data_pos != 0 && blk.data_pos != NPOS &&
            blk.size > 0 &&
            blk.data_pos + blk.size <= fileSize_ &&
            !collectedData.contains(blk.data_pos)) {
            collectedData.insert(blk.data_pos);

            DataEntry de;
            de.oldPos = blk.data_pos;
            de.size = blk.size;
            de.alignedSize = alignUp(blk.size, PAGE_SIZE);
            de.data.resize(de.alignedSize, 0);
            std::memcpy(de.data.data(), ptr(blk.data_pos), blk.size);
            fileDataEntries.push_back(std::move(de));
        }

        // Raccogli nomi esterni
        if (blk.name_offset != 0 && blk.name_offset != NPOS &&
            blk.name_len > 0 &&
            blk.name_offset + blk.name_len <= fileSize_ &&
            !collectedNames.contains(blk.name_offset)) {
            collectedNames.insert(blk.name_offset);

            DataEntry ne;
            ne.oldPos = blk.name_offset;
            ne.size = blk.name_len;
            ne.alignedSize = alignUp(blk.name_len, 16);
            ne.data.resize(ne.alignedSize, 0);
            std::memcpy(ne.data.data(), ptr(blk.name_offset), blk.name_len);
            nameEntries.push_back(std::move(ne));
        }
    }

    // ===== Step 3: Calcola nuovo layout =====
    // Layout: [Blocchi][Padding][Dati][Padding][Nomi]

    std::unordered_map<size_t, size_t> blockReloc;
    std::unordered_map<size_t, size_t> dataReloc;
    std::unordered_map<size_t, size_t> nameReloc;

    size_t cursor = 0;

    // Blocchi
    for (const auto &[oldPos, block]: blocks) {
        blockReloc[oldPos] = cursor;
        cursor += sizeof(Block);
    }
    cursor = alignUp(cursor, PAGE_SIZE);

    // Dati file
    for (const auto &entry: fileDataEntries) {
        dataReloc[entry.oldPos] = cursor;
        cursor += entry.alignedSize;
    }

    // Nomi esterni
    if (!nameEntries.empty()) {
        cursor = alignUp(cursor, PAGE_SIZE);
        for (const auto &entry: nameEntries) {
            nameReloc[entry.oldPos] = cursor;
            cursor += entry.alignedSize;
        }
    }

    size_t newFileSize = alignUp(cursor, PAGE_SIZE);
    if (newFileSize == 0) newFileSize = PAGE_SIZE;

    // ===== Step 4: Aggiorna puntatori nei blocchi =====
    auto relocBlock = [&](size_t p) -> size_t {
        if (p == NPOS) return NPOS;
        auto it = blockReloc.find(p);
        return (it != blockReloc.end()) ? it->second : 0;
    };

    auto relocData = [&](size_t p) -> size_t {
        if (p == 0 || p == NPOS) return p;
        auto it = dataReloc.find(p);
        return (it != dataReloc.end()) ? it->second : 0;
    };

    auto relocName = [&](size_t p) -> size_t {
        if (p == 0 || p == NPOS) return p;
        auto it = nameReloc.find(p);
        return (it != nameReloc.end()) ? it->second : 0;
    };

    for (auto &[oldPos, block]: blocks) {
        Block &blk = block;

        // current = nuova posizione di questo blocco
        blk.current = blockReloc[oldPos];

        // Altri puntatori a blocchi
        blk.parent = relocBlock(blk.parent);
        blk.next = relocBlock(blk.next);
        blk.previous = relocBlock(blk.previous);
        blk.subdir_pos = relocBlock(blk.subdir_pos);

        // data_pos: per i FILE punta ai dati, per le DIRECTORY punta al primo file (blocco)
        if (blk.data_pos != 0 && blk.data_pos != NPOS) {
            if (blk.isFile) {
                blk.data_pos = relocData(blk.data_pos);
            } else {
                blk.data_pos = relocBlock(blk.data_pos);
            }
        }

        // Puntatore nome esterno
        if (blk.name_offset != 0 && blk.name_offset != NPOS) {
            blk.name_offset = relocName(blk.name_offset);
        }
    }

    // ===== Step 5: Costruisci immagine compattata =====
    std::vector<uint8_t> newImage(newFileSize, 0);

    // Scrivi blocchi
    for (const auto &[oldPos, block]: blocks) {
        size_t newPos = blockReloc[oldPos];
        std::memcpy(newImage.data() + newPos, &block, sizeof(Block));
    }

    // Scrivi dati file
    for (const auto &entry: fileDataEntries) {
        size_t newPos = dataReloc[entry.oldPos];
        std::memcpy(newImage.data() + newPos, entry.data.data(), entry.alignedSize);
    }

    // Scrivi nomi esterni
    for (const auto &entry: nameEntries) {
        size_t newPos = nameReloc[entry.oldPos];
        std::memcpy(newImage.data() + newPos, entry.data.data(), entry.alignedSize);
    }

    // ===== Step 6: Scrivi sul file =====
    if (newFileSize > allocSize_) {
        if (!remapFile(newFileSize))
            return false;
    }

    std::memcpy(mappedPtr_, newImage.data(), newFileSize);

    // ===== Step 7: Finalizza =====
    fileSize_ = newFileSize;
    dirty_ = true;
    sync();

    return truncateToSize(newFileSize);
}

// ==================== Raw I/O ====================

bool inode_raw::write(size_t pos, const void *data, size_t size) {
    if (fd_ < 0 || !data || size == 0)
        return false;

    size_t needed = pos + size;
    if (needed > allocSize_) {
        if (!remapFile(needed))
            return false;
    }

    if (needed > fileSize_)
        fileSize_ = needed;

    std::memcpy(static_cast<char *>(mappedPtr_) + pos, data, size);
    dirty_ = true;
    return true;
}

bool inode_raw::read(size_t pos, void *data, size_t size) const {
    if (fd_ < 0 || !data || size == 0)
        return false;
    if (pos + size > fileSize_)
        return false;
    if (!mappedPtr_)
        return false;

    std::memcpy(data, static_cast<const char *>(mappedPtr_) + pos, size);
    return true;
}

void *inode_raw::ptr(size_t pos) noexcept {
    if (!mappedPtr_ || pos >= allocSize_)
        return nullptr;
    return static_cast<char *>(mappedPtr_) + pos;
}

const void *inode_raw::ptr(size_t pos) const noexcept {
    if (!mappedPtr_ || pos >= allocSize_)
        return nullptr;
    return static_cast<const char *>(mappedPtr_) + pos;
}

// ==================== Block I/O ====================

bool inode_raw::readBlock(size_t pos, Block *block) const {
    return block && read(pos, block, sizeof(Block));
}

bool inode_raw::writeBlock(size_t pos, const Block *block) {
    return block && write(pos, block, sizeof(Block));
}

size_t inode_raw::appendBlock(const Block *block) {
    if (!block) return NPOS;

    size_t pos = allocate(sizeof(Block));
    if (pos == NPOS) return NPOS;

    if (!write(pos, block, sizeof(Block)))
        return NPOS;

    return pos;
}

// ==================== Sync ====================

void inode_raw::sync() {
    if (mappedPtr_ && dirty_ && fileSize_ > 0) {
        mman::sync(mappedPtr_, fileSize_);
        dirty_ = false;
    }
}
