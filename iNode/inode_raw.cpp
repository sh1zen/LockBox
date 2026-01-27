#include "inode_raw.h"
#include "mman.h"

#include <fcntl.h>
#include <cstring>
#include <algorithm>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#define O_RDWR  _O_RDWR
#define O_CREAT _O_CREAT
#define O_TRUNC _O_TRUNC

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
    : fd_(-1), mappedPtr_(nullptr), mappedSize_(0),
      fileSize_(0), allocSize_(0), dirty_(false) {
}

inode_raw::~inode_raw() { close(); }

inode_raw::inode_raw(inode_raw &&o) noexcept
    : fd_(o.fd_), path_(std::move(o.path_)), freeList_(std::move(o.freeList_)),
      mappedPtr_(o.mappedPtr_), mappedSize_(o.mappedSize_),
      fileSize_(o.fileSize_), allocSize_(o.allocSize_), dirty_(o.dirty_) {
    o.fd_ = -1;
    o.mappedPtr_ = nullptr;
    o.mappedSize_ = o.fileSize_ = o.allocSize_ = 0;
    o.dirty_ = false;
}

inode_raw &inode_raw::operator=(inode_raw &&o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        path_ = std::move(o.path_);
        freeList_ = std::move(o.freeList_);
        mappedPtr_ = o.mappedPtr_;
        mappedSize_ = o.mappedSize_;
        fileSize_ = o.fileSize_;
        allocSize_ = o.allocSize_;
        dirty_ = o.dirty_;
        o.fd_ = -1;
        o.mappedPtr_ = nullptr;
        o.mappedSize_ = o.fileSize_ = o.allocSize_ = 0;
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
        if (dirty_ && fileSize_ > 0)
            mman::sync(mappedPtr_, fileSize_);
        mman::unmap(mappedPtr_, mappedSize_);
        mappedPtr_ = nullptr;
        mappedSize_ = 0;
        dirty_ = false;
    }
}

bool inode_raw::shrinkFile(size_t newSize) {
    if (fd_ < 0 || newSize >= fileSize_) return false;

    size_t alignedSize = alignUp(newSize, PAGE_SIZE);

    unmapFile();

    if (p_ftrunc(fd_, static_cast<int64_t>(alignedSize)) != 0)
        return false;

    // Remap with new size
    auto res = mman::map(nullptr, alignedSize,
                         mman::Prot::Read | mman::Prot::Write,
                         mman::MapFlags::Shared, fd_, 0);
    if (!res.ok()) return false;

    mappedPtr_ = res.ptr;
    mappedSize_ = alignedSize;
    allocSize_ = alignedSize;
    fileSize_ = newSize;
    return true;
}

// Pattern: lseek + write(1 byte) per estendere, poi mmap
bool inode_raw::extendFile(size_t newAllocSize) {
    if (fd_ < 0 || newAllocSize == 0) return false;

    // Seek to last byte position and write 1 byte
    if (p_lseek(fd_, static_cast<int64_t>(newAllocSize - 1), SEEK_SET) == -1)
        return false;
    if (p_write(fd_, "", 1) != 1)
        return false;

    return true;
}

bool inode_raw::remapFile(size_t newAllocSize) {
    if (fd_ < 0) return false;
    if (mappedPtr_ && allocSize_ >= newAllocSize) return true;

    // Align to page size
    size_t targetAlloc = alignUp(newAllocSize, PAGE_SIZE);

    // Unmap existing
    unmapFile();

    // Extend file on disk using lseek+write pattern
    if (!extendFile(targetAlloc))
        return false;

    // Map the file
    auto res = mman::map(nullptr, targetAlloc,
                         mman::Prot::Read | mman::Prot::Write,
                         mman::MapFlags::Shared, fd_, 0);
    if (!res.ok()) return false;

    mappedPtr_ = res.ptr;
    mappedSize_ = targetAlloc;
    allocSize_ = targetAlloc;
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
        // Truncate to actual logical size
        if (fileSize_ > 0)
            p_ftrunc(fd_, static_cast<int64_t>(fileSize_));
        p_close(fd_);
        fd_ = -1;
    }

    path_.clear();
    freeList_.clear();
    fileSize_ = allocSize_ = 0;
}

// ==================== Size Management ====================

bool inode_raw::reserve(size_t capacity) {
    if (capacity <= allocSize_) return true;
    return remapFile(capacity);
}

bool inode_raw::resize(size_t newSize) {
    if (newSize > allocSize_) {
        if (!remapFile(newSize)) return false;
    }
    fileSize_ = newSize;
    dirty_ = true;
    return true;
}

// ==================== Allocation ====================

size_t inode_raw::allocate(size_t size) {
    if (size == 0) return NPOS;

    size = alignUp(size, PAGE_SIZE);

    // Try free list (best-fit)
    if (size_t pos = findFree(size); pos != NPOS)
        return pos;

    // Allocate from end
    size_t pos = fileSize_;
    size_t newSize = pos + size;

    if (newSize > allocSize_) {
        if (!remapFile(newSize)) return NPOS;
    }

    fileSize_ = newSize;
    return pos;
}

void inode_raw::free(size_t pos, size_t size) {
    if (size == 0) return;

    // Se liberiamo alla fine del file, shrink immediato
    if (pos + size >= fileSize_) {
        fileSize_ = pos;
        // Rimuovi eventuali blocchi liberi che ora sono oltre fileSize_
        while (!freeList_.empty() && freeList_.back().first >= fileSize_) {
            freeList_.pop_back();
        }
        // Tronca l'ultimo blocco se si sovrappone
        if (!freeList_.empty()) {
            auto &last = freeList_.back();
            if (last.first + last.second > fileSize_) {
                last.second = fileSize_ - last.first;
                if (last.second == 0) freeList_.pop_back();
            }
        }
        return;
    }

    auto it = std::lower_bound(freeList_.begin(), freeList_.end(), pos,
                               [](const auto &p, size_t v) { return p.first < v; });

    freeList_.insert(it, {pos, size});
    mergeFree();
}

std::vector<std::pair<size_t, size_t> >::iterator
inode_raw::findAdjacentFree(size_t pos, size_t size) {
    size_t endPos = pos + size;

    for (auto it = freeList_.begin(); it != freeList_.end(); ++it) {
        if (it->first == endPos) return it; // blocco libero subito dopo
        if (it->first > endPos) break; // sorted, non troveremo più
    }
    return freeList_.end();
}

bool inode_raw::tryExpand(size_t pos, size_t currentSize, size_t newSize) {
    if (newSize <= currentSize) return true; // già abbastanza grande

    size_t needed = newSize - currentSize;
    size_t endPos = pos + currentSize;

    // Caso 1: siamo alla fine del file, espandi direttamente
    if (endPos == fileSize_) {
        size_t newFileSize = pos + newSize;
        if (newFileSize > allocSize_) {
            if (!remapFile(newFileSize)) return false;
        }
        fileSize_ = newFileSize;
        return true;
    }

    // Caso 2: c'è un blocco libero adiacente abbastanza grande
    auto adj = findAdjacentFree(pos, currentSize);
    if (adj != freeList_.end() && adj->second >= needed) {
        if (adj->second == needed) {
            freeList_.erase(adj);
        } else {
            adj->first += needed;
            adj->second -= needed;
        }
        return true;
    }

    return false;
}

size_t inode_raw::reallocate(size_t pos, size_t oldSize, size_t newSize) {
    if (pos == NPOS) return allocate(newSize);
    if (newSize == 0) {
        free(pos, oldSize);
        return NPOS;
    }

    oldSize = alignUp(oldSize, PAGE_SIZE);
    newSize = alignUp(newSize, PAGE_SIZE);

    if (newSize == oldSize) return pos;

    // Caso: nuovo più piccolo → libera la differenza
    if (newSize < oldSize) {
        free(pos + newSize, oldSize - newSize);
        return pos;
    }

    // Caso: nuovo più grande → prova espansione in-place
    if (tryExpand(pos, oldSize, newSize)) {
        return pos;
    }

    // Caso: devo riallocare altrove
    size_t newPos = allocate(newSize);
    if (newPos == NPOS) return NPOS;

    // Copia dati
    if (mappedPtr_) {
        std::memmove(static_cast<char *>(mappedPtr_) + newPos,
                     static_cast<char *>(mappedPtr_) + pos,
                     oldSize);
    }

    // Libera vecchia posizione
    free(pos, oldSize);
    dirty_ = true;

    return newPos;
}

size_t inode_raw::getFreeSpace() const noexcept {
    size_t total = 0;
    for (const auto &[p, s]: freeList_) total += s;
    return total;
}

size_t inode_raw::findFree(size_t size) {
    if (freeList_.empty()) return NPOS;

    auto best = freeList_.end();
    size_t bestSz = SIZE_MAX;

    for (auto it = freeList_.begin(); it != freeList_.end(); ++it) {
        if (it->second >= size && it->second < bestSz) {
            best = it;
            bestSz = it->second;
            if (bestSz == size) break; // exact fit
        }
    }

    if (best == freeList_.end()) return NPOS;

    size_t pos = best->first;
    if (best->second > size) {
        best->first += size;
        best->second -= size;
    } else {
        freeList_.erase(best);
    }
    return pos;
}

void inode_raw::mergeFree() {
    if (freeList_.size() < 2) return;

    auto it = freeList_.begin();
    while (it != freeList_.end() && std::next(it) != freeList_.end()) {
        auto nx = std::next(it);
        if (it->first + it->second >= nx->first) {
            size_t end = std::max(it->first + it->second, nx->first + nx->second);
            it->second = end - it->first;
            freeList_.erase(nx);
        } else {
            ++it;
        }
    }
}

void inode_raw::defragmentFreeList() {
    if (freeList_.empty()) return;

    // Sort by offset
    std::sort(freeList_.begin(), freeList_.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });

    // Merge adjacent blocks
    std::vector<std::pair<size_t, size_t> > merged;
    merged.reserve(freeList_.size());
    merged.push_back(freeList_[0]);

    for (size_t i = 1; i < freeList_.size(); ++i) {
        auto &last = merged.back();
        const auto &curr = freeList_[i];
        if (last.first + last.second >= curr.first) {
            size_t end = std::max(last.first + last.second, curr.first + curr.second);
            last.second = end - last.first;
        } else {
            merged.push_back(curr);
        }
    }

    freeList_ = std::move(merged);

    // Shrink: rimuovi tutto lo spazio libero alla fine del file
    while (!freeList_.empty()) {
        auto &last = freeList_.back();
        if (last.first + last.second >= fileSize_) {
            // Questo blocco libero è alla fine, riduci fileSize_
            fileSize_ = last.first;
            freeList_.pop_back();
        } else {
            break;
        }
    }
}

void inode_raw::compact() {
    defragmentFreeList();

    if (fileSize_ == 0) return;

    // Shrink file fisico se allocSize_ >> fileSize_
    size_t alignedSize = alignUp(fileSize_, PAGE_SIZE);
    if (allocSize_ > alignedSize) {
        shrinkFile(fileSize_);
    }
}

// ==================== Raw I/O ====================

bool inode_raw::write(size_t pos, const void *data, size_t size) {
    if (fd_ < 0 || !data || size == 0) return false;

    size_t needed = pos + size;
    if (needed > allocSize_) {
        if (!remapFile(needed)) return false;
    }
    if (needed > fileSize_) fileSize_ = needed;

    std::memcpy(static_cast<char *>(mappedPtr_) + pos, data, size);
    dirty_ = true;
    return true;
}

bool inode_raw::read(size_t pos, void *data, size_t size) const {
    if (fd_ < 0 || !data || size == 0) return false;
    if (pos + size > fileSize_) return false;
    if (!mappedPtr_) return false;

    std::memcpy(data, static_cast<const char *>(mappedPtr_) + pos, size);
    return true;
}

void *inode_raw::ptr(size_t pos) noexcept {
    if (!mappedPtr_ || pos >= allocSize_) return nullptr;
    return static_cast<char *>(mappedPtr_) + pos;
}

const void *inode_raw::ptr(size_t pos) const noexcept {
    if (!mappedPtr_ || pos >= allocSize_) return nullptr;
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
    if (!write(pos, block, sizeof(Block))) return NPOS;
    return pos;
}

// ==================== Sync ====================

void inode_raw::sync() {
    if (mappedPtr_ && dirty_ && fileSize_ > 0) {
        mman::sync(mappedPtr_, fileSize_);
        dirty_ = false;
    }
}
