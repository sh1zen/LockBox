#include "inode_raw.h"
#include "mman.h"

#include <fcntl.h>
#include <cstring>
#include <algorithm>
#include <ranges>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
// Non usare macro, usa funzioni wrapper inline
inline int posix_open(const char *path, int flags, int mode = 0) {
    return ::_open(path, flags, mode);
}

inline int posix_close(int fd) {
    return ::_close(fd);
}

inline int64_t posix_lseek(int fd, int64_t offset, int whence) {
    return ::_lseeki64(fd, offset, whence);
}

inline int posix_ftruncate(int fd, int64_t size) {
    return ::_chsize_s(fd, size);
}
#ifndef O_RDWR
#define O_RDWR  _O_RDWR
#define O_CREAT _O_CREAT
#define O_TRUNC _O_TRUNC
#endif
#else
#include <unistd.h>
inline int posix_open(const char *path, int flags, int mode = 0) {
    return ::open(path, flags, mode);
}
inline int posix_close(int fd) {
    return ::close(fd);
}
inline off_t posix_lseek(int fd, off_t offset, int whence) {
    return ::lseek(fd, offset, whence);
}
inline int posix_ftruncate(int fd, off_t size) {
    return ::ftruncate(fd, size);
}
#endif

// ====================== Lifecycle ======================

inode_raw::inode_raw() : fd_(-1) {
}

inode_raw::~inode_raw() { close(); }

inode_raw::inode_raw(inode_raw &&other) noexcept
    : fd_(other.fd_)
      , path_(std::move(other.path_))
      , freeList_(std::move(other.freeList_)) {
    other.fd_ = -1;
}

inode_raw &inode_raw::operator=(inode_raw &&other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        path_ = std::move(other.path_);
        freeList_ = std::move(other.freeList_);
        other.fd_ = -1;
    }
    return *this;
}

// ====================== File Operations ======================

bool inode_raw::open(const std::string &path) {
    if (fd_ >= 0) close();

    fd_ = posix_open(path.c_str(), O_RDWR);
    if (fd_ < 0) return false;

    path_ = path;

    if (getFileSize() < sizeof(Block)) {
        close();
        return false;
    }

    return true;
}

bool inode_raw::create(const std::string &path) {
    if (fd_ >= 0) close();

#ifdef _WIN32
    fd_ = posix_open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, _S_IREAD | _S_IWRITE);
#else
    fd_ = posix_open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
#endif
    if (fd_ < 0) return false;

    path_ = path;
    return true;
}

void inode_raw::close() {
    if (fd_ >= 0) {
        posix_close(fd_);
        fd_ = -1;
    }
    path_.clear();
    freeList_.clear();
}

bool inode_raw::isOpen() const { return fd_ >= 0; }

const std::string &inode_raw::getPath() const { return path_; }

// ====================== Size & Space ======================

size_t inode_raw::getFileSize() const {
    if (fd_ < 0) return 0;

    const auto cur = posix_lseek(fd_, 0, SEEK_CUR);
    const auto size = posix_lseek(fd_, 0, SEEK_END);
    posix_lseek(fd_, cur, SEEK_SET);

    return static_cast<size_t>(size);
}

bool inode_raw::resize(const size_t newSize) const {
    if (fd_ < 0) return false;
    return posix_ftruncate(fd_, static_cast<int64_t>(newSize)) == 0;
}

size_t inode_raw::allocate(size_t size) {
    if (const size_t pos = findFreeSpace(size); pos != NPOS) return pos;
    return getFileSize();
}

void inode_raw::free(size_t pos, size_t size) {
    if (size == 0) return;
    freeList_.emplace_back(pos, size);
}

size_t inode_raw::getFreeSpace() const {
    size_t total = 0;
    for (const auto &sz: freeList_ | std::views::values)
        total += sz;
    return total;
}

size_t inode_raw::getFragmentCount() const {
    return freeList_.size();
}

// ====================== Raw I/O ======================

bool inode_raw::write(size_t pos, const void *data, size_t size) const {
    if (fd_ < 0 || !data || size == 0) return false;

    size_t fileSize = getFileSize();

    if (const size_t needed = pos + size; needed > fileSize) {
        if (!resize(needed)) return false;
        fileSize = needed;
    }

    const mman::MappedMemory mapping(
        nullptr, fileSize,
        mman::Prot::Read | mman::Prot::Write,
        mman::MapFlags::Shared,
        fd_, 0
    );

    if (!mapping) return false;

    memcpy(mapping.as<char>() + pos, data, size);
    (void) mman::sync(mapping.get(), fileSize);

    return true;
}

bool inode_raw::read(size_t pos, void *data, size_t size) const {
    if (fd_ < 0 || !data || size == 0) return false;

    const size_t fileSize = getFileSize();
    if (pos + size > fileSize) return false;

    const mman::MappedMemory mapping(
        nullptr, fileSize,
        mman::Prot::Read,
        mman::MapFlags::Shared,
        fd_, 0
    );

    if (!mapping) return false;

    memcpy(data, mapping.as<const char>() + pos, size);

    return true;
}

// ====================== Block I/O ======================

bool inode_raw::readBlock(size_t pos, Block *block) const {
    if (!block) return false;
    return read(pos, block, sizeof(Block));
}

bool inode_raw::writeBlock(size_t pos, const Block *block) const {
    if (!block) return false;
    return write(pos, block, sizeof(Block));
}

size_t inode_raw::appendBlock(const Block *block) {
    if (!block) return NPOS;

    const size_t pos = allocate(sizeof(Block));
    if (!write(pos, block, sizeof(Block))) return NPOS;

    return pos;
}

// ====================== Free List Management ======================

size_t inode_raw::findFreeSpace(size_t size) {
    for (auto it = freeList_.begin(); it != freeList_.end(); ++it) {
        if (it->second >= size) {
            const size_t pos = it->first;

            if (it->second > size) {
                it->first += size;
                it->second -= size;
            } else {
                freeList_.erase(it);
            }

            return pos;
        }
    }
    return NPOS;
}

void inode_raw::defragmentFreeList() {
    if (freeList_.size() < 2) return;

    std::ranges::sort(freeList_,
                      [](const auto &a, const auto &b) { return a.first < b.first; });

    mergeFreeList();
}

void inode_raw::mergeFreeList() {
    if (freeList_.size() < 2) return;

    std::vector<std::pair<size_t, size_t> > merged;
    merged.reserve(freeList_.size());
    merged.push_back(freeList_[0]);

    for (size_t i = 1; i < freeList_.size(); ++i) {
        auto &[fst, snd] = merged.back();

        if (const auto &curr = freeList_[i]; fst + snd >= curr.first) {
            const size_t newEnd = std::max(fst + snd, curr.first + curr.second);
            snd = newEnd - fst;
        } else {
            merged.push_back(curr);
        }
    }

    freeList_ = std::move(merged);
}

const std::vector<std::pair<size_t, size_t> > &inode_raw::getFreeList() const {
    return freeList_;
}
