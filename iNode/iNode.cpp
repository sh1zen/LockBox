#include "iNode.h"

#include <iostream>
#include <fstream>
#include <chrono>

#include "interface.h"
#include "filesystem.h"
#include "OES.h"

// ═══════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR / DESTRUCTOR
// ═══════════════════════════════════════════════════════════════════════════

iNode::iNode(const std::string &path, OES *engine)
    : root_(std::make_unique<Block>()), cipher_(engine), path_(path) {
    Block::setCipherEngine(engine);

    if (storage_.open(path)) {
        if (!storage_.readBlock(0, root_.get()))
            throw std::runtime_error("Failed to read root block: " + path);
    } else {
        if (!storage_.create(path))
            throw std::runtime_error("Failed to create iNode: " + path);

        root_->reset();
        root_->setName("root");
        root_->setCreatedNow();
        root_->setModifiedNow();
        root_->current = storage_.allocate(sizeof(Block));
        storage_.writeBlock(root_->current, root_.get());
        storage_.sync();
    }
}

iNode::~iNode() {
    storage_.sync();
    storage_.close();
}

// ═══════════════════════════════════════════════════════════════════════════
// DIRECT BLOCK ACCESS (zero-copy via mmap)
// ═══════════════════════════════════════════════════════════════════════════

Block *iNode::blockAt(size_t pos) const {
    return pos ? static_cast<Block *>(const_cast<inode_raw &>(storage_).ptr(pos)) : nullptr;
}

// ═══════════════════════════════════════════════════════════════════════════
// SYNC OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

void iNode::syncRoot() const {
    if (const auto *b = static_cast<const Block *>(storage_.ptr(root_->current)))
        *root_ = *b;
}

void iNode::commitRoot() const {
    storage_.writeBlock(root_->current, root_.get());
    storage_.sync();
}

void iNode::sync() const {
    storage_.sync();
    syncRoot();
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

std::pair<char *, size_t> iNode::encryptData(const char *data, size_t size) const {
    if (!data || size == 0) return {nullptr, 0};
    if (!cipher_) {
        auto *copy = static_cast<char *>(malloc(size));
        if (copy) memcpy(copy, data, size);
        return {copy, size};
    }
    try {
        cipher_->resetBlocks();
        cipher_->load_data_raw(const_cast<char *>(data), size);
        cipher_->enc_adv();
        auto *cb = cipher_->get_cipherBlock();
        if (!cb || cb->isNull()) goto fallback;
        auto [exp, len] = exportBlock(cb, OES_TYPE_RAW_UINT8);
        if (!exp || len == 0) goto fallback;
        return {static_cast<char *>(exp), len};
    } catch (...) {
    }
fallback:
    auto *copy = static_cast<char *>(malloc(size));
    if (copy) memcpy(copy, data, size);
    return {copy, size};
}

std::pair<char *, size_t> iNode::decryptData(const char *data, size_t size) const {
    if (!data || size == 0) return {nullptr, 0};
    if (!cipher_) {
        auto *copy = static_cast<char *>(malloc(size));
        if (copy) memcpy(copy, data, size);
        return {copy, size};
    }
    try {
        cipher_->resetBlocks();
        cipher_->load_cipher_data_raw(const_cast<char *>(data), size);
        cipher_->dec_adv();
        auto *pb = cipher_->get_plainBlock();
        if (!pb || pb->isNull()) goto fallback;
        auto [exp, len] = exportBlock(pb, OES_TYPE_UINT8);
        if (!exp || len == 0) goto fallback;
        return {static_cast<char *>(exp), len};
    } catch (...) {
    }
fallback:
    auto *copy = static_cast<char *>(malloc(size));
    if (copy) memcpy(copy, data, size);
    return {copy, size};
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL BLOCK OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

size_t iNode::insertBlock(Block *block) const {
    size_t pos = storage_.allocate(sizeof(Block));
    if (pos == inode_raw::NPOS) return 0;
    block->current = pos;
    storage_.writeBlock(pos, block);
    return pos;
}

void iNode::updateBlock(const Block *block) const {
    storage_.writeBlock(block->current, block);
}

void iNode::unlinkBlock(const Block *block) const {
    // Update sibling links
    if (block->previous) {
        if (auto *prev = blockAt(block->previous)) {
            prev->next = block->next;
            updateBlock(prev);
        }
    }
    if (block->next) {
        if (auto *next = blockAt(block->next)) {
            next->previous = block->previous;
            updateBlock(next);
        }
    }

    // Update parent's head pointer
    if (Block *parent = block->parent ? blockAt(block->parent) : root_.get()) {
        bool updated = false;
        if (block->isFile && parent->data_pos == block->current) {
            parent->data_pos = block->next;
            updated = true;
        } else if (!block->isFile && parent->subdir_pos == block->current) {
            parent->subdir_pos = block->next;
            updated = true;
        }
        if (updated) {
            if (block->parent) updateBlock(parent);
            else commitRoot();
        }
    }
    // Note: space is not reclaimed until defragment() is called
}

Block *iNode::findBlock(const std::string &plainPath, bool isFile) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return nullptr;

    Block *cur = root_.get();
    size_t start = 0, end;

    while ((end = norm.find('/', start)) != std::string::npos || start < norm.length()) {
        if (end == std::string::npos) end = norm.length();
        if (end <= start) {
            start = end + 1;
            continue;
        }

        std::string token = norm.substr(start, end - start);
        bool lastComponent = (end >= norm.length());

        size_t searchPos = lastComponent && isFile ? cur->data_pos : cur->subdir_pos;
        Block *found = nullptr;

        for (auto *b = blockAt(searchPos); b; b = blockAt(b->next)) {
            if (b->nameEquals(token)) {
                found = b;
                break;
            }
        }
        if (!found) return nullptr;
        cur = found;
        start = end + 1;
    }
    return cur;
}

Block *iNode::findParent(const std::string &plainPath) const {
    std::string norm = normalizePath(plainPath);
    size_t lastSlash = norm.rfind('/');
    if (lastSlash == std::string::npos) return root_.get();
    return findBlock(norm.substr(0, lastSlash), false);
}

size_t iNode::ensureDirChain(const std::string &plainPath) const {
    std::string norm = normalizePath(plainPath);
    Block *parent = root_.get();
    uint32_t level = 1;
    size_t start = 0, end;

    while ((end = norm.find('/', start)) != std::string::npos || start < norm.length()) {
        if (end == std::string::npos) end = norm.length();
        if (end <= start) {
            start = end + 1;
            continue;
        }

        std::string token = norm.substr(start, end - start);

        Block *found = nullptr;
        for (auto *b = blockAt(parent->subdir_pos); b; b = blockAt(b->next)) {
            if (b->nameEquals(token)) {
                found = b;
                break;
            }
        }

        if (found) {
            parent = found;
            level++;
            start = end + 1;
            continue;
        }

        auto newDir = std::make_unique<Block>();
        newDir->reset();
        newDir->setName(token);
        newDir->isFile = false;
        newDir->level = level;
        newDir->parent = parent->current;
        newDir->setCreatedNow();
        newDir->setModifiedNow();
        newDir->current = insertBlock(newDir.get());

        if (parent->subdir_pos == 0) {
            parent->subdir_pos = newDir->current;
        } else {
            Block *last = blockAt(parent->subdir_pos);
            while (last && last->next) last = blockAt(last->next);
            if (last) {
                last->next = newDir->current;
                newDir->previous = last->current;
                updateBlock(last);
                updateBlock(newDir.get());
            }
        }
        parent->folders_n++;
        parent->setModifiedNow();

        if (parent == root_.get()) commitRoot();
        else updateBlock(parent);

        parent = blockAt(newDir->current);
        level++;
        start = end + 1;
    }
    sync();
    return parent->current;
}

size_t iNode::createFileBlock(const std::string &plainName, const char *encData,
                              size_t encSize, size_t parentPos) const {
    Block *parent = parentPos ? blockAt(parentPos) : root_.get();
    if (!parent || parent->isFile) return 0;

    const auto fb = std::make_unique<Block>();
    fb->reset();
    fb->setName(plainName);
    fb->isFile = true;
    fb->level = parent->level + 1;
    fb->parent = parentPos;
    fb->size = encSize;
    fb->setCreatedNow();
    fb->setModifiedNow();

    if (encData && encSize > 0) {
        fb->data_pos = storage_.allocate(encSize);
        if (fb->data_pos == inode_raw::NPOS) return 0;
        storage_.write(fb->data_pos, encData, encSize);
    }
    fb->current = insertBlock(fb.get());
    if (fb->current == 0) return 0;

    if (parent->data_pos == 0) {
        parent->data_pos = fb->current;
    } else {
        Block *last = blockAt(parent->data_pos);
        while (last && last->next) last = blockAt(last->next);
        if (last) {
            last->next = fb->current;
            fb->previous = last->current;
            updateBlock(last);
            updateBlock(fb.get());
        }
    }
    parent->files_n++;
    parent->setModifiedNow();

    if (parentPos == 0) commitRoot();
    else updateBlock(parent);

    sync();
    return fb->current;
}

std::pair<std::unique_ptr<char[]>, size_t> iNode::readFileData(Block *block) const {
    if (!block || block->size == 0) return {nullptr, 0};

    const char *src = static_cast<const char *>(storage_.ptr(block->data_pos));
    if (!src) return {nullptr, 0};

    if (cipher_) {
        auto [dec, decSize] = decryptData(src, block->size);
        if (dec && decSize > 0) {
            auto result = std::make_unique<char[]>(decSize);
            memcpy(result.get(), dec, decSize);
            free(dec);
            return {std::move(result), decSize};
        }
    }
    auto data = std::make_unique<char[]>(block->size);
    memcpy(data.get(), src, block->size);
    return {std::move(data), block->size};
}

// ═══════════════════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════════════════

void iNode::logOperation(const std::string &op, const std::string &details) const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

    std::string entry = std::string("[") + buf + "] " + op;
    if (!details.empty()) entry += ": " + details;
    entry += "\n";

    if (auto *logBlock = findBlock(LOG_INTERNAL_PATH, true)) {
        auto [existing, existingSize] = readFileData(logBlock);
        std::string fullLog;
        if (existing && existingSize > 0)
            fullLog = std::string(existing.get(), existingSize);
        fullLog += entry;

        auto [encData, encSize] = encryptData(fullLog.c_str(), fullLog.size());
        size_t newPos = storage_.reallocate(logBlock->data_pos, logBlock->size, encSize);
        if (newPos != inode_raw::NPOS) {
            storage_.write(newPos, encData, encSize);
            logBlock->data_pos = newPos;
            logBlock->size = encSize;
            logBlock->setModifiedNow();
            updateBlock(logBlock);
        }
        free(encData);
    } else {
        auto [encData, encSize] = encryptData(entry.c_str(), entry.size());
        createFileBlock(LOG_INTERNAL_PATH, encData, encSize, 0);
        free(encData);
    }
    sync();
}

std::string iNode::getLog() const {
    auto *logBlock = findBlock(LOG_INTERNAL_PATH, true);
    if (!logBlock) return "(No log available)\n";
    auto [data, size] = const_cast<iNode *>(this)->readFileData(logBlock);
    if (!data || size == 0) return "(Empty log)\n";
    return std::string(data.get(), size);
}

void iNode::clearLog() {
    auto *logBlock = findBlock(LOG_INTERNAL_PATH, true);
    if (!logBlock) return;

    std::string empty = "[Log cleared]\n";
    auto [encData, encSize] = encryptData(empty.c_str(), empty.size());
    size_t newPos = storage_.reallocate(logBlock->data_pos, logBlock->size, encSize);
    if (newPos != inode_raw::NPOS) {
        storage_.write(newPos, encData, encSize);
        logBlock->data_pos = newPos;
        logBlock->size = encSize;
        logBlock->setModifiedNow();
        updateBlock(logBlock);
    }
    free(encData);
    sync();
}

size_t iNode::getLogSize() const {
    auto *logBlock = findBlock(LOG_INTERNAL_PATH, true);
    return logBlock ? logBlock->size : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

size_t iNode::addFile(const std::string &plainPath, const char *data, size_t size) {
    if (!data || size == 0) return 0;
    if (exists(plainPath, true)) return 0;

    std::string norm = normalizePath(plainPath);
    size_t lastSlash = norm.rfind('/');
    std::string dirPath = (lastSlash == std::string::npos) ? "" : norm.substr(0, lastSlash);
    std::string fileName = (lastSlash == std::string::npos) ? norm : norm.substr(lastSlash + 1);

    size_t parentPos = dirPath.empty() ? 0 : ensureDirChain(dirPath);

    auto [encData, encSize] = encryptData(data, size);
    size_t pos = createFileBlock(fileName, encData, encSize, parentPos);
    free(encData);

    if (pos > 0) logOperation("ADD_FILE", plainPath + " (" + std::to_string(size) + " bytes)");
    return pos;
}

size_t iNode::addDirectory(const std::string &plainPath) const {
    if (exists(plainPath, false)) return 0;
    size_t result = ensureDirChain(normalizePath(plainPath));
    if (result > 0) logOperation("ADD_DIR", plainPath);
    return result;
}

bool iNode::removeFile(const std::string &plainPath) const {
    auto *block = findBlock(plainPath, true);
    if (!block) return false;

    // Note: data space not reclaimed until defragment()
    size_t parentPos = block->parent;
    unlinkBlock(block);

    if (Block *parent = parentPos ? blockAt(parentPos) : root_.get(); parent && parent->files_n > 0) {
        parent->files_n--;
        parent->setModifiedNow();
        if (parentPos) updateBlock(parent);
        else commitRoot();
    }
    sync();
    logOperation("REMOVE_FILE", plainPath);
    return true;
}

bool iNode::removeDirectory(const std::string &plainPath, bool force) const {
    auto *block = findBlock(plainPath, false);
    if (!block) return false;
    if (!force && (block->subdir_pos || block->data_pos)) return false;

    size_t parentPos = block->parent;
    unlinkBlock(block);

    if (Block *parent = parentPos ? blockAt(parentPos) : root_.get(); parent && parent->folders_n > 0) {
        parent->folders_n--;
        parent->setModifiedNow();
        if (parentPos) updateBlock(parent);
        else commitRoot();
    }
    sync();
    logOperation("REMOVE_DIR", plainPath);
    return true;
}

bool iNode::removeDirectoryRecursive(const std::string &plainPath) {
    auto *block = findBlock(plainPath, false);
    if (!block) return false;

    std::string normPlain = normalizePath(plainPath);
    std::vector<std::pair<std::string, bool> > toDelete;

    walk(plainPath, [&](Block *b, const std::string &p, iNode *) {
        std::string normP = normalizePath(p);
        if (normP != normPlain && !normP.empty())
            toDelete.emplace_back(p, b->isFile);
    });

    std::sort(toDelete.begin(), toDelete.end(), [](const auto &a, const auto &b) {
        size_t da = std::count(a.first.begin(), a.first.end(), '/');
        size_t db = std::count(b.first.begin(), b.first.end(), '/');
        if (da != db) return da > db;
        return a.second && !b.second;
    });

    for (const auto &[path, isFile]: toDelete) {
        if (isFile) {
            if (auto *f = findBlock(path, true)) {
                size_t pp = f->parent;
                unlinkBlock(f);
                if (auto *fp = pp ? blockAt(pp) : nullptr) {
                    if (fp->files_n > 0) fp->files_n--;
                    updateBlock(fp);
                }
            }
        } else {
            if (auto *d = findBlock(path, false)) {
                size_t pp = d->parent;
                unlinkBlock(d);
                if (auto *dp = pp ? blockAt(pp) : nullptr) {
                    if (dp->folders_n > 0) dp->folders_n--;
                    updateBlock(dp);
                }
            }
        }
    }

    block = findBlock(plainPath, false);
    if (block) {
        size_t parentPos = block->parent;
        unlinkBlock(block);
        Block *parent = parentPos ? blockAt(parentPos) : root_.get();
        if (parent && parent->folders_n > 0) {
            parent->folders_n--;
            parent->setModifiedNow();
            if (parentPos) updateBlock(parent);
            else commitRoot();
        }
    }
    sync();
    logOperation("REMOVE_DIR_RECURSIVE", plainPath);
    return true;
}

bool iNode::remove(const std::string &plainPath) {
    if (findBlock(plainPath, true)) return removeFile(plainPath);
    if (findBlock(plainPath, false)) return removeDirectoryRecursive(plainPath);
    return false;
}

std::pair<char *, size_t> iNode::readFile(const std::string &plainPath) const {
    auto *block = findBlock(plainPath, true);
    if (!block) return {nullptr, 0};

    block->setAccessedNow();
    updateBlock(block);

    auto [data, size] = readFileData(block);
    if (!data) return {nullptr, 0};

    logOperation("READ_FILE", plainPath);
    return {data.release(), size};
}

bool iNode::updateFile(const std::string &plainPath, const char *data, size_t size) const {
    auto *block = findBlock(plainPath, true);
    if (!block) return false;

    auto [encData, encSize] = encryptData(data, size);
    size_t newPos = storage_.reallocate(block->data_pos, block->size, encSize);
    if (newPos == inode_raw::NPOS) {
        free(encData);
        return false;
    }
    storage_.write(newPos, encData, encSize);

    block->data_pos = newPos;
    block->size = encSize;
    block->setModifiedNow();
    updateBlock(block);
    free(encData);

    sync();
    logOperation("UPDATE_FILE", plainPath + " (" + std::to_string(size) + " bytes)");
    return true;
}

bool iNode::exists(const std::string &plainPath, bool isFile) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return !isFile;
    return findBlock(plainPath, isFile) != nullptr;
}

bool iNode::rename(const std::string &plainPath, const std::string &newName) const {
    if (newName.find('/') != std::string::npos || newName.empty()) return false;

    auto *block = findBlock(plainPath, true);
    if (!block) block = findBlock(plainPath, false);
    if (!block) return false;

    std::string norm = normalizePath(plainPath);
    size_t lastSlash = norm.rfind('/');
    std::string parentPath = (lastSlash == std::string::npos) ? "" : norm.substr(0, lastSlash);

    std::string newFullPath = parentPath.empty() ? newName : parentPath + "/" + newName;
    if (exists(newFullPath, true) || exists(newFullPath, false)) return false;

    block->setName(newName);
    block->setModifiedNow();
    updateBlock(block);
    sync();
    logOperation("RENAME", plainPath + " -> " + newName);
    return true;
}

bool iNode::move(const std::string &srcPath, const std::string &destPath) const {
    bool isFile = exists(srcPath, true);
    auto *src = findBlock(srcPath, isFile);
    if (!src) {
        src = findBlock(srcPath, false);
        isFile = false;
    }
    if (!src) return false;

    std::string normDest = normalizePath(destPath);
    std::string destDir, destName;

    if (exists(destPath, false)) {
        destDir = normDest;
        destName = src->getPlainName();
    } else {
        size_t lastSlash = normDest.rfind('/');
        destDir = (lastSlash == std::string::npos) ? "" : normDest.substr(0, lastSlash);
        destName = (lastSlash == std::string::npos) ? normDest : normDest.substr(lastSlash + 1);
    }

    const size_t destParentPos = destDir.empty() ? 0 : ensureDirChain(destDir);
    std::string fullDest = destDir.empty() ? destName : destDir + "/" + destName;
    if (exists(fullDest, true) || exists(fullDest, false)) return false;

    // Update old parent
    size_t oldParentPos = src->parent;
    Block *oldParent = oldParentPos ? blockAt(oldParentPos) : root_.get();
    if (oldParent) {
        if (isFile) { if (oldParent->files_n > 0) oldParent->files_n--; } else {
            if (oldParent->folders_n > 0) oldParent->folders_n--;
        }
        oldParent->setModifiedNow();

        size_t *head = isFile ? &oldParent->data_pos : &oldParent->subdir_pos;
        if (*head == src->current) *head = src->next;

        if (oldParentPos) updateBlock(oldParent);
        else commitRoot();
    }

    // Update siblings
    if (src->previous) {
        if (auto *prev = blockAt(src->previous)) {
            prev->next = src->next;
            updateBlock(prev);
        }
    }
    if (src->next) {
        if (auto *next = blockAt(src->next)) {
            next->previous = src->previous;
            updateBlock(next);
        }
    }

    // Move to new parent
    src->parent = destParentPos;
    src->previous = 0;
    src->next = 0;
    src->setName(destName);
    src->setModifiedNow();

    Block *newParent = destParentPos ? blockAt(destParentPos) : root_.get();
    size_t *listHead = isFile ? &newParent->data_pos : &newParent->subdir_pos;

    if (*listHead == 0) {
        *listHead = src->current;
    } else {
        Block *last = blockAt(*listHead);
        while (last && last->next) last = blockAt(last->next);
        if (last) {
            last->next = src->current;
            src->previous = last->current;
            updateBlock(last);
        }
    }

    if (isFile) newParent->files_n++;
    else newParent->folders_n++;
    newParent->setModifiedNow();

    if (destParentPos) updateBlock(newParent);
    else commitRoot();
    updateBlock(src);

    sync();
    logOperation("MOVE", srcPath + " -> " + destPath);
    return true;
}

bool iNode::copy(const std::string &srcPath, const std::string &destPath) {
    if (exists(srcPath, true)) {
        bool r = copyFile(srcPath, destPath);
        if (r) logOperation("COPY", srcPath + " -> " + destPath);
        return r;
    }
    if (exists(srcPath, false)) {
        bool r = copyDirectoryRecursive(srcPath, destPath);
        if (r) logOperation("COPY_RECURSIVE", srcPath + " -> " + destPath);
        return r;
    }
    return false;
}

bool iNode::copyFile(const std::string &srcPath, const std::string &destPath) {
    auto [data, size] = readFile(srcPath);
    if (!data || size == 0) return false;

    std::string normDest = normalizePath(destPath);
    std::string finalDest = exists(destPath, false)
                                ? normDest + "/" + getFileName(normalizePath(srcPath))
                                : normDest;

    if (exists(finalDest, true)) {
        delete[] data;
        return false;
    }

    size_t result = addFile(finalDest, data, size);
    delete[] data;
    return result != 0;
}

bool iNode::copyDirectoryRecursive(const std::string &srcPath, const std::string &destPath) {
    std::string normSrc = normalizePath(srcPath);
    std::string normDest = normalizePath(destPath);
    std::string srcName = getFileName(normSrc);
    std::string finalDest = exists(destPath, false) ? normDest + "/" + srcName : normDest;

    if (exists(finalDest, false) || exists(finalDest, true)) return false;
    if (addDirectory(finalDest) == 0) return false;

    std::vector<std::tuple<std::string, std::string, bool> > items;
    walk(srcPath, [&](Block *b, const std::string &p, iNode *) {
        std::string normP = normalizePath(p);
        if (normP == normSrc) return;
        if (normP.length() > normSrc.length()) {
            std::string rel = normP.substr(normSrc.length());
            if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
            if (!rel.empty()) items.emplace_back(p, rel, b->isFile);
        }
    });

    std::sort(items.begin(), items.end(), [](const auto &a, const auto &b) {
        if (!std::get<2>(a) && std::get<2>(b)) return true;
        if (std::get<2>(a) && !std::get<2>(b)) return false;
        return std::count(std::get<1>(a).begin(), std::get<1>(a).end(), '/') <
               std::count(std::get<1>(b).begin(), std::get<1>(b).end(), '/');
    });

    for (const auto &[src, rel, isFile]: items) {
        std::string dest = finalDest + "/" + rel;
        if (isFile) {
            if (auto [fdata, fsize] = readFile(src); fdata && fsize > 0) {
                addFile(dest, fdata, fsize);
                delete[] fdata;
            }
        } else {
            addDirectory(dest);
        }
    }
    sync();
    return true;
}

size_t iNode::importFile(const std::string &plainPath, const std::string &externalPath) {
    std::ifstream file(externalPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return 0;

    size_t fileSize = file.tellg();
    if (fileSize == 0) return 0;

    file.seekg(0);
    std::vector<char> buffer(fileSize);
    file.read(buffer.data(), fileSize);

    size_t result = addFile(plainPath, buffer.data(), fileSize);
    if (result > 0) logOperation("IMPORT_FILE", externalPath + " -> " + plainPath);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// DIRECTORY LISTING & SEARCH
// ═══════════════════════════════════════════════════════════════════════════

std::vector<iNode::DirEntry> iNode::listDirectory(const std::string &plainPath) const {
    std::vector<DirEntry> entries;
    std::string norm = normalizePath(plainPath);

    Block *dir = norm.empty() ? root_.get() : findBlock(plainPath, false);
    if (!dir) return entries;

    entries.reserve(dir->folders_n + dir->files_n);

    for (auto *b = blockAt(dir->subdir_pos); b; b = blockAt(b->next)) {
        std::string name = b->getPlainName();
        if (name != ".lockbox_log")
            entries.push_back({b->getRawName(), name, false, 0});
    }

    for (auto *b = blockAt(dir->data_pos); b; b = blockAt(b->next)) {
        std::string name = b->getPlainName();
        if (name != ".lockbox_log")
            entries.push_back({b->getRawName(), name, true, b->size});
    }

    const_cast<iNode *>(this)->logOperation("LIST_DIR", plainPath.empty() ? "/" : plainPath);
    return entries;
}

std::vector<std::string> iNode::search(const std::string &name, bool caseSensitive) {
    std::vector<std::string> results;
    std::string searchName = caseSensitive ? name : toLower(name);

    walk([&](Block *b, const std::string &path, iNode *) {
        std::string blockName = getFileName(normalizePath(path));
        if (blockName == ".lockbox_log") return;
        if (!caseSensitive) blockName = toLower(blockName);
        if (blockName.find(searchName) != std::string::npos)
            results.push_back(path);
    });

    logOperation("SEARCH", name + " (found " + std::to_string(results.size()) + " results)");
    return results;
}

size_t iNode::countSubdirs(const std::string &plainPath) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return root_->folders_n;
    auto *block = findBlock(plainPath, false);
    return block ? block->folders_n : 0;
}

size_t iNode::countFiles(const std::string &plainPath) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return root_->files_n;
    auto *block = findBlock(plainPath, false);
    return block ? block->files_n : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// TRAVERSAL
// ═══════════════════════════════════════════════════════════════════════════

void iNode::walk(const WalkCallback &callback) { walk("/", callback); }

void iNode::walk(const std::string &startPath, const WalkCallback &callback) {
    std::string norm = normalizePath(startPath);
    if (norm.empty()) {
        callback(root_.get(), "/", this);
        walkIterative(root_->subdir_pos, "", callback);
        walkIterative(root_->data_pos, "", callback);
        return;
    }

    auto *start = findBlock(startPath, false);
    if (!start) {
        start = findBlock(startPath, true);
        if (start) callback(start, startPath, this);
        return;
    }

    callback(start, startPath, this);
    walkIterative(start->subdir_pos, startPath, callback);
    walkIterative(start->data_pos, startPath, callback);
}

void iNode::walkIterative(size_t startPos, const std::string &basePath, const WalkCallback &cb) {
    struct Entry {
        size_t pos;
        std::string path;
    };
    std::vector<Entry> stack;
    stack.push_back({startPos, basePath});

    while (!stack.empty()) {
        auto [pos, currentPath] = stack.back();
        stack.pop_back();

        auto *block = blockAt(pos);
        if (!block) continue;

        std::string name = block->getPlainName();
        std::string newPath = currentPath;
        if (newPath.empty() || newPath == "/") {
            newPath = name;
        } else {
            newPath.reserve(newPath.size() + 1 + name.size());
            newPath += '/';
            newPath += name;
        }

        cb(block, newPath, this);

        if (block->next) stack.push_back({block->next, currentPath});
        if (!block->isFile) {
            if (block->data_pos) stack.push_back({block->data_pos, newPath});
            if (block->subdir_pos) stack.push_back({block->subdir_pos, newPath});
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// STATS & DISPLAY
// ═══════════════════════════════════════════════════════════════════════════

iNode::Stats iNode::getStats() const {
    Stats s = {0, 0, 0, 0, 0};
    s.totalSize = storage_.size();

    const_cast<iNode *>(this)->walk([&s](Block *b, const std::string &, iNode *) {
        if (b->isFile) {
            s.fileCount++;
            s.usedSpace += b->size + sizeof(Block);
        } else {
            s.dirCount++;
            s.usedSpace += sizeof(Block);
        }
    });

    s.freeSpace = (s.totalSize > s.usedSpace) ? (s.totalSize - s.usedSpace) : 0;
    return s;
}

void iNode::printStats() const {
    const auto [totalSize, usedSpace, freeSpace, fileCount, dirCount] = getStats();
    std::cout << "\n═══════════════ LockBox Statistics ═══════════════\n"
            << "  Total size:    " << totalSize << " bytes\n"
            << "  Used space:    " << usedSpace << " bytes\n"
            << "  Free space:    " << freeSpace << " bytes (reclaimable via defragment)\n"
            << "  Directories:   " << dirCount << "\n"
            << "  Files:         " << fileCount << "\n"
            << "══════════════════════════════════════════════════\n";
}

void iNode::display() const {
    syncRoot();
    std::cout << "══════════════════════════════════════════════════════════════\n"
            << "iNode Structure:\n"
            << "══════════════════════════════════════════════════════════════\n"
            << "📁 / [" << root_->folders_n << " dirs, " << root_->files_n << " files]\n";

    struct PrintEntry {
        size_t pos;
        int depth;
        bool isLast;
        std::vector<bool> cont;
    };
    std::vector<PrintEntry> stack;

    auto addChildren = [&](Block *b, int depth, const std::vector<bool> &cont) {
        std::vector<size_t> children;
        if (b->data_pos) children.push_back(b->data_pos);
        if (b->subdir_pos) children.push_back(b->subdir_pos);
        for (size_t i = children.size(); i > 0; --i)
            stack.push_back({children[i - 1], depth, i == children.size(), cont});
    };

    addChildren(root_.get(), 1, {});

    while (!stack.empty()) {
        auto e = stack.back();
        stack.pop_back();

        auto *block = blockAt(e.pos);
        if (!block) continue;

        for (int i = 0; i < e.depth - 1; i++)
            std::cout << (i < static_cast<int>(e.cont.size()) && e.cont[i] ? "│   " : "    ");
        std::cout << (e.isLast ? "└── " : "├── ");

        std::string name = block->getPlainName();
        if (block->isFile)
            std::cout << "📄 " << name << " (" << block->size << " bytes)\n";
        else {
            std::cout << "📁 " << name << " [" << block->folders_n
                    << " dirs, " << block->files_n << " files]\n";
            auto newCont = e.cont;
            newCont.push_back(!e.isLast);
            addChildren(block, e.depth + 1, newCont);
        }
        if (block->next) stack.push_back({block->next, e.depth, false, e.cont});
    }
    std::cout << "══════════════════════════════════════════════════════════════\n";
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT & PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════

void iNode::save() {
    commitRoot();
    logOperation("SAVE", "LockBox saved");
}

void iNode::exportTo(const std::string &exportPath) { exportTo(exportPath, ""); }

void iNode::exportTo(const std::string &exportPath, const std::string &internalPath) {
    if (!Filesystem::createDirectory(exportPath, true))
        throw std::runtime_error("Failed to create export directory");

    if (internalPath.empty()) {
        exportIterative(root_->subdir_pos, exportPath);
        exportIterative(root_->data_pos, exportPath);
        logOperation("EXPORT_ALL", "-> " + exportPath);
        return;
    }

    if (auto *fileBlock = findBlock(internalPath, true)) {
        exportSingleFile(fileBlock, exportPath);
        logOperation("EXPORT_FILE", internalPath + " -> " + exportPath);
        return;
    }

    const auto *dirBlock = findBlock(internalPath, false);
    if (!dirBlock) throw std::runtime_error("Path not found: " + internalPath);

    std::string targetPath = exportPath + "/" + dirBlock->getPlainName();
    Filesystem::createDirectory(targetPath, true);
    exportIterative(dirBlock->subdir_pos, targetPath);
    exportIterative(dirBlock->data_pos, targetPath);
    logOperation("EXPORT_DIR", internalPath + " -> " + exportPath);
}

void iNode::exportIterative(size_t startPos, const std::string &basePath) const {
    struct Entry {
        size_t pos;
        std::string destPath;
    };
    std::vector<Entry> stack;
    stack.push_back({startPos, basePath});

    while (!stack.empty()) {
        auto [pos, destPath] = stack.back();
        stack.pop_back();

        auto *block = blockAt(pos);
        if (!block) continue;

        std::string name = block->getPlainName();
        if (name == ".lockbox_log") {
            if (block->next) stack.push_back({block->next, destPath});
            continue;
        }

        std::string fullPath = destPath + "/" + name;
        if (block->isFile) {
            auto [data, size] = readFileData(block);
            if (data && size > 0) Filesystem::writeFile(fullPath, data.get(), size);
        } else {
            Filesystem::createDirectory(fullPath, true);
            if (block->data_pos) stack.push_back({block->data_pos, fullPath});
            if (block->subdir_pos) stack.push_back({block->subdir_pos, fullPath});
        }
        if (block->next) stack.push_back({block->next, destPath});
    }
}

void iNode::exportSingleFile(Block *block, const std::string &destPath) const {
    if (!block || !block->isFile) return;
    auto [data, size] = readFileData(block);
    if (data && size > 0)
        Filesystem::writeFile(destPath + "/" + block->getPlainName(), data.get(), size);
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILD FROM FILESYSTEM
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<iNode> iNode::buildFromFilesystem(const std::string &fsPath,
                                                  const std::string &inodePath,
                                                  OES *cipherEngine) {
    auto node = std::make_unique<iNode>(inodePath, cipherEngine);

    if (Filesystem::isDirectory(fsPath)) {
        node->scanFilesystem(fsPath, "");
    } else if (Filesystem::isFile(fsPath)) {
        auto [size, buffer] = Filesystem::readFile(fsPath);
        if (size > 0) {
            node->addFile(Filesystem::getFilename(fsPath), buffer.data(), size);
        }
    } else {
        throw std::runtime_error("Cannot access: " + fsPath);
    }
    return node;
}

void iNode::scanFilesystem(const std::string &fsPath, const std::string &internalPath) {
    for (const auto &entry: Filesystem::listDirectory(fsPath)) {
        std::string fullPath = fsPath + "/" + entry.name;
        std::string newInternal = internalPath.empty()
                                      ? entry.name
                                      : internalPath + "/" + entry.name;

        if (entry.isDirectory) {
            addDirectory(newInternal);
            scanFilesystem(fullPath, newInternal);
        } else {
            try {
                auto [size, buffer] = Filesystem::readFile(fullPath);
                if (size > 0) addFile(newInternal, buffer.data(), size);
            } catch (...) {
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAINTENANCE
// ═══════════════════════════════════════════════════════════════════════════

bool iNode::defragment() const {
    bool result = storage_.defragment();
    storage_.sync();
    syncRoot();
    return result;
}

const std::string &iNode::getFilePath() const { return path_; }
OES *iNode::getCipherEngine() const { return cipher_; }

// ═══════════════════════════════════════════════════════════════════════════
// PATH UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

std::string iNode::normalizePath(const std::string &path) {
    if (path.empty() || path == "/") return "";
    size_t start = (path.front() == '/') ? 1 : 0;
    size_t end = path.length();
    if (end > start && path.back() == '/') end--;
    return path.substr(start, end - start);
}

std::string iNode::getParentPath(const std::string &path) {
    const size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? "" : path.substr(0, pos);
}

std::string iNode::getFileName(const std::string &path) {
    const size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string iNode::toLower(const std::string &str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](const unsigned char c) { return std::tolower(c); });
    return result;
}
