#include <iostream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <functional>

#include "interface.h"
#include "iNode.h"
#include "filesystem.h"
#include "OES.h"

// ═══════════════════════════════════════════════════════════════════════════
// LIFECYCLE
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
        root_->current = insertBlock(root_.get());
    }
}

iNode::~iNode() { storage_.close(); }

// ═══════════════════════════════════════════════════════════════════════════
// DATA ENCRYPTION/DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

std::pair<char *, size_t> iNode::encryptData(const char *data, size_t size) const {
    if (!data || size == 0) return {nullptr, 0};
    if (!cipher_) {
        auto copy = static_cast<char *>(malloc(size));
        if (copy) memcpy(copy, data, size);
        return {copy, size};
    }
    try {
        cipher_->resetBlocks();
        cipher_->load_data_raw(const_cast<char *>(data), size);
        auto *pb = cipher_->get_plainBlock();
        if (!pb || pb->isNull()) goto fallback;
        cipher_->enc_adv();
        auto *cb = cipher_->get_cipherBlock();
        if (!cb || cb->isNull()) goto fallback;
        auto [exp, len] = exportBlock(cb, OES_TYPE_RAW_UINT8);
        if (!exp || len == 0) goto fallback;
        return {static_cast<char *>(exp), len};
    } catch (...) {}
fallback:
    auto copy = static_cast<char *>(malloc(size));
    if (copy) memcpy(copy, data, size);
    return {copy, size};
}

std::pair<char *, size_t> iNode::decryptData(const char *data, size_t size) const {
    if (!data || size == 0 || !cipher_) {
        auto copy = static_cast<char *>(malloc(size));
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
    } catch (...) {}
fallback:
    auto copy = static_cast<char *>(malloc(size));
    if (copy) memcpy(copy, data, size);
    return {copy, size};
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL BLOCK OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

void iNode::syncRoot() const { storage_.readBlock(0, root_.get()); }

std::unique_ptr<Block> iNode::readBlockAt(size_t pos) const {
    if (pos == 0) return nullptr;
    auto block = std::make_unique<Block>();
    if (!storage_.readBlock(pos, block.get())) return nullptr;
    return block;
}

std::unique_ptr<Block> iNode::cloneRoot() const {
    auto block = std::make_unique<Block>();
    storage_.readBlock(0, block.get());
    return block;
}

size_t iNode::insertBlock(Block *block) {
    size_t pos = storage_.allocate(sizeof(Block));
    block->current = pos;
    storage_.writeBlock(pos, block);
    return pos;
}

bool iNode::updateBlock(Block *block) {
    return storage_.writeBlock(block->current, block);
}

bool iNode::deleteBlock(Block *block) {
    storage_.free(block->current, sizeof(Block));
    return true;
}

bool iNode::unlinkBlock(Block *block) {
    if (block->previous != 0)
        storage_.modifyBlock(block->previous, [&](Block *p) { p->next = block->next; });
    if (block->next != 0)
        storage_.modifyBlock(block->next, [&](Block *n) { n->previous = block->previous; });

    if (block->parent != 0) {
        storage_.modifyBlock(block->parent, [&](Block *p) {
            if (block->isFile && p->data_pos == block->current) p->data_pos = block->next;
            else if (!block->isFile && p->subdir_pos == block->current) p->subdir_pos = block->next;
        });
    } else {
        syncRoot();
        if (block->isFile && root_->data_pos == block->current) root_->data_pos = block->next;
        else if (!block->isFile && root_->subdir_pos == block->current) root_->subdir_pos = block->next;
        updateBlock(root_.get());
    }
    return deleteBlock(block);
}

std::unique_ptr<Block> iNode::findBlockByPath(const std::string &plainPath, bool isFile) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return cloneRoot();

    std::string dirPath = getParentPath(norm);
    std::string targetName = getFileName(norm);

    std::unique_ptr<Block> currentDir;
    if (dirPath.empty()) {
        currentDir = cloneRoot();
    } else {
        currentDir = cloneRoot();
        std::istringstream ss(dirPath);
        std::string token;
        while (std::getline(ss, token, '/')) {
            if (token.empty()) continue;
            if (currentDir->subdir_pos == 0) return nullptr;
            auto sub = readBlockAt(currentDir->subdir_pos);
            bool found = false;
            while (sub) {
                if (sub->nameEquals(token)) {
                    currentDir = std::move(sub);
                    found = true;
                    break;
                }
                if (sub->next == 0) break;
                sub = readBlockAt(sub->next);
            }
            if (!found) return nullptr;
        }
    }

    size_t searchPos = isFile ? currentDir->data_pos : currentDir->subdir_pos;
    if (searchPos == 0) return nullptr;

    auto result = readBlockAt(searchPos);
    while (result) {
        if (result->nameEquals(targetName)) return result;
        if (result->next == 0) break;
        result = readBlockAt(result->next);
    }
    return nullptr;
}

std::unique_ptr<Block> iNode::findParentByPath(const std::string &plainPath) const {
    std::string dirPath = getParentPath(normalizePath(plainPath));
    return dirPath.empty() ? cloneRoot() : findBlockByPath(dirPath, false);
}

size_t iNode::ensureDirChain(const std::string &plainPath) {
    std::istringstream ss(normalizePath(plainPath));
    std::string token;
    auto parent = cloneRoot();
    uint32_t level = 1;

    while (std::getline(ss, token, '/')) {
        if (token.empty()) continue;

        if (parent->subdir_pos != 0) {
            auto cur = readBlockAt(parent->subdir_pos);
            bool found = false;
            while (cur) {
                if (cur->nameEquals(token)) {
                    parent = std::move(cur);
                    found = true;
                    break;
                }
                if (cur->next == 0) break;
                cur = readBlockAt(cur->next);
            }
            if (found) { level++; continue; }
        }

        auto newDir = std::make_unique<Block>();
        newDir->reset();
        newDir->setName(token);
        newDir->isFile = false;
        newDir->level = level;
        newDir->parent = parent->current;
        newDir->current = insertBlock(newDir.get());

        if (parent->subdir_pos == 0) {
            parent->subdir_pos = newDir->current;
        } else {
            auto last = readBlockAt(parent->subdir_pos);
            while (last && last->next != 0) last = readBlockAt(last->next);
            if (last) {
                last->next = newDir->current;
                newDir->previous = last->current;
                updateBlock(last.get());
            }
        }
        parent->folders_n++;
        updateBlock(parent.get());
        updateBlock(newDir.get());
        parent = std::move(newDir);
        level++;
    }
    return parent->current;
}

size_t iNode::createFileBlock(const std::string &plainName, const char *encData,
                              size_t encSize, size_t parentPos) {
    auto parent = std::make_unique<Block>();
    if (!storage_.readBlock(parentPos, parent.get())) return 0;
    if (parent->isFile) return 0;

    const auto fb = std::make_unique<Block>();
    fb->reset();
    fb->setName(plainName);
    fb->isFile = true;
    fb->level = parent->level + 1;
    fb->parent = parentPos;
    fb->size = encSize;

    if (encData && encSize > 0) {
        fb->data_pos = storage_.allocate(encSize);
        if (!storage_.write(fb->data_pos, encData, encSize)) return 0;
    }
    fb->current = insertBlock(fb.get());

    if (parent->data_pos == 0) {
        parent->data_pos = fb->current;
    } else {
        auto last = readBlockAt(parent->data_pos);
        while (last && last->next != 0) last = readBlockAt(last->next);
        if (last) {
            last->next = fb->current;
            fb->previous = last->current;
            updateBlock(last.get());
            updateBlock(fb.get());
        }
    }
    parent->files_n++;
    updateBlock(parent.get());

    if (parentPos == 0) {
        root_->files_n = parent->files_n;
        root_->data_pos = parent->data_pos;
    }
    return fb->current;
}

std::pair<std::unique_ptr<char[]>, size_t> iNode::readFileData(Block *block) const {
    if (!block || block->size == 0) return {nullptr, 0};
    auto data = std::make_unique<char[]>(block->size);
    if (!storage_.read(block->data_pos, data.get(), block->size)) return {nullptr, 0};

    if (cipher_) {
        auto [dec, decSize] = decryptData(data.get(), block->size);
        if (dec && decSize > 0) {
            auto result = std::make_unique<char[]>(decSize);
            memcpy(result.get(), dec, decSize);
            free(dec);
            return {std::move(result), decSize};
        }
    }
    return {std::move(data), block->size};
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

size_t iNode::addFile(const std::string &plainPath, const char *data, size_t size) {
    if (!data || size == 0) {
        std::cerr << "Cannot add empty file: " << plainPath << std::endl;
        return 0;
    }
    if (exists(plainPath, true)) {
        std::cerr << "File already exists: " << plainPath << std::endl;
        return 0;
    }

    std::string norm = normalizePath(plainPath);
    std::string dirPath = getParentPath(norm);
    std::string fileName = getFileName(norm);

    syncRoot();

    size_t parentPos = 0;
    if (!dirPath.empty()) {
        parentPos = ensureDirChain(dirPath);
        if (parentPos == 0) {
            std::cerr << "Failed to create directory chain: " << plainPath << std::endl;
            return 0;
        }
    }

    auto [encData, encSize] = encryptData(data, size);
    size_t pos = createFileBlock(fileName, encData, encSize, parentPos);
    if (encData) free(encData);

    syncRoot();
    return pos;
}

size_t iNode::addDirectory(const std::string &plainPath) {
    if (exists(plainPath, false)) return 0;
    size_t result = ensureDirChain(normalizePath(plainPath));
    syncRoot();
    return result;
}

bool iNode::removeFile(const std::string &plainPath) {
    auto block = findBlockByPath(plainPath, true);
    if (!block) return false;

    if (block->data_pos != 0 && block->size > 0)
        storage_.free(block->data_pos, block->size);

    auto parent = findParentByPath(plainPath);
    bool result = unlinkBlock(block.get());

    if (result && parent) {
        if (parent->files_n > 0) parent->files_n--;
        updateBlock(parent.get());
    }
    syncRoot();
    return result;
}

bool iNode::removeDirectory(const std::string &plainPath, bool force) {
    auto block = findBlockByPath(plainPath, false);
    if (!block) return false;

    if (!force && (block->subdir_pos != 0 || block->data_pos != 0)) {
        std::cerr << "Cannot remove non-empty directory: " << plainPath << std::endl;
        return false;
    }

    auto parent = findParentByPath(plainPath);
    bool result = unlinkBlock(block.get());

    if (result && parent) {
        if (parent->folders_n > 0) parent->folders_n--;
        updateBlock(parent.get());
    }
    syncRoot();
    return result;
}

bool iNode::removeDirectoryRecursive(const std::string &plainPath) {
    auto block = findBlockByPath(plainPath, false);
    if (!block) return false;

    std::vector<std::pair<std::string, bool>> toDelete;
    std::string normPlain = normalizePath(plainPath);

    walk(plainPath, [&](Block *b, const std::string &p, iNode *) {
        if (normalizePath(p) != normPlain)
            toDelete.emplace_back(p, b->isFile);
    });

    std::sort(toDelete.begin(), toDelete.end(), [](const auto &a, const auto &b) {
        return std::count(a.first.begin(), a.first.end(), '/') >
               std::count(b.first.begin(), b.first.end(), '/');
    });

    for (const auto &[path, isFile] : toDelete) {
        if (isFile) removeFile(path);
        else removeDirectory(path, true);
    }

    block = findBlockByPath(plainPath, false);
    if (!block) { syncRoot(); return true; }

    block->folders_n = 0;
    block->files_n = 0;
    block->subdir_pos = 0;
    block->data_pos = 0;
    updateBlock(block.get());

    auto parent = findParentByPath(plainPath);
    bool result = unlinkBlock(block.get());

    if (result && parent) {
        if (parent->folders_n > 0) parent->folders_n--;
        updateBlock(parent.get());
    }
    syncRoot();
    return result;
}

bool iNode::remove(const std::string &plainPath) {
    if (exists(plainPath, true)) return removeFile(plainPath);
    if (exists(plainPath, false)) return removeDirectoryRecursive(plainPath);
    return false;
}

std::pair<char *, size_t> iNode::readFile(const std::string &plainPath) {
    auto block = findBlockByPath(plainPath, true);
    if (!block) return {nullptr, 0};
    auto [data, size] = readFileData(block.get());
    if (!data) return {nullptr, 0};
    return {data.release(), size};
}

bool iNode::updateFile(const std::string &plainPath, const char *data, size_t size) {
    auto block = findBlockByPath(plainPath, true);
    if (!block) return false;

    if (block->data_pos != 0 && block->size > 0)
        storage_.free(block->data_pos, block->size);

    auto [encData, encSize] = encryptData(data, size);
    block->data_pos = storage_.allocate(encSize);
    block->size = encSize;

    bool result = storage_.write(block->data_pos, encData, encSize) && updateBlock(block.get());
    if (encData) free(encData);
    return result;
}

bool iNode::exists(const std::string &plainPath, bool isFile) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return !isFile;
    auto block = findBlockByPath(plainPath, isFile);
    return block != nullptr;
}

bool iNode::rename(const std::string &plainPath, const std::string &newPlainName) {
    if (newPlainName.find('/') != std::string::npos || newPlainName.empty()) {
        std::cerr << "Invalid name: " << newPlainName << std::endl;
        return false;
    }

    auto block = findBlockByPath(plainPath, true);
    if (!block) block = findBlockByPath(plainPath, false);
    if (!block) return false;

    std::string parentPath = getParentPath(normalizePath(plainPath));
    std::string newFullPath = parentPath.empty() ? newPlainName : parentPath + "/" + newPlainName;
    if (exists(newFullPath, true) || exists(newFullPath, false)) {
        std::cerr << "Name already exists: " << newPlainName << std::endl;
        return false;
    }

    block->setName(newPlainName);
    bool result = updateBlock(block.get());
    syncRoot();
    return result;
}

bool iNode::move(const std::string &srcPlainPath, const std::string &destPlainPath) {
    bool isFile = exists(srcPlainPath, true);
    auto srcBlock = findBlockByPath(srcPlainPath, isFile);
    if (!srcBlock) {
        srcBlock = findBlockByPath(srcPlainPath, false);
        isFile = false;
    }
    if (!srcBlock) {
        std::cerr << "Source not found: " << srcPlainPath << std::endl;
        return false;
    }

    std::string normDest = normalizePath(destPlainPath);
    std::string destDir, destName;

    if (exists(destPlainPath, false)) {
        destDir = normDest;
        destName = srcBlock->getPlainName();
    } else {
        destDir = getParentPath(normDest);
        destName = getFileName(normDest);
    }

    size_t destParentPos = 0;
    if (!destDir.empty()) {
        destParentPos = ensureDirChain(destDir);
        if (destParentPos == 0) {
            std::cerr << "Failed to create destination directory" << std::endl;
            return false;
        }
    }

    std::string fullDestPath = destDir.empty() ? destName : destDir + "/" + destName;
    if (exists(fullDestPath, true) || exists(fullDestPath, false)) {
        std::cerr << "Destination already exists: " << fullDestPath << std::endl;
        return false;
    }

    auto oldParent = findParentByPath(srcPlainPath);
    if (oldParent) {
        if (isFile) { if (oldParent->files_n > 0) oldParent->files_n--; }
        else { if (oldParent->folders_n > 0) oldParent->folders_n--; }
        updateBlock(oldParent.get());
    }

    if (srcBlock->previous != 0)
        storage_.modifyBlock(srcBlock->previous, [&](Block *p) { p->next = srcBlock->next; });
    if (srcBlock->next != 0)
        storage_.modifyBlock(srcBlock->next, [&](Block *n) { n->previous = srcBlock->previous; });
    if (srcBlock->parent != 0) {
        storage_.modifyBlock(srcBlock->parent, [&](Block *p) {
            if (isFile && p->data_pos == srcBlock->current) p->data_pos = srcBlock->next;
            else if (!isFile && p->subdir_pos == srcBlock->current) p->subdir_pos = srcBlock->next;
        });
    } else {
        syncRoot();
        if (isFile && root_->data_pos == srcBlock->current) root_->data_pos = srcBlock->next;
        else if (!isFile && root_->subdir_pos == srcBlock->current) root_->subdir_pos = srcBlock->next;
        updateBlock(root_.get());
    }

    srcBlock->parent = destParentPos;
    srcBlock->previous = 0;
    srcBlock->next = 0;
    srcBlock->setName(destName);

    auto newParent = std::make_unique<Block>();
    if (!storage_.readBlock(destParentPos, newParent.get())) return false;

    size_t *listHead = isFile ? &newParent->data_pos : &newParent->subdir_pos;
    if (*listHead == 0) {
        *listHead = srcBlock->current;
    } else {
        auto last = readBlockAt(*listHead);
        while (last && last->next != 0) last = readBlockAt(last->next);
        if (last) {
            last->next = srcBlock->current;
            srcBlock->previous = last->current;
            updateBlock(last.get());
        }
    }

    if (isFile) newParent->files_n++;
    else newParent->folders_n++;

    updateBlock(newParent.get());
    updateBlock(srcBlock.get());
    syncRoot();
    return true;
}

bool iNode::copy(const std::string &srcPlainPath, const std::string &destPlainPath) {
    if (exists(srcPlainPath, true)) return copyFile(srcPlainPath, destPlainPath);
    if (exists(srcPlainPath, false)) return copyDirectoryRecursive(srcPlainPath, destPlainPath);
    std::cerr << "Source not found: " << srcPlainPath << std::endl;
    return false;
}

bool iNode::copyFile(const std::string &srcPlainPath, const std::string &destPlainPath) {
    auto [data, size] = readFile(srcPlainPath);
    if (!data || size == 0) {
        std::cerr << "Failed to read source file: " << srcPlainPath << std::endl;
        return false;
    }

    std::string normDest = normalizePath(destPlainPath);
    std::string finalDest = exists(destPlainPath, false)
        ? normDest + "/" + getFileName(normalizePath(srcPlainPath))
        : normDest;

    if (exists(finalDest, true)) {
        std::cerr << "Destination file already exists: " << finalDest << std::endl;
        delete[] data;
        return false;
    }

    size_t result = addFile(finalDest, data, size);
    delete[] data;
    return result != 0;
}

bool iNode::copyDirectoryRecursive(const std::string &srcPlainPath, const std::string &destPlainPath) {
    std::string normSrc = normalizePath(srcPlainPath);
    std::string normDest = normalizePath(destPlainPath);
    std::string srcName = getFileName(normSrc);
    std::string finalDest = exists(destPlainPath, false) ? normDest + "/" + srcName : normDest;

    if (exists(finalDest, false) || exists(finalDest, true)) {
        std::cerr << "Destination already exists: " << finalDest << std::endl;
        return false;
    }

    if (addDirectory(finalDest) == 0) {
        std::cerr << "Failed to create destination directory: " << finalDest << std::endl;
        return false;
    }

    std::vector<std::tuple<std::string, std::string, bool>> items;
    walk(srcPlainPath, [&](Block *b, const std::string &plainPath, iNode *) {
        std::string normPath = normalizePath(plainPath);
        if (normPath == normSrc) return;
        std::string relPath = normPath.substr(normSrc.length());
        if (!relPath.empty() && relPath[0] == '/') relPath = relPath.substr(1);
        if (!relPath.empty()) items.emplace_back(plainPath, relPath, b->isFile);
    });

    std::sort(items.begin(), items.end(), [](const auto &a, const auto &b) {
        if (!std::get<2>(a) && std::get<2>(b)) return true;
        if (std::get<2>(a) && !std::get<2>(b)) return false;
        return std::count(std::get<1>(a).begin(), std::get<1>(a).end(), '/') <
               std::count(std::get<1>(b).begin(), std::get<1>(b).end(), '/');
    });

    for (const auto &[srcPath, relPath, isFile] : items) {
        std::string destPath = finalDest + "/" + relPath;
        if (isFile) {
            auto [fdata, fsize] = readFile(srcPath);
            if (fdata && fsize > 0) {
                addFile(destPath, fdata, fsize);
                delete[] fdata;
            }
        } else {
            addDirectory(destPath);
        }
    }
    syncRoot();
    return true;
}

size_t iNode::importFile(const std::string &plainPath, const std::string &externalPath) {
    std::ifstream file(externalPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Cannot open external file: " << externalPath << std::endl;
        return 0;
    }
    size_t fileSize = file.tellg();
    if (fileSize == 0) {
        std::cerr << "Cannot import empty file" << std::endl;
        return 0;
    }
    file.seekg(0);
    std::vector<char> buffer(fileSize);
    file.read(buffer.data(), fileSize);
    file.close();
    return addFile(plainPath, buffer.data(), fileSize);
}

// ═══════════════════════════════════════════════════════════════════════════
// DIRECTORY LISTING
// ═══════════════════════════════════════════════════════════════════════════

std::vector<iNode::DirEntry> iNode::listDirectory(const std::string &plainPath) const {
    std::vector<DirEntry> entries;
    std::string norm = normalizePath(plainPath);

    std::unique_ptr<Block> dirBlock = norm.empty()
        ? cloneRoot()
        : findBlockByPath(plainPath, false);

    if (!dirBlock) return entries;

    if (dirBlock->subdir_pos != 0) {
        auto cur = readBlockAt(dirBlock->subdir_pos);
        while (cur) {
            DirEntry e;
            e.encryptedName = cur->getRawName();
            e.name = cur->getPlainName();
            e.isFile = false;
            e.size = 0;
            entries.push_back(e);
            if (cur->next == 0) break;
            cur = readBlockAt(cur->next);
        }
    }

    if (dirBlock->data_pos != 0) {
        auto cur = readBlockAt(dirBlock->data_pos);
        while (cur) {
            DirEntry e;
            e.encryptedName = cur->getRawName();
            e.name = cur->getPlainName();
            e.isFile = true;
            e.size = cur->size;
            entries.push_back(e);
            if (cur->next == 0) break;
            cur = readBlockAt(cur->next);
        }
    }
    return entries;
}

// ═══════════════════════════════════════════════════════════════════════════
// SEARCH & TRAVERSAL
// ═══════════════════════════════════════════════════════════════════════════

std::vector<std::string> iNode::search(const std::string &name, bool caseSensitive) {
    std::vector<std::string> results;
    std::string searchName = caseSensitive ? name : toLower(name);

    walk([&](Block *b, const std::string &plainPath, iNode *) {
        std::string blockName = getFileName(normalizePath(plainPath));
        if (!caseSensitive) blockName = toLower(blockName);
        if (blockName.find(searchName) != std::string::npos)
            results.push_back(plainPath);
    });
    return results;
}

void iNode::walk(WalkCallback callback) { walk("/", callback); }

void iNode::walk(const std::string &startPlainPath, WalkCallback callback) {
    std::string norm = normalizePath(startPlainPath);

    if (norm.empty()) {
        auto root = cloneRoot();
        callback(root.get(), "/", this);
        if (root->subdir_pos != 0) walkRecursiveInternal(root->subdir_pos, 1, "", callback);
        if (root->data_pos != 0) walkRecursiveInternal(root->data_pos, 1, "", callback);
        return;
    }

    auto startBlock = findBlockByPath(startPlainPath, false);
    if (!startBlock) {
        startBlock = findBlockByPath(startPlainPath, true);
        if (startBlock) callback(startBlock.get(), startPlainPath, this);
        return;
    }

    callback(startBlock.get(), startPlainPath, this);
    if (startBlock->subdir_pos != 0)
        walkRecursiveInternal(startBlock->subdir_pos, startBlock->level + 1, startPlainPath, callback);
    if (startBlock->data_pos != 0)
        walkRecursiveInternal(startBlock->data_pos, startBlock->level + 1, startPlainPath, callback);
}

void iNode::walkRecursiveInternal(size_t pos, uint32_t level, const std::string &currentPlainPath,
                                  WalkCallback callback) {
    if (pos == 0) return;
    auto block = readBlockAt(pos);
    if (!block) return;

    std::string plainName = block->getPlainName();
    std::string newPath = (currentPlainPath.empty() || currentPlainPath == "/")
                              ? plainName
                              : currentPlainPath + "/" + plainName;

    callback(block.get(), newPath, this);

    if (!block->isFile) {
        if (block->subdir_pos != 0) walkRecursiveInternal(block->subdir_pos, level + 1, newPath, callback);
        if (block->data_pos != 0) walkRecursiveInternal(block->data_pos, level + 1, newPath, callback);
    }
    if (block->next != 0) walkRecursiveInternal(block->next, level, currentPlainPath, callback);
}

size_t iNode::countSubdirs(const std::string &plainPath) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return cloneRoot()->folders_n;
    auto block = findBlockByPath(plainPath, false);
    return block ? block->folders_n : 0;
}

size_t iNode::countFiles(const std::string &plainPath) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return cloneRoot()->files_n;
    auto block = findBlockByPath(plainPath, false);
    return block ? block->files_n : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// DISPLAY & STATS
// ═══════════════════════════════════════════════════════════════════════════

void iNode::display() const {
    auto root = cloneRoot();
    std::cout << "══════════════════════════════════════════════════════════════\n"
              << "iNode Structure:\n"
              << "══════════════════════════════════════════════════════════════\n"
              << "📁 / [" << root->folders_n << " dirs, " << root->files_n << " files]\n";

    std::vector<bool> cont;
    std::function<void(size_t, int, bool)> printTree = [&](size_t pos, int depth, bool isLast) {
        auto block = readBlockAt(pos);
        if (!block) return;

        for (int i = 0; i < depth - 1; i++)
            std::cout << (i < (int)cont.size() && cont[i] ? "│   " : "    ");
        if (depth > 0) std::cout << (isLast ? "└── " : "├── ");

        std::string displayName = block->getPlainName();

        if (block->isFile) {
            std::cout << "📄 " << displayName << " (" << block->size << " bytes)\n";
        } else {
            std::cout << "📁 " << displayName << " [" << block->folders_n
                      << " dirs, " << block->files_n << " files]\n";

            bool hasData = block->data_pos != 0;
            if (block->subdir_pos != 0) {
                cont.push_back(hasData);
                printTree(block->subdir_pos, depth + 1, !hasData && block->next == 0);
                cont.pop_back();
            }
            if (hasData) {
                cont.push_back(false);
                printTree(block->data_pos, depth + 1, true);
                cont.pop_back();
            }
        }
        if (block->next != 0) printTree(block->next, depth, false);
    };

    if (root->subdir_pos != 0) {
        cont.push_back(root->data_pos != 0);
        printTree(root->subdir_pos, 1, root->data_pos == 0);
        cont.pop_back();
    }
    if (root->data_pos != 0) {
        cont.push_back(false);
        printTree(root->data_pos, 1, true);
        cont.pop_back();
    }
    std::cout << "══════════════════════════════════════════════════════════════\n";
}

iNode::Stats iNode::getStats() const {
    Stats s = {0, 0, 0, 0, 0};
    s.totalSize = storage_.getFileSize();
    s.freeSpace = storage_.getFreeSpace();

    const_cast<iNode *>(this)->walk([&s](Block *b, const std::string &, iNode *) {
        if (b->isFile) {
            s.fileCount++;
            s.usedSpace += b->size + sizeof(Block);
        } else {
            s.dirCount++;
            s.usedSpace += sizeof(Block);
        }
    });
    return s;
}

void iNode::printStats() const {
    Stats s = getStats();
    std::cout << "\n═══════════════ LockBox Statistics ═══════════════\n"
              << "  Total size:    " << s.totalSize << " bytes\n"
              << "  Used space:    " << s.usedSpace << " bytes\n"
              << "  Free space:    " << s.freeSpace << " bytes\n"
              << "  Directories:   " << s.dirCount << "\n"
              << "  Files:         " << s.fileCount << "\n"
              << "  Fragments:     " << storage_.getFragmentCount() << "\n"
              << "══════════════════════════════════════════════════\n";
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT & PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════

void iNode::save() {
    syncRoot();
    updateBlock(root_.get());
}

void iNode::exportTo(const std::string &exportPath) { exportTo(exportPath, ""); }

void iNode::exportTo(const std::string &exportPath, const std::string &internalPlainPath) {
    if (!Filesystem::createDirectory(exportPath, true))
        throw std::runtime_error("Failed to create export directory");

    if (internalPlainPath.empty()) {
        auto root = cloneRoot();
        if (root->subdir_pos != 0) exportRecursive(root->subdir_pos, exportPath);
        if (root->data_pos != 0) exportRecursive(root->data_pos, exportPath);
        return;
    }

    auto fileBlock = findBlockByPath(internalPlainPath, true);
    if (fileBlock) {
        exportSingleFile(fileBlock.get(), exportPath);
        return;
    }

    auto dirBlock = findBlockByPath(internalPlainPath, false);
    if (!dirBlock) throw std::runtime_error("Path not found: " + internalPlainPath);

    std::string targetPath = exportPath + "/" + dirBlock->getPlainName();
    Filesystem::createDirectory(targetPath, true);

    if (dirBlock->subdir_pos != 0) exportRecursive(dirBlock->subdir_pos, targetPath);
    if (dirBlock->data_pos != 0) exportRecursive(dirBlock->data_pos, targetPath);
}

void iNode::exportRecursive(size_t pos, const std::string &destPath) {
    if (pos == 0) return;
    auto block = readBlockAt(pos);
    if (!block) return;

    std::string plainName = block->getPlainName();
    std::string fullPath = destPath + "/" + plainName;

    if (block->isFile) {
        auto [data, size] = readFileData(block.get());
        if (data && size > 0) Filesystem::writeFile(fullPath, data.get(), size);
    } else {
        Filesystem::createDirectory(fullPath, true);
        if (block->subdir_pos != 0) exportRecursive(block->subdir_pos, fullPath);
        if (block->data_pos != 0) exportRecursive(block->data_pos, fullPath);
    }

    if (block->next != 0) exportRecursive(block->next, destPath);
}

void iNode::exportSingleFile(Block *block, const std::string &destPath) {
    if (!block || !block->isFile) return;
    std::string fullPath = destPath + "/" + block->getPlainName();
    auto [data, size] = readFileData(block);
    if (data && size > 0) Filesystem::writeFile(fullPath, data.get(), size);
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILDER & IMPORT
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<iNode> iNode::buildFromFilesystem(const std::string &fsPath,
                                                  const std::string &inodePath,
                                                  OES *cipherEngine) {
    auto node = std::make_unique<iNode>(inodePath, cipherEngine);

    if (Filesystem::isDirectory(fsPath)) {
        node->scanFilesystem(fsPath, "");
    } else if (Filesystem::isFile(fsPath)) {
        std::string fileName = Filesystem::getFilename(fsPath);
        try {
            auto [size, buffer] = Filesystem::readFile(fsPath);
            if (size > 0) node->addFile(fileName, buffer.data(), size);
        } catch (const std::exception &e) {
            std::cerr << "Failed to read file: " << fsPath << " - " << e.what() << std::endl;
        }
    } else {
        throw std::runtime_error("Cannot access: " + fsPath);
    }
    return node;
}

void iNode::scanFilesystem(const std::string &fsPath, const std::string &internalPlainPath) {
    auto entries = Filesystem::listDirectory(fsPath);

    for (const auto &entry : entries) {
        std::string fullPath = fsPath + "/" + entry.name;
        std::string newInternal = internalPlainPath.empty()
                                      ? entry.name
                                      : internalPlainPath + "/" + entry.name;

        if (entry.isDirectory) {
            addDirectory(newInternal);
            scanFilesystem(fullPath, newInternal);
        } else {
            try {
                auto [size, buffer] = Filesystem::readFile(fullPath);
                if (size > 0) addFile(newInternal, buffer.data(), size);
            } catch (const std::exception &e) {
                std::cerr << "Failed to read: " << fullPath << " - " << e.what() << std::endl;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAINTENANCE & ACCESSORS
// ═══════════════════════════════════════════════════════════════════════════

bool iNode::defragment() {
    storage_.defragmentFreeList();
    return true;
}

const std::string &iNode::getFilePath() const { return path_; }
OES *iNode::getCipherEngine() const { return cipher_; }

// ═══════════════════════════════════════════════════════════════════════════
// PATH UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

std::string iNode::normalizePath(const std::string &path) const {
    if (path.empty() || path == "/") return "";
    std::string result = path;
    if (result.front() == '/') result.erase(0, 1);
    if (!result.empty() && result.back() == '/') result.pop_back();
    return result;
}

std::string iNode::getParentPath(const std::string &path) const {
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? "" : path.substr(0, pos);
}

std::string iNode::getFileName(const std::string &path) const {
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string iNode::toLower(const std::string &str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// LEGACY/COMPATIBILITY
// ═══════════════════════════════════════════════════════════════════════════

Block *iNode::findBlock(const std::string &path, bool isFile) const {
    auto block = findBlockByPath(path, isFile);
    return block ? block.release() : nullptr;
}

Block *iNode::findParent(const std::string &path) const {
    auto block = findParentByPath(path);
    return block ? block.release() : nullptr;
}