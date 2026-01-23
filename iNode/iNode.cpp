#include <iostream>
#include <algorithm>
#include <fstream>
#include <functional>
#include <chrono>
#include <ctime>

#include "interface.h"
#include "iNode.h"
#include "filesystem.h"
#include "OES.h"

// ═══════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR / DESTRUCTOR
// ═══════════════════════════════════════════════════════════════════════════

iNode::iNode(const std::string& path, OES* engine)
    : root_(std::make_unique<Block>()), cipher_(engine), path_(path) {
    Block::setCipherEngine(engine);
    blockCache_.reserve(64);

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
        root_->current = insertBlock(root_.get());
    }
}

iNode::~iNode() { storage_.close(); }

// ═══════════════════════════════════════════════════════════════════════════
// CACHE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

Block* iNode::getCached(size_t pos) const {
    auto it = blockCache_.find(pos);
    return (it != blockCache_.end()) ? it->second.get() : nullptr;
}

void iNode::putCache(size_t pos, std::unique_ptr<Block> block) const {
    if (blockCache_.size() >= MAX_CACHE_SIZE) {
        blockCache_.erase(blockCache_.begin());
    }
    blockCache_[pos] = std::move(block);
}

void iNode::invalidateCache(size_t pos) const {
    blockCache_.erase(pos);
}

void iNode::clearCache() const {
    blockCache_.clear();
}

void iNode::syncRoot() const {
    storage_.readBlock(0, root_.get());
}

void iNode::flushAll() const {
    clearCache();
    syncRoot();
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

std::pair<char*, size_t> iNode::encryptData(const char* data, size_t size) const {
    if (!data || size == 0) return {nullptr, 0};
    if (!cipher_) {
        auto copy = static_cast<char*>(malloc(size));
        if (copy) memcpy(copy, data, size);
        return {copy, size};
    }
    try {
        cipher_->resetBlocks();
        cipher_->load_data_raw(const_cast<char*>(data), size);
        auto* pb = cipher_->get_plainBlock();
        if (!pb || pb->isNull()) goto fallback;
        cipher_->enc_adv();
        auto* cb = cipher_->get_cipherBlock();
        if (!cb || cb->isNull()) goto fallback;
        auto [exp, len] = exportBlock(cb, OES_TYPE_RAW_UINT8);
        if (!exp || len == 0) goto fallback;
        return {static_cast<char*>(exp), len};
    } catch (...) {}
fallback:
    auto copy = static_cast<char*>(malloc(size));
    if (copy) memcpy(copy, data, size);
    return {copy, size};
}

std::pair<char*, size_t> iNode::decryptData(const char* data, size_t size) const {
    if (!data || size == 0 || !cipher_) {
        auto copy = static_cast<char*>(malloc(size));
        if (copy) memcpy(copy, data, size);
        return {copy, size};
    }
    try {
        cipher_->resetBlocks();
        cipher_->load_cipher_data_raw(const_cast<char*>(data), size);
        cipher_->dec_adv();
        auto* pb = cipher_->get_plainBlock();
        if (!pb || pb->isNull()) goto fallback;
        auto [exp, len] = exportBlock(pb, OES_TYPE_UINT8);
        if (!exp || len == 0) goto fallback;
        return {static_cast<char*>(exp), len};
    } catch (...) {}
fallback:
    auto copy = static_cast<char*>(malloc(size));
    if (copy) memcpy(copy, data, size);
    return {copy, size};
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL BLOCK OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<Block> iNode::readBlockAt(size_t pos) const {
    if (pos == 0) return nullptr;

    // Don't use cache for critical operations - always read fresh
    auto block = std::make_unique<Block>();
    if (!storage_.readBlock(pos, block.get())) return nullptr;
    return block;
}

std::unique_ptr<Block> iNode::cloneRoot() const {
    // Always re-read root from disk
    syncRoot();
    auto block = std::make_unique<Block>();
    *block = *root_;
    return block;
}

size_t iNode::insertBlock(Block* block) {
    size_t pos = storage_.allocate(sizeof(Block));
    block->current = pos;
    storage_.writeBlock(pos, block);
    return pos;
}

bool iNode::updateBlock(Block* block) {
    invalidateCache(block->current);
    bool result = storage_.writeBlock(block->current, block);
    // Force sync if updating root
    if (block->current == 0 || block->current == root_->current) {
        syncRoot();
    }
    return result;
}

bool iNode::deleteBlock(Block* block) {
    invalidateCache(block->current);
    storage_.free(block->current, sizeof(Block));
    return true;
}

bool iNode::unlinkBlock(Block* block) {
    // Update previous sibling
    if (block->previous != 0) {
        auto prevBlock = std::make_unique<Block>();
        if (storage_.readBlock(block->previous, prevBlock.get())) {
            prevBlock->next = block->next;
            storage_.writeBlock(block->previous, prevBlock.get());
            invalidateCache(block->previous);
        }
    }

    // Update next sibling
    if (block->next != 0) {
        auto nextBlock = std::make_unique<Block>();
        if (storage_.readBlock(block->next, nextBlock.get())) {
            nextBlock->previous = block->previous;
            storage_.writeBlock(block->next, nextBlock.get());
            invalidateCache(block->next);
        }
    }

    // Update parent's pointer if this was the first child
    if (block->parent != 0) {
        auto parentBlock = std::make_unique<Block>();
        if (storage_.readBlock(block->parent, parentBlock.get())) {
            bool updated = false;
            if (block->isFile && parentBlock->data_pos == block->current) {
                parentBlock->data_pos = block->next;
                updated = true;
            } else if (!block->isFile && parentBlock->subdir_pos == block->current) {
                parentBlock->subdir_pos = block->next;
                updated = true;
            }
            if (updated) {
                storage_.writeBlock(block->parent, parentBlock.get());
                invalidateCache(block->parent);
            }
        }
    } else {
        // Parent is root
        syncRoot();
        bool updated = false;
        if (block->isFile && root_->data_pos == block->current) {
            root_->data_pos = block->next;
            updated = true;
        } else if (!block->isFile && root_->subdir_pos == block->current) {
            root_->subdir_pos = block->next;
            updated = true;
        }
        if (updated) {
            storage_.writeBlock(root_->current, root_.get());
        }
    }

    return deleteBlock(block);
}

std::unique_ptr<Block> iNode::findBlockByPath(const std::string& plainPath, bool isFile) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return cloneRoot();

    // Always start fresh
    syncRoot();

    std::unique_ptr<Block> currentDir = cloneRoot();
    size_t start = 0, end;

    std::string dirPath, targetName;
    size_t lastSlash = norm.rfind('/');
    if (lastSlash == std::string::npos) {
        targetName = norm;
    } else {
        dirPath = norm.substr(0, lastSlash);
        targetName = norm.substr(lastSlash + 1);
    }

    // Navigate to parent directory
    if (!dirPath.empty()) {
        start = 0;
        while ((end = dirPath.find('/', start)) != std::string::npos || start < dirPath.length()) {
            if (end == std::string::npos) end = dirPath.length();
            if (end > start) {
                std::string token = dirPath.substr(start, end - start);
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
            start = end + 1;
        }
    }

    // Search for target
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

std::unique_ptr<Block> iNode::findParentByPath(const std::string& plainPath) const {
    std::string norm = normalizePath(plainPath);
    size_t lastSlash = norm.rfind('/');
    if (lastSlash == std::string::npos) return cloneRoot();
    return findBlockByPath(norm.substr(0, lastSlash), false);
}

size_t iNode::ensureDirChain(const std::string& plainPath) {
    std::string norm = normalizePath(plainPath);
    syncRoot();
    auto parent = cloneRoot();
    uint32_t level = 1;
    size_t start = 0, end;

    while ((end = norm.find('/', start)) != std::string::npos || start < norm.length()) {
        if (end == std::string::npos) end = norm.length();
        if (end > start) {
            std::string token = norm.substr(start, end - start);

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
                if (found) {
                    level++;
                    start = end + 1;
                    continue;
                }
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
                auto last = readBlockAt(parent->subdir_pos);
                while (last && last->next != 0) last = readBlockAt(last->next);
                if (last) {
                    last->next = newDir->current;
                    newDir->previous = last->current;
                    storage_.writeBlock(last->current, last.get());
                }
            }
            parent->folders_n++;
            parent->setModifiedNow();
            storage_.writeBlock(parent->current, parent.get());
            storage_.writeBlock(newDir->current, newDir.get());

            // Sync root if parent is root
            if (parent->current == root_->current) {
                syncRoot();
            }

            parent = std::move(newDir);
            level++;
        }
        start = end + 1;
    }
    return parent->current;
}

size_t iNode::createFileBlock(const std::string& plainName, const char* encData,
                               size_t encSize, size_t parentPos) {
    auto parent = std::make_unique<Block>();
    if (!storage_.readBlock(parentPos, parent.get())) return 0;
    if (parent->isFile) return 0;

    auto fb = std::make_unique<Block>();
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
            storage_.writeBlock(last->current, last.get());
            storage_.writeBlock(fb->current, fb.get());
        }
    }
    parent->files_n++;
    parent->setModifiedNow();
    storage_.writeBlock(parentPos, parent.get());

    if (parentPos == 0 || parentPos == root_->current) {
        syncRoot();
    }
    return fb->current;
}

std::pair<std::unique_ptr<char[]>, size_t> iNode::readFileData(Block* block) const {
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
// LOGGING SYSTEM
// ═══════════════════════════════════════════════════════════════════════════

void iNode::logOperation(const std::string& operation, const std::string& details) {
    auto now = std::chrono::system_clock::now();
    auto time_t_val = std::chrono::system_clock::to_time_t(now);
    char timeBuf[64];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&time_t_val));

    std::string logEntry = std::string("[") + timeBuf + "] " + operation;
    if (!details.empty()) logEntry += ": " + details;
    logEntry += "\n";

    // Find or create log block
    flushAll();
    auto logBlock = findBlockByPath(LOG_INTERNAL_PATH, true);

    if (logBlock) {
        auto [existingData, existingSize] = readFileData(logBlock.get());
        std::string fullLog;
        if (existingData && existingSize > 0) {
            fullLog = std::string(existingData.get(), existingSize);
        }
        fullLog += logEntry;

        // Free old data
        if (logBlock->data_pos != 0 && logBlock->size > 0)
            storage_.free(logBlock->data_pos, logBlock->size);

        auto [encData, encSize] = encryptData(fullLog.c_str(), fullLog.size());
        logBlock->data_pos = storage_.allocate(encSize);
        logBlock->size = encSize;
        logBlock->setModifiedNow();

        storage_.write(logBlock->data_pos, encData, encSize);
        storage_.writeBlock(logBlock->current, logBlock.get());
        if (encData) free(encData);
    } else {
        // Create new log file
        auto [encData, encSize] = encryptData(logEntry.c_str(), logEntry.size());
        createFileBlock(LOG_INTERNAL_PATH, encData, encSize, 0);
        if (encData) free(encData);
    }
}

std::string iNode::getLog() const {
    const_cast<iNode*>(this)->flushAll();
    auto logBlock = findBlockByPath(LOG_INTERNAL_PATH, true);
    if (!logBlock) return "(Nessun log disponibile)\n";

    auto [data, size] = const_cast<iNode*>(this)->readFileData(logBlock.get());
    if (!data || size == 0) return "(Log vuoto)\n";

    return std::string(data.get(), size);
}

void iNode::clearLog() {
    flushAll();
    auto logBlock = findBlockByPath(LOG_INTERNAL_PATH, true);
    if (!logBlock) return;

    if (logBlock->data_pos != 0 && logBlock->size > 0) {
        storage_.free(logBlock->data_pos, logBlock->size);
    }

    std::string emptyLog = "[Log cleared]\n";
    auto [encData, encSize] = encryptData(emptyLog.c_str(), emptyLog.size());

    logBlock->data_pos = storage_.allocate(encSize);
    logBlock->size = encSize;
    logBlock->setModifiedNow();

    storage_.write(logBlock->data_pos, encData, encSize);
    storage_.writeBlock(logBlock->current, logBlock.get());

    if (encData) free(encData);
}

size_t iNode::getLogSize() const {
    const_cast<iNode*>(this)->flushAll();
    auto logBlock = findBlockByPath(LOG_INTERNAL_PATH, true);
    return logBlock ? logBlock->size : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════

size_t iNode::addFile(const std::string& plainPath, const char* data, size_t size) {
    if (!data || size == 0) {
        std::cerr << "Cannot add empty file: " << plainPath << std::endl;
        return 0;
    }

    flushAll();

    if (exists(plainPath, true)) {
        std::cerr << "File already exists: " << plainPath << std::endl;
        return 0;
    }

    std::string norm = normalizePath(plainPath);
    size_t lastSlash = norm.rfind('/');
    std::string dirPath = (lastSlash == std::string::npos) ? "" : norm.substr(0, lastSlash);
    std::string fileName = (lastSlash == std::string::npos) ? norm : norm.substr(lastSlash + 1);

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

    flushAll();

    if (pos > 0) {
        logOperation("ADD_FILE", plainPath + " (" + std::to_string(size) + " bytes)");
    }

    return pos;
}

size_t iNode::addDirectory(const std::string& plainPath) {
    flushAll();

    if (exists(plainPath, false)) return 0;

    size_t result = ensureDirChain(normalizePath(plainPath));

    flushAll();

    if (result > 0) {
        logOperation("ADD_DIR", plainPath);
    }

    return result;
}

bool iNode::removeFile(const std::string& plainPath) {
    flushAll();

    auto block = findBlockByPath(plainPath, true);
    if (!block) {
        std::cerr << "File not found: " << plainPath << std::endl;
        return false;
    }

    // Free file data
    if (block->data_pos != 0 && block->size > 0) {
        storage_.free(block->data_pos, block->size);
    }

    // Get parent and update count
    size_t parentPos = block->parent;

    // Unlink the block
    bool result = unlinkBlock(block.get());

    // Update parent's file count
    if (result && parentPos != 0) {
        auto parent = std::make_unique<Block>();
        if (storage_.readBlock(parentPos, parent.get())) {
            if (parent->files_n > 0) parent->files_n--;
            parent->setModifiedNow();
            storage_.writeBlock(parentPos, parent.get());
        }
    } else if (result) {
        // Parent is root
        syncRoot();
        if (root_->files_n > 0) root_->files_n--;
        root_->setModifiedNow();
        storage_.writeBlock(root_->current, root_.get());
    }

    flushAll();

    if (result) {
        logOperation("REMOVE_FILE", plainPath);
    }

    return result;
}

bool iNode::removeDirectory(const std::string& plainPath, bool force) {
    flushAll();

    auto block = findBlockByPath(plainPath, false);
    if (!block) {
        std::cerr << "Directory not found: " << plainPath << std::endl;
        return false;
    }

    if (!force && (block->subdir_pos != 0 || block->data_pos != 0)) {
        std::cerr << "Cannot remove non-empty directory: " << plainPath << std::endl;
        return false;
    }

    size_t parentPos = block->parent;

    bool result = unlinkBlock(block.get());

    if (result && parentPos != 0) {
        auto parent = std::make_unique<Block>();
        if (storage_.readBlock(parentPos, parent.get())) {
            if (parent->folders_n > 0) parent->folders_n--;
            parent->setModifiedNow();
            storage_.writeBlock(parentPos, parent.get());
        }
    } else if (result) {
        syncRoot();
        if (root_->folders_n > 0) root_->folders_n--;
        root_->setModifiedNow();
        storage_.writeBlock(root_->current, root_.get());
    }

    flushAll();

    if (result) {
        logOperation("REMOVE_DIR", plainPath);
    }

    return result;
}

bool iNode::removeDirectoryRecursive(const std::string& plainPath) {
    flushAll();

    auto block = findBlockByPath(plainPath, false);
    if (!block) return false;

    std::string normPlain = normalizePath(plainPath);

    // Collect all items to delete
    std::vector<std::pair<std::string, bool>> toDelete;
    toDelete.reserve(64);

    walk(plainPath, [&](Block* b, const std::string& p, iNode*) {
        std::string normP = normalizePath(p);
        if (normP != normPlain && !normP.empty())
            toDelete.emplace_back(p, b->isFile);
    });

    // Sort: deepest first, files before directories
    std::sort(toDelete.begin(), toDelete.end(), [](const auto& a, const auto& b) {
        size_t depthA = std::count(a.first.begin(), a.first.end(), '/');
        size_t depthB = std::count(b.first.begin(), b.first.end(), '/');
        if (depthA != depthB) return depthA > depthB;
        if (a.second != b.second) return a.second;  // files first
        return false;
    });

    // Delete contents one by one
    for (const auto& [path, isFileItem] : toDelete) {
        flushAll();

        if (isFileItem) {
            auto fileBlock = findBlockByPath(path, true);
            if (fileBlock) {
                if (fileBlock->data_pos != 0 && fileBlock->size > 0)
                    storage_.free(fileBlock->data_pos, fileBlock->size);

                size_t fileParentPos = fileBlock->parent;
                unlinkBlock(fileBlock.get());

                if (fileParentPos != 0) {
                    auto fp = std::make_unique<Block>();
                    if (storage_.readBlock(fileParentPos, fp.get())) {
                        if (fp->files_n > 0) fp->files_n--;
                        storage_.writeBlock(fileParentPos, fp.get());
                    }
                }
            }
        } else {
            auto dirBlock = findBlockByPath(path, false);
            if (dirBlock) {
                size_t dirParentPos = dirBlock->parent;
                unlinkBlock(dirBlock.get());

                if (dirParentPos != 0) {
                    auto dp = std::make_unique<Block>();
                    if (storage_.readBlock(dirParentPos, dp.get())) {
                        if (dp->folders_n > 0) dp->folders_n--;
                        storage_.writeBlock(dirParentPos, dp.get());
                    }
                }
            }
        }
    }

    // Now delete the directory itself
    flushAll();

    block = findBlockByPath(plainPath, false);
    if (!block) {
        flushAll();
        logOperation("REMOVE_DIR_RECURSIVE", plainPath);
        return true;
    }

    size_t parentPos = block->parent;
    bool result = unlinkBlock(block.get());

    if (result && parentPos != 0) {
        auto parent = std::make_unique<Block>();
        if (storage_.readBlock(parentPos, parent.get())) {
            if (parent->folders_n > 0) parent->folders_n--;
            parent->setModifiedNow();
            storage_.writeBlock(parentPos, parent.get());
        }
    } else if (result) {
        syncRoot();
        if (root_->folders_n > 0) root_->folders_n--;
        root_->setModifiedNow();
        storage_.writeBlock(root_->current, root_.get());
    }

    flushAll();

    if (result) {
        logOperation("REMOVE_DIR_RECURSIVE", plainPath);
    }

    return result;
}

bool iNode::remove(const std::string& plainPath) {
    flushAll();

    // Check file first
    auto fileBlock = findBlockByPath(plainPath, true);
    if (fileBlock) {
        return removeFile(plainPath);
    }

    // Then check directory
    auto dirBlock = findBlockByPath(plainPath, false);
    if (dirBlock) {
        return removeDirectoryRecursive(plainPath);
    }

    std::cerr << "Path not found: " << plainPath << std::endl;
    return false;
}

std::pair<char*, size_t> iNode::readFile(const std::string& plainPath) {
    flushAll();

    auto block = findBlockByPath(plainPath, true);
    if (!block) return {nullptr, 0};

    block->setAccessedNow();
    storage_.writeBlock(block->current, block.get());

    auto [data, size] = readFileData(block.get());
    if (!data) return {nullptr, 0};

    logOperation("READ_FILE", plainPath);

    return {data.release(), size};
}

// Continuation of updateFile
bool iNode::updateFile(const std::string& plainPath, const char* data, size_t size) {
    flushAll();

    auto block = findBlockByPath(plainPath, true);
    if (!block) return false;

    if (block->data_pos != 0 && block->size > 0)
        storage_.free(block->data_pos, block->size);

    auto [encData, encSize] = encryptData(data, size);
    block->data_pos = storage_.allocate(encSize);
    block->size = encSize;
    block->setModifiedNow();

    bool result = storage_.write(block->data_pos, encData, encSize);
    result = result && storage_.writeBlock(block->current, block.get());
    if (encData) free(encData);

    flushAll();

    if (result) {
        logOperation("UPDATE_FILE", plainPath + " (" + std::to_string(size) + " bytes)");
    }

    return result;
}

bool iNode::exists(const std::string& plainPath, bool isFile) const {
    std::string norm = normalizePath(plainPath);
    if (norm.empty()) return !isFile;
    return findBlockByPath(plainPath, isFile) != nullptr;
}

bool iNode::rename(const std::string& plainPath, const std::string& newPlainName) {
    if (newPlainName.find('/') != std::string::npos || newPlainName.empty()) {
        std::cerr << "Invalid name: " << newPlainName << std::endl;
        return false;
    }

    flushAll();

    bool isFile = true;
    auto block = findBlockByPath(plainPath, true);
    if (!block) {
        block = findBlockByPath(plainPath, false);
        isFile = false;
    }
    if (!block) return false;

    std::string norm = normalizePath(plainPath);
    size_t lastSlash = norm.rfind('/');
    std::string parentPath = (lastSlash == std::string::npos) ? "" : norm.substr(0, lastSlash);
    std::string newFullPath = parentPath.empty() ? newPlainName : parentPath + "/" + newPlainName;

    if (exists(newFullPath, true) || exists(newFullPath, false)) {
        std::cerr << "Name already exists: " << newPlainName << std::endl;
        return false;
    }

    block->setName(newPlainName);
    block->setModifiedNow();
    bool result = storage_.writeBlock(block->current, block.get());

    flushAll();

    if (result) {
        logOperation("RENAME", plainPath + " -> " + newPlainName);
    }

    return result;
}

bool iNode::move(const std::string& srcPlainPath, const std::string& destPlainPath) {
    flushAll();

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
        size_t lastSlash = normDest.rfind('/');
        destDir = (lastSlash == std::string::npos) ? "" : normDest.substr(0, lastSlash);
        destName = (lastSlash == std::string::npos) ? normDest : normDest.substr(lastSlash + 1);
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

    // Update old parent count
    size_t oldParentPos = srcBlock->parent;
    if (oldParentPos != 0) {
        auto oldParent = std::make_unique<Block>();
        if (storage_.readBlock(oldParentPos, oldParent.get())) {
            if (isFile) { if (oldParent->files_n > 0) oldParent->files_n--; }
            else { if (oldParent->folders_n > 0) oldParent->folders_n--; }
            oldParent->setModifiedNow();
            storage_.writeBlock(oldParentPos, oldParent.get());
        }
    } else {
        syncRoot();
        if (isFile) { if (root_->files_n > 0) root_->files_n--; }
        else { if (root_->folders_n > 0) root_->folders_n--; }
        root_->setModifiedNow();
        storage_.writeBlock(root_->current, root_.get());
    }

    // Update siblings
    if (srcBlock->previous != 0) {
        auto prev = std::make_unique<Block>();
        if (storage_.readBlock(srcBlock->previous, prev.get())) {
            prev->next = srcBlock->next;
            storage_.writeBlock(srcBlock->previous, prev.get());
        }
    }
    if (srcBlock->next != 0) {
        auto next = std::make_unique<Block>();
        if (storage_.readBlock(srcBlock->next, next.get())) {
            next->previous = srcBlock->previous;
            storage_.writeBlock(srcBlock->next, next.get());
        }
    }

    // Update old parent's head pointer
    if (oldParentPos != 0) {
        auto oldParent = std::make_unique<Block>();
        if (storage_.readBlock(oldParentPos, oldParent.get())) {
            if (isFile && oldParent->data_pos == srcBlock->current) {
                oldParent->data_pos = srcBlock->next;
                storage_.writeBlock(oldParentPos, oldParent.get());
            } else if (!isFile && oldParent->subdir_pos == srcBlock->current) {
                oldParent->subdir_pos = srcBlock->next;
                storage_.writeBlock(oldParentPos, oldParent.get());
            }
        }
    } else {
        syncRoot();
        if (isFile && root_->data_pos == srcBlock->current) {
            root_->data_pos = srcBlock->next;
        } else if (!isFile && root_->subdir_pos == srcBlock->current) {
            root_->subdir_pos = srcBlock->next;
        }
        storage_.writeBlock(root_->current, root_.get());
    }

    // Update source block
    srcBlock->parent = destParentPos;
    srcBlock->previous = 0;
    srcBlock->next = 0;
    srcBlock->setName(destName);
    srcBlock->setModifiedNow();

    // Add to new parent
    auto newParent = std::make_unique<Block>();
    if (!storage_.readBlock(destParentPos, newParent.get())) return false;

    size_t* listHead = isFile ? &newParent->data_pos : &newParent->subdir_pos;
    if (*listHead == 0) {
        *listHead = srcBlock->current;
    } else {
        auto last = readBlockAt(*listHead);
        while (last && last->next != 0) last = readBlockAt(last->next);
        if (last) {
            last->next = srcBlock->current;
            srcBlock->previous = last->current;
            storage_.writeBlock(last->current, last.get());
        }
    }

    if (isFile) newParent->files_n++;
    else newParent->folders_n++;
    newParent->setModifiedNow();

    storage_.writeBlock(destParentPos, newParent.get());
    storage_.writeBlock(srcBlock->current, srcBlock.get());

    flushAll();

    logOperation("MOVE", srcPlainPath + " -> " + destPlainPath);
    return true;
}

bool iNode::copy(const std::string& srcPlainPath, const std::string& destPlainPath) {
    flushAll();

    if (exists(srcPlainPath, true)) {
        bool result = copyFile(srcPlainPath, destPlainPath);
        if (result) logOperation("COPY", srcPlainPath + " -> " + destPlainPath);
        return result;
    }
    if (exists(srcPlainPath, false)) {
        bool result = copyDirectoryRecursive(srcPlainPath, destPlainPath);
        if (result) logOperation("COPY_RECURSIVE", srcPlainPath + " -> " + destPlainPath);
        return result;
    }
    std::cerr << "Source not found: " << srcPlainPath << std::endl;
    return false;
}

bool iNode::copyFile(const std::string& srcPlainPath, const std::string& destPlainPath) {
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

bool iNode::copyDirectoryRecursive(const std::string& srcPlainPath, const std::string& destPlainPath) {
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
    items.reserve(64);

    walk(srcPlainPath, [&](Block* b, const std::string& plainPath, iNode*) {
        std::string normPath = normalizePath(plainPath);
        if (normPath == normSrc) return;
        if (normPath.length() > normSrc.length()) {
            std::string relPath = normPath.substr(normSrc.length());
            if (!relPath.empty() && relPath[0] == '/') relPath = relPath.substr(1);
            if (!relPath.empty()) items.emplace_back(plainPath, relPath, b->isFile);
        }
    });

    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        if (!std::get<2>(a) && std::get<2>(b)) return true;
        if (std::get<2>(a) && !std::get<2>(b)) return false;
        return std::count(std::get<1>(a).begin(), std::get<1>(a).end(), '/') <
               std::count(std::get<1>(b).begin(), std::get<1>(b).end(), '/');
    });

    for (const auto& [srcPath, relPath, isFileItem] : items) {
        std::string destPath = finalDest + "/" + relPath;
        if (isFileItem) {
            auto [fdata, fsize] = readFile(srcPath);
            if (fdata && fsize > 0) {
                addFile(destPath, fdata, fsize);
                delete[] fdata;
            }
        } else {
            addDirectory(destPath);
        }
    }

    flushAll();
    return true;
}

size_t iNode::importFile(const std::string& plainPath, const std::string& externalPath) {
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

    size_t result = addFile(plainPath, buffer.data(), fileSize);
    if (result > 0) {
        logOperation("IMPORT_FILE", externalPath + " -> " + plainPath);
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// DIRECTORY LISTING
// ═══════════════════════════════════════════════════════════════════════════

std::vector<iNode::DirEntry> iNode::listDirectory(const std::string& plainPath) const {
    std::vector<DirEntry> entries;
    std::string norm = normalizePath(plainPath);

    const_cast<iNode*>(this)->flushAll();

    std::unique_ptr<Block> dirBlock = norm.empty() ? cloneRoot() : findBlockByPath(plainPath, false);
    if (!dirBlock) return entries;

    entries.reserve(dirBlock->folders_n + dirBlock->files_n);

    auto isLogFile = [](const std::string& name) {
        return name == ".lockbox_log";
    };

    if (dirBlock->subdir_pos != 0) {
        auto cur = readBlockAt(dirBlock->subdir_pos);
        while (cur) {
            std::string plainName = cur->getPlainName();
            if (!isLogFile(plainName)) {
                entries.push_back({cur->getRawName(), plainName, false, 0});
            }
            if (cur->next == 0) break;
            cur = readBlockAt(cur->next);
        }
    }

    if (dirBlock->data_pos != 0) {
        auto cur = readBlockAt(dirBlock->data_pos);
        while (cur) {
            std::string plainName = cur->getPlainName();
            if (!isLogFile(plainName)) {
                entries.push_back({cur->getRawName(), plainName, true, cur->size});
            }
            if (cur->next == 0) break;
            cur = readBlockAt(cur->next);
        }
    }

    const_cast<iNode*>(this)->logOperation("LIST_DIR", plainPath.empty() ? "/" : plainPath);

    return entries;
}

std::vector<std::string> iNode::search(const std::string& name, bool caseSensitive) {
    std::vector<std::string> results;
    results.reserve(32);
    std::string searchName = caseSensitive ? name : toLower(name);

    walk([&](Block* b, const std::string& plainPath, iNode*) {
        std::string blockName = getFileName(normalizePath(plainPath));
        if (blockName == ".lockbox_log") return;
        if (!caseSensitive) blockName = toLower(blockName);
        if (blockName.find(searchName) != std::string::npos)
            results.push_back(plainPath);
    });

    logOperation("SEARCH", name + " (found " + std::to_string(results.size()) + " results)");

    return results;
}

size_t iNode::countSubdirs(const std::string& plainPath) const {
    std::string norm = normalizePath(plainPath);
    const_cast<iNode*>(this)->flushAll();
    if (norm.empty()) return root_->folders_n;
    auto block = findBlockByPath(plainPath, false);
    return block ? block->folders_n : 0;
}

size_t iNode::countFiles(const std::string& plainPath) const {
    std::string norm = normalizePath(plainPath);
    const_cast<iNode*>(this)->flushAll();
    if (norm.empty()) return root_->files_n;
    auto block = findBlockByPath(plainPath, false);
    return block ? block->files_n : 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// SEARCH & TRAVERSAL
// ═══════════════════════════════════════════════════════════════════════════

void iNode::walk(WalkCallback callback) { walk("/", callback); }

void iNode::walk(const std::string& startPlainPath, WalkCallback callback) {
    flushAll();
    std::string norm = normalizePath(startPlainPath);

    if (norm.empty()) {
        auto root = cloneRoot();
        callback(root.get(), "/", this);
        if (root->subdir_pos != 0) walkIterative(root->subdir_pos, "", callback);
        if (root->data_pos != 0) walkIterative(root->data_pos, "", callback);
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
        walkIterative(startBlock->subdir_pos, startPlainPath, callback);
    if (startBlock->data_pos != 0)
        walkIterative(startBlock->data_pos, startPlainPath, callback);
}

void iNode::walkIterative(size_t startPos, const std::string& basePath, WalkCallback callback) {
    struct StackEntry { size_t pos; std::string path; };
    std::vector<StackEntry> stack;
    stack.reserve(64);
    stack.push_back({startPos, basePath});

    while (!stack.empty()) {
        auto [pos, currentPath] = stack.back();
        stack.pop_back();

        if (pos == 0) continue;
        auto block = readBlockAt(pos);
        if (!block) continue;

        std::string plainName = block->getPlainName();
        std::string newPath = (currentPath.empty() || currentPath == "/")
                                  ? plainName : currentPath + "/" + plainName;

        callback(block.get(), newPath, this);

        if (block->next != 0) stack.push_back({block->next, currentPath});

        if (!block->isFile) {
            if (block->data_pos != 0) stack.push_back({block->data_pos, newPath});
            if (block->subdir_pos != 0) stack.push_back({block->subdir_pos, newPath});
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DISPLAY & STATS
// ═══════════════════════════════════════════════════════════════════════════

void iNode::display() const {
    const_cast<iNode*>(this)->flushAll();
    auto root = cloneRoot();
    std::cout << "══════════════════════════════════════════════════════════════\n"
              << "iNode Structure:\n"
              << "══════════════════════════════════════════════════════════════\n"
              << "📁 / [" << root->folders_n << " dirs, " << root->files_n << " files]\n";

    struct PrintEntry { size_t pos; int depth; bool isLast; std::vector<bool> cont; };
    std::vector<PrintEntry> stack;

    auto addChildren = [&](Block* block, int depth, std::vector<bool> cont) {
        std::vector<size_t> children;
        if (block->data_pos != 0) children.push_back(block->data_pos);
        if (block->subdir_pos != 0) children.push_back(block->subdir_pos);
        for (size_t i = children.size(); i > 0; --i) {
            stack.push_back({children[i - 1], depth, i == children.size(), cont});
        }
    };

    addChildren(root.get(), 1, {});

    while (!stack.empty()) {
        auto entry = stack.back();
        stack.pop_back();

        auto block = readBlockAt(entry.pos);
        if (!block) continue;

        for (int i = 0; i < entry.depth - 1; i++)
            std::cout << (i < (int)entry.cont.size() && entry.cont[i] ? "│   " : "    ");
        if (entry.depth > 0) std::cout << (entry.isLast ? "└── " : "├── ");

        std::string displayName = block->getPlainName();

        if (block->isFile) {
            std::cout << "📄 " << displayName << " (" << block->size << " bytes)\n";
        } else {
            std::cout << "📁 " << displayName << " [" << block->folders_n
                      << " dirs, " << block->files_n << " files]\n";
            auto newCont = entry.cont;
            newCont.push_back(!entry.isLast);
            addChildren(block.get(), entry.depth + 1, newCont);
        }

        if (block->next != 0) {
            stack.push_back({block->next, entry.depth, false, entry.cont});
        }
    }
    std::cout << "══════════════════════════════════════════════════════════════\n";
}

iNode::Stats iNode::getStats() const {
    Stats s = {0, 0, 0, 0, 0};
    s.totalSize = storage_.getFileSize();
    s.freeSpace = storage_.getFreeSpace();

    const_cast<iNode*>(this)->walk([&s](Block* b, const std::string&, iNode*) {
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
    flushAll();
    storage_.writeBlock(root_->current, root_.get());
    logOperation("SAVE", "LockBox saved");
}

void iNode::exportTo(const std::string& exportPath) { exportTo(exportPath, ""); }

void iNode::exportTo(const std::string& exportPath, const std::string& internalPlainPath) {
    if (!Filesystem::createDirectory(exportPath, true))
        throw std::runtime_error("Failed to create export directory");

    flushAll();

    if (internalPlainPath.empty()) {
        auto root = cloneRoot();
        if (root->subdir_pos != 0) exportIterative(root->subdir_pos, exportPath);
        if (root->data_pos != 0) exportIterative(root->data_pos, exportPath);
        logOperation("EXPORT_ALL", "-> " + exportPath);
        return;
    }

    auto fileBlock = findBlockByPath(internalPlainPath, true);
    if (fileBlock) {
        exportSingleFile(fileBlock.get(), exportPath);
        logOperation("EXPORT_FILE", internalPlainPath + " -> " + exportPath);
        return;
    }

    auto dirBlock = findBlockByPath(internalPlainPath, false);
    if (!dirBlock) throw std::runtime_error("Path not found: " + internalPlainPath);

    std::string targetPath = exportPath + "/" + dirBlock->getPlainName();
    Filesystem::createDirectory(targetPath, true);

    if (dirBlock->subdir_pos != 0) exportIterative(dirBlock->subdir_pos, targetPath);
    if (dirBlock->data_pos != 0) exportIterative(dirBlock->data_pos, targetPath);

    logOperation("EXPORT_DIR", internalPlainPath + " -> " + exportPath);
}

void iNode::exportIterative(size_t startPos, const std::string& basePath) {
    struct StackEntry { size_t pos; std::string destPath; };
    std::vector<StackEntry> stack;
    stack.reserve(64);
    stack.push_back({startPos, basePath});

    while (!stack.empty()) {
        auto [pos, destPath] = stack.back();
        stack.pop_back();

        if (pos == 0) continue;
        auto block = readBlockAt(pos);
        if (!block) continue;

        std::string plainName = block->getPlainName();

        if (plainName == ".lockbox_log") {
            if (block->next != 0) stack.push_back({block->next, destPath});
            continue;
        }

        std::string fullPath = destPath + "/" + plainName;

        if (block->isFile) {
            auto [data, size] = readFileData(block.get());
            if (data && size > 0) Filesystem::writeFile(fullPath, data.get(), size);
        } else {
            Filesystem::createDirectory(fullPath, true);
            if (block->data_pos != 0) stack.push_back({block->data_pos, fullPath});
            if (block->subdir_pos != 0) stack.push_back({block->subdir_pos, fullPath});
        }

        if (block->next != 0) stack.push_back({block->next, destPath});
    }
}

void iNode::exportSingleFile(Block* block, const std::string& destPath) {
    if (!block || !block->isFile) return;
    std::string fullPath = destPath + "/" + block->getPlainName();
    auto [data, size] = readFileData(block);
    if (data && size > 0) Filesystem::writeFile(fullPath, data.get(), size);
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILDER & IMPORT
// ═══════════════════════════════════════════════════════════════════════════

std::unique_ptr<iNode> iNode::buildFromFilesystem(const std::string& fsPath,
                                                   const std::string& inodePath,
                                                   OES* cipherEngine) {
    auto node = std::make_unique<iNode>(inodePath, cipherEngine);

    if (Filesystem::isDirectory(fsPath)) {
        node->scanFilesystem(fsPath, "");
    } else if (Filesystem::isFile(fsPath)) {
        std::string fileName = Filesystem::getFilename(fsPath);
        try {
            auto [size, buffer] = Filesystem::readFile(fsPath);
            if (size > 0) node->addFile(fileName, buffer.data(), size);
        } catch (const std::exception& e) {
            std::cerr << "Failed to read file: " << fsPath << " - " << e.what() << std::endl;
        }
    } else {
        throw std::runtime_error("Cannot access: " + fsPath);
    }
    return node;
}

void iNode::scanFilesystem(const std::string& fsPath, const std::string& internalPlainPath) {
    auto entries = Filesystem::listDirectory(fsPath);

    for (const auto& entry : entries) {
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
            } catch (const std::exception& e) {
                std::cerr << "Failed to read: " << fullPath << " - " << e.what() << std::endl;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAINTENANCE & ACCESSORS
// ═══════════════════════════════════════════════════════════════════════════

bool iNode::defragment() const {
    clearCache();
    storage_.defragmentFreeList();
    return true;
}

const std::string& iNode::getFilePath() const { return path_; }
OES* iNode::getCipherEngine() const { return cipher_; }

// ═══════════════════════════════════════════════════════════════════════════
// PATH UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

std::string iNode::normalizePath(const std::string& path) {
    if (path.empty() || path == "/") return "";
    size_t start = (path.front() == '/') ? 1 : 0;
    size_t end = path.length();
    if (end > start && path.back() == '/') end--;
    return (start == 0 && end == path.length()) ? path : path.substr(start, end - start);
}

std::string iNode::getParentPath(const std::string& path) {
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? "" : path.substr(0, pos);
}

std::string iNode::getFileName(const std::string& path) {
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string iNode::toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}