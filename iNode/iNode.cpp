#include "iNode.h"
#include "Block.h"
#include "io_helpers.h"
#include "utility.h"
#include <iostream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include <dirent.h>
#include "mman.h"

// ====================== Constructor / Destructor ======================

iNode::iNode(const std::string &path, OES *engine)
    : root(std::make_unique<Block>()), cipherEngine(engine), lockbox(-1), filePath(path) {
    // Try to open existing file first
    lockbox = open(path.c_str(), O_RDWR);

    if (lockbox != -1) {
        // File exists - load it
        size_t fileSize = getLockboxSize();

        if (fileSize < sizeof(Block)) {
            std::cerr << "Corrupted iNode file (too small): " << path << std::endl;
            ::close(lockbox);
            exit(255);
        }

        // Read root block (always at offset 0)
        if (!readBlock(0, root.get())) {
            std::cerr << "Failed to read root block from: " << path << std::endl;
            ::close(lockbox);
            exit(255);
        }

        std::cout << "Opened existing iNode: " << path << std::endl;
    } else {
        // File doesn't exist - create new one
        lockbox = open(path.c_str(), O_RDWR | O_CREAT, 0666);

        if (lockbox == -1) {
            std::cerr << "Failed to create iNode file: " << path << std::endl;
            exit(255);
        }

        // Initialize new iNode with root
        root->setName("root");
        root->isFile = false;
        root->level = 0;
        root->parent = 0;
        root->current = insertBlock(root.get());

        std::cout << "Created new iNode: " << path << std::endl;
    }
}

iNode::~iNode() {
    close_inode();
}

// ====================== Display ======================

void iNode::display() const {
    // CRITICAL FIX: Reload root from disk to get current counts
    Block freshRoot;
    if (!readBlock(0, &freshRoot)) {
        std::cerr << "Failed to read root block" << std::endl;
        return;
    }

    std::cout << "==================================================================================================\n";
    std::cout << "iNode Structure:\n";
    std::cout << "==================================================================================================\n";

    // Display root with fresh data from disk
    std::cout << "/" << freshRoot.getName() << " [" << freshRoot.folders_n << " dirs, " << freshRoot.files_n << " files]\n";

    // Walk from root's children
    if (freshRoot.subdir_pos != 0) {
        const_cast<iNode *>(this)->walkRecursive(freshRoot.subdir_pos, 1, "",
                                                 [](Block *block, const std::string &path, iNode *node) {
                                                     for (int i = 0; i < block->level; i++) {
                                                         std::cout << "│  ";
                                                     }
                                                     std::cout << (block->isFile ? "├─   " : "├─ ") << block->
                                                             getName();
                                                     if (block->isFile) {
                                                         std::cout << " (" << block->size << " bytes)";
                                                     } else {
                                                         std::cout << " [" << block->folders_n << " dirs, " << block->
                                                                 files_n << " files]";
                                                     }
                                                     std::cout << std::endl;
                                                 });
    }

    // Walk root's files
    if (freshRoot.data_pos != 0) {
        const_cast<iNode *>(this)->walkRecursive(freshRoot.data_pos, 1, "",
                                                 [](Block *block, const std::string &path, iNode *node) {
                                                     for (int i = 0; i < block->level; i++) {
                                                         std::cout << "│  ";
                                                     }
                                                     std::cout << "├─ " << block->getName() << " (" << block->size <<
                                                             " bytes)\n";
                                                 });
    }

    std::cout << "==================================================================================================\n";
}

// ====================== Save/Export ======================

void iNode::save() {
    // CRITICAL FIX: Reload root from disk before saving
    readBlock(0, root.get());

    if (cipherEngine) {
        cipherEngine->enc_adv();
    }
    updateBlock(root.get());
}

void iNode::exportTo(const std::string &exportPath) {
    std::string basePath = exportPath;
    if (!makePath(basePath, true)) {
        throw std::runtime_error("Failed to create export directory");
    }

    // Reload root to get fresh pointers
    Block freshRoot;
    readBlock(0, &freshRoot);

    // Export root's subdirectories
    if (freshRoot.subdir_pos != 0) {
        walkRecursive(freshRoot.subdir_pos, 1, basePath, exportCallback);
    }

    // Export root's files
    if (freshRoot.data_pos != 0) {
        walkRecursive(freshRoot.data_pos, 1, basePath, exportCallback);
    }
}

void iNode::exportCallback(Block *block, const std::string &path, iNode *node) {
    if (!block->isFile) {
        // Create directory
        if (block->level > 0) {
            if (!makePath(path, true)) {
                std::cerr << "Failed to create directory: " << path << std::endl;
            }
        }
        return;
    }

    // Create file
    int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        std::cerr << "Failed to create file: " << path << std::endl;
        return;
    }

    if (ftruncate(fd, block->size) == -1) {
        close(fd);
        return;
    }

    char *dst = (char *) mmap(nullptr, block->size, PROT_WRITE, MAP_SHARED, fd, 0);
    if (dst == MAP_FAILED) {
        close(fd);
        return;
    }

    // Read file data from iNode
    if (!node->read(block->data_pos, dst, block->size)) {
        munmap(dst, block->size);
        close(fd);
        return;
    }

    // Decrypt if cipher engine present
    if (node->cipherEngine) {
        auto decrypted = node->decryptData(dst, block->size);
        if (decrypted.first) {
            memcpy(dst, decrypted.first, decrypted.second);
            free(decrypted.first);
        }
    }

    msync(dst, block->size, MS_SYNC);
    munmap(dst, block->size);
    close(fd);
}

// ====================== File/Directory Operations ======================

off64_t iNode::addFile(const std::string &internalPath, const char *data, size_t size) {
    if (exists(internalPath, true)) {
        std::cerr << "File already exists: " << internalPath << std::endl;
        return 0;
    }

    std::string normalPath = normalizePath(internalPath);
    std::string dirPath = basename(normalPath);
    std::string fileName = filename(normalPath);

    // Create parent directories if needed
    off64_t parentPos = 0;
    if (!dirPath.empty()) {
        parentPos = createDirectoryChain(dirPath);
    } else {
        parentPos = root->current;
    }

    if (parentPos == 0) {
        return 0;
    }

    // Encrypt data if cipher engine present
    char *dataToStore = const_cast<char *>(data);
    size_t sizeToStore = size;
    bool needsFree = false;

    if (cipherEngine) {
        auto encrypted = encryptData(data, size);
        dataToStore = encrypted.first;
        sizeToStore = encrypted.second;
        needsFree = true;
    }

    off64_t filePos = createFileBlock(fileName, dataToStore, sizeToStore, parentPos);

    if (needsFree) {
        free(dataToStore);
    }

    // CRITICAL FIX: Reload root after modification
    readBlock(0, root.get());

    return filePos;
}

off64_t iNode::addDirectory(const std::string &internalPath) {
    if (exists(internalPath, false)) {
        return 0; // Already exists
    }

    off64_t result = createDirectoryChain(normalizePath(internalPath));

    // CRITICAL FIX: Reload root after modification
    readBlock(0, root.get());

    return result;
}

bool iNode::removeFile(const std::string &internalPath) {
    auto [block, parent] = findBlockAndParent(internalPath, true);
    if (!block) {
        return false;
    }

    // Free data space
    freeSpace(block->data_pos, block->size);

    // Unlink from parent's file list
    bool result = unlinkBlock(block);

    // Update parent file count
    if (parent) {
        parent->files_n--;
        updateBlock(parent);
        delete parent;
    }

    delete block;

    // CRITICAL FIX: Reload root after modification
    readBlock(0, root.get());

    return result;
}

bool iNode::removeDirectory(const std::string &internalPath) {
    Block *block = findBlock(internalPath, false);
    if (!block) {
        return false;
    }

    // Check if directory is empty
    if (block->subdir_pos != 0 || block->data_pos != 0) {
        std::cerr << "Cannot remove non-empty directory: " << internalPath << std::endl;
        delete block;
        return false;
    }

    bool result = unlinkBlock(block);
    delete block;

    // CRITICAL FIX: Reload root after modification
    readBlock(0, root.get());

    return result;
}

std::pair<char *, size_t> iNode::readFile(const std::string &internalPath) {
    Block *fileBlock = findBlock(internalPath, true);
    if (!fileBlock) {
        return {nullptr, 0};
    }

    char *data = (char *) malloc(fileBlock->size);
    if (!read(fileBlock->data_pos, data, fileBlock->size)) {
        free(data);
        delete fileBlock;
        return {nullptr, 0};
    }

    // Decrypt if cipher engine present
    if (cipherEngine) {
        auto decrypted = decryptData(data, fileBlock->size);
        free(data);
        delete fileBlock;
        return decrypted;
    }

    size_t size = fileBlock->size;
    delete fileBlock;
    return {data, size};
}

bool iNode::updateFile(const std::string &internalPath, const char *data, size_t size) {
    Block *fileBlock = findBlock(internalPath, true);
    if (!fileBlock) {
        return false;
    }

    // Free old data space
    freeSpace(fileBlock->data_pos, fileBlock->size);

    // Encrypt new data if needed
    char *dataToStore = const_cast<char *>(data);
    size_t sizeToStore = size;
    bool needsFree = false;

    if (cipherEngine) {
        auto encrypted = encryptData(data, size);
        dataToStore = encrypted.first;
        sizeToStore = encrypted.second;
        needsFree = true;
    }

    // Allocate new space and write data
    fileBlock->data_pos = allocateSpace(sizeToStore);
    fileBlock->size = sizeToStore;

    bool result = write(dataToStore, fileBlock->data_pos, sizeToStore) && updateBlock(fileBlock);

    if (needsFree) {
        free(dataToStore);
    }

    delete fileBlock;
    return result;
}

bool iNode::exists(const std::string &internalPath, bool isFile) const {
    Block *block = findBlock(internalPath, isFile);
    if (block) {
        delete block;
        return true;
    }
    return false;
}

Block *iNode::findBlock(const std::string &internalPath, bool isFile) const {
    std::string normalPath = normalizePath(internalPath);

    if (normalPath.empty()) {
        return cloneBlock(root.get());
    }

    // Navigate to parent directory
    std::string dirPath = basename(normalPath);
    std::string targetName = filename(normalPath);

    Block *currentDir = nullptr;

    if (dirPath.empty()) {
        // Target is in root
        currentDir = cloneBlock(root.get());
    } else {
        // Navigate to parent directory
        std::istringstream pathStream(dirPath);
        std::string token;
        currentDir = cloneBlock(root.get());

        while (std::getline(pathStream, token, '/')) {
            if (token.empty()) continue;

            if (currentDir->subdir_pos == 0) {
                delete currentDir;
                return nullptr;
            }

            Block *subdirBlock = new Block();
            if (!readBlock(currentDir->subdir_pos, subdirBlock)) {
                delete subdirBlock;
                delete currentDir;
                return nullptr;
            }

            bool found = false;
            do {
                if (strcmp(subdirBlock->name, token.c_str()) == 0) {
                    found = true;
                    delete currentDir;
                    currentDir = subdirBlock;
                    break;
                }

                if (subdirBlock->next == 0) break;
            } while (readBlock(subdirBlock->next, subdirBlock));

            if (!found) {
                delete subdirBlock;
                delete currentDir;
                return nullptr;
            }
        }
    }

    // Now search in currentDir for the target
    if (isFile) {
        // Search in file list
        if (currentDir->data_pos == 0) {
            delete currentDir;
            return nullptr;
        }

        Block *fileBlock = new Block();
        if (!readBlock(currentDir->data_pos, fileBlock)) {
            delete fileBlock;
            delete currentDir;
            return nullptr;
        }

        do {
            if (strcmp(fileBlock->name, targetName.c_str()) == 0) {
                // found — return block (caller must delete)
                delete currentDir;
                return fileBlock;
            }
            if (fileBlock->next == 0) break;
            if (!readBlock(fileBlock->next, fileBlock)) break;
        } while (true);

        // Not found
        delete fileBlock;
        delete currentDir;
        return nullptr;
    } else {
        // Search in subdirectory list
        if (currentDir->subdir_pos == 0) {
            delete currentDir;
            return nullptr;
        }

        Block *subdirBlock = new Block();
        if (!readBlock(currentDir->subdir_pos, subdirBlock)) {
            delete subdirBlock;
            delete currentDir;
            return nullptr;
        }

        do {
            if (strcmp(subdirBlock->name, targetName.c_str()) == 0) {
                // found — return block (caller must delete)
                delete currentDir;
                return subdirBlock;
            }
            if (subdirBlock->next == 0) break;
            if (!readBlock(subdirBlock->next, subdirBlock)) break;
        } while (true);

        // Not found
        delete subdirBlock;
        delete currentDir;
        return nullptr;
    }

    // If looking for directory and target is empty (root case handled above)
    // This should not be reached
    return currentDir;
}

// ====================== Traversal Operations ======================

void iNode::walk(const std::string &startPath, WalkerCallback callback) {
    Block *startBlock = findBlock(startPath, false);
    if (!startBlock) {
        std::cerr << "Path not found: " << startPath << std::endl;
        return;
    }

    callback(startBlock, startPath, this);

    // Walk subdirectories
    if (startBlock->subdir_pos != 0) {
        walkRecursive(startBlock->subdir_pos, startBlock->level + 1, startPath, callback);
    }

    // Walk files
    if (startBlock->data_pos != 0) {
        walkRecursive(startBlock->data_pos, startBlock->level + 1, startPath, callback);
    }

    delete startBlock;
}

void iNode::walk(WalkerCallback callback) {
    walk("/", callback);
}

void iNode::walkRecursive(off64_t blockPos, int level, const std::string &currentPath, WalkerCallback callback) {
    Block *block = new Block();
    if (!readBlock(blockPos, block)) {
        delete block;
        return;
    }

    std::string newPath = currentPath.empty() ? block->getName() : currentPath + "/" + block->getName();
    callback(block, newPath, this);

    // If it's a directory, walk its children
    if (!block->isFile) {
        if (block->subdir_pos != 0) {
            walkRecursive(block->subdir_pos, level + 1, newPath, callback);
        }
        if (block->data_pos != 0) {
            walkRecursive(block->data_pos, level + 1, newPath, callback);
        }
    }

    // Walk siblings
    if (block->next != 0) {
        walkRecursive(block->next, level, currentPath, callback);
    }

    delete block;
}

unsigned int iNode::countSubdirs(const std::string &path) const {
    if (path == "/" || path.empty()) {
        // CRITICAL FIX: Reload root from disk to get current counts
        Block freshRoot;
        if (readBlock(0, &freshRoot)) {
            return freshRoot.folders_n;
        }
        return root->folders_n;
    }

    Block *block = findBlock(path, false);
    if (!block) {
        return 0;
    }

    unsigned int count = block->folders_n;
    delete block;
    return count;
}

unsigned int iNode::countFiles(const std::string &path) const {
    if (path == "/" || path.empty()) {
        // CRITICAL FIX: Reload root from disk to get current counts
        Block freshRoot;
        if (readBlock(0, &freshRoot)) {
            return freshRoot.files_n;
        }
        return root->files_n;
    }

    Block *block = findBlock(path, false);
    if (!block) {
        return 0;
    }

    unsigned int count = block->files_n;
    delete block;
    return count;
}

// ====================== Builder Function ======================

std::unique_ptr<iNode> iNode::buildFromFilesystem(
    const std::string &fsPath,
    const std::string &inodePath,
    OES *cipherEngine) {
    auto node = std::make_unique<iNode>(inodePath, cipherEngine);

    struct stat st;
    if (stat(fsPath.c_str(), &st) != 0) {
        throw std::runtime_error("Cannot access filesystem path: " + fsPath);
    }

    if (S_ISDIR(st.st_mode)) {
        node->scanFilesystem(fsPath, "");
    } else if (S_ISREG(st.st_mode)) {
        // Single file
        std::string fileName = filename(fsPath);
        char *data = nullptr;
        size_t size = 0;

        int fd = open(fsPath.c_str(), O_RDONLY);
        if (fd >= 0) {
            size = st.st_size;
            data = (char *) mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (data != MAP_FAILED) {
                node->addFile(fileName, data, size);
                munmap(data, size);
            }
            close(fd);
        }
    }

    return node;
}

// ====================== Low-level IO ======================

size_t iNode::getLockboxSize() const {
    if (lockbox <= 0) return 0;
    return lseek64(lockbox, 0, SEEK_END);
}

off64_t iNode::allocateSpace(size_t size) {
    // Simple allocation: append to end
    return getLockboxSize();
}

void iNode::freeSpace(off64_t pos, size_t size) {
    // Add to free list (simple implementation)
    freeList.push_back({pos, size});
}

void iNode::defragment() {
    // TODO: Implement defragmentation
}

bool iNode::write(const void *buf, off64_t pos, size_t size) {
    if (lockbox <= 0) return false;

    size_t length = getLockboxSize();
    size_t neededSize = pos + size;

    if (neededSize > length) {
        // Extend file
        if (ftruncate(lockbox, neededSize) == -1) {
            return false;
        }
        length = neededSize;
    }

    char *mapped = (char *) mmap(nullptr, length, PROT_WRITE, MAP_SHARED, lockbox, 0);
    if (mapped == MAP_FAILED) {
        return false;
    }

    memcpy(mapped + pos, buf, size);
    msync(mapped, length, MS_SYNC);
    munmap(mapped, length);

    return true;
}

bool iNode::read(off64_t pos, void *buf, size_t size) const {
    if (lockbox <= 0 || buf == nullptr) return false;

    off64_t length = getLockboxSize();
    if (pos + size > (size_t)length) {
        return false;
    }

    char *mapped = (char *) mmap(nullptr, length, PROT_READ, MAP_SHARED, lockbox, 0);
    if (mapped == MAP_FAILED) {
        return false;
    }

    memcpy(buf, mapped + pos, size);
    munmap(mapped, length);

    return true;
}

// ====================== Block Operations ======================

bool iNode::readBlock(off64_t offset, Block *block) const {
    if (lockbox < 0 || offset < 0) return false;
    return read(offset, block, sizeof(Block));
}

off64_t iNode::insertBlock(Block *block) {
    off64_t pos = allocateSpace(sizeof(Block));
    block->current = pos;
    write(block, pos, sizeof(Block));
    return pos;
}

bool iNode::updateBlock(Block *block) {
    return write(block, block->current, sizeof(Block));
}

bool iNode::deleteBlock(off64_t pos) {
    freeSpace(pos, sizeof(Block));
    return true;
}

// ====================== Navigation ======================

Block *iNode::navigateToPath(const std::string &path, bool createIfMissing, bool isFile) const {
    // Not used in current implementation
    return nullptr;
}

std::pair<Block *, Block *> iNode::findBlockAndParent(const std::string &path, bool isFile) const {
    std::string dirPath = basename(path);
    Block *parent = dirPath.empty() ? cloneBlock(root.get()) : findBlock(dirPath, false);

    if (!parent) {
        return {nullptr, nullptr};
    }

    Block *block = findBlock(path, isFile);
    return {block, parent};
}

// ====================== Internal Helpers ======================

off64_t iNode::createDirectoryChain(const std::string &path) {
    std::istringstream pathStream(normalizePath(path));
    std::string token;

    Block *parent = cloneBlock(root.get());
    Block *current = new Block();

    int level = 1;

    while (std::getline(pathStream, token, '/')) {
        if (token.empty()) continue;

        // Check if directory already exists
        if (parent->subdir_pos != 0) {
            readBlock(parent->subdir_pos, current);
            bool found = false;

            do {
                if (strcmp(current->name, token.c_str()) == 0) {
                    found = true;
                    break;
                }
            } while (current->next != 0 && readBlock(current->next, current));

            if (found) {
                delete parent;
                parent = cloneBlock(current);
                level++;
                continue;
            }
        }

        // Create new directory
        current->reset();
        current->setName(token.c_str());
        current->isFile = false;
        current->level = level;
        current->parent = parent->current;
        current->current = insertBlock(current);

        // Link to parent
        if (parent->subdir_pos == 0) {
            parent->subdir_pos = current->current;
        } else {
            Block *lastSibling = new Block();
            readBlock(parent->subdir_pos, lastSibling);

            while (lastSibling->next != 0) {
                readBlock(lastSibling->next, lastSibling);
            }

            lastSibling->next = current->current;
            current->previous = lastSibling->current;
            updateBlock(lastSibling);
            delete lastSibling;
        }

        parent->folders_n++;
        updateBlock(parent);
        updateBlock(current);

        delete parent;
        parent = cloneBlock(current);
        level++;
    }

    off64_t result = parent->current;
    delete parent;
    delete current;

    return result;
}

off64_t iNode::createFileBlock(const std::string &name, const char *data, size_t size, off64_t parentPos) {
    Block *parent = new Block();
    if (!readBlock(parentPos, parent)) {
        delete parent;
        return 0;
    }

    Block *fileBlock = new Block();
    fileBlock->reset();
    fileBlock->setName(name.c_str());
    fileBlock->isFile = true;
    fileBlock->level = parent->level + 1;
    fileBlock->parent = parentPos;
    fileBlock->size = size;
    fileBlock->data_pos = allocateSpace(size);

    // Write file data
    if (!write(data, fileBlock->data_pos, size)) {
        delete parent;
        delete fileBlock;
        return 0;
    }

    fileBlock->current = insertBlock(fileBlock);

    // Link to parent's file list
    if (parent->data_pos == 0) {
        parent->data_pos = fileBlock->current;
    } else {
        Block *lastFile = new Block();
        readBlock(parent->data_pos, lastFile);

        while (lastFile->next != 0) {
            readBlock(lastFile->next, lastFile);
        }

        lastFile->next = fileBlock->current;
        fileBlock->previous = lastFile->current;
        updateBlock(lastFile);
        delete lastFile;
    }

    parent->files_n++;
    updateBlock(parent);

    off64_t result = fileBlock->current;
    delete parent;
    delete fileBlock;

    return result;
}

bool iNode::unlinkBlock(Block *block) {
    // Unlink from siblings
    if (block->previous != 0) {
        Block *prev = new Block();
        readBlock(block->previous, prev);
        prev->next = block->next;
        updateBlock(prev);
        delete prev;
    }

    if (block->next != 0) {
        Block *next = new Block();
        readBlock(block->next, next);
        next->previous = block->previous;
        updateBlock(next);
        delete next;
    }

    // Update parent's first child pointer if this was first
    if (block->parent != 0) {
        Block *parent = new Block();
        readBlock(block->parent, parent);

        if (block->isFile && parent->data_pos == block->current) {
            parent->data_pos = block->next;
            updateBlock(parent);
        } else if (!block->isFile && parent->subdir_pos == block->current) {
            parent->subdir_pos = block->next;
            updateBlock(parent);
        }

        delete parent;
    }

    return deleteBlock(block->current);
}

// ====================== Filesystem Scanner ======================

void iNode::scanFilesystem(const std::string &fsPath, const std::string &internalPath) {
    DIR *dir = opendir(fsPath.c_str());
    if (!dir) {
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string fullPath = fsPath + "/" + name;
        std::string newInternalPath = internalPath.empty() ? name : internalPath + "/" + name;

        struct stat st;
        if (stat(fullPath.c_str(), &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            addDirectory(newInternalPath);
            scanFilesystem(fullPath, newInternalPath);
        } else if (S_ISREG(st.st_mode)) {
            int fd = open(fullPath.c_str(), O_RDONLY);
            if (fd >= 0) {
                size_t size = st.st_size;
                char *data = (char *) mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (data != MAP_FAILED) {
                    addFile(newInternalPath, data, size);
                    munmap(data, size);
                }
                close(fd);
            }
        }
    }

    closedir(dir);
}

// ====================== Encryption Helpers ======================

std::pair<char *, size_t> iNode::encryptData(const char *data, size_t size) {
    if (!cipherEngine) {
        auto copy = static_cast<char *>(malloc(size));
        memcpy(copy, data, size);
        return {copy, size};
    }

    cipherEngine->load_data(const_cast<char *>(data), size)->enc_adv();

    size_t encSize = cipherEngine->get_cipherBlock()->len;
    auto encrypted = static_cast<char *>(malloc(encSize));
    memcpy(encrypted, cipherEngine->get_cipherBlock()->data, encSize);

    return {encrypted, encSize};
}

std::pair<char *, size_t> iNode::decryptData(const char *data, size_t size) {
    if (!cipherEngine) {
        auto copy = static_cast<char *>(malloc(size));
        memcpy(copy, data, size);
        return {copy, size};
    }

    cipherEngine->load_data(const_cast<char *>(data), size)->dec_adv();

    size_t decSize = cipherEngine->get_cipherBlock()->len;
    char *decrypted = (char *) malloc(decSize);
    memcpy(decrypted, cipherEngine->get_cipherBlock()->data, decSize);

    return {decrypted, decSize};
}

// ====================== Utility ======================

Block *iNode::cloneBlock(const Block *src) const {
    Block *dst = new Block();
    memcpy(dst, src, sizeof(Block));
    return dst;
}

std::string iNode::normalizePath(const std::string &path) const {
    if (path.empty() || path == "/") {
        return "";
    }

    std::string result = path;

    // Remove leading slash
    if (result[0] == '/') {
        result = result.substr(1);
    }

    // Remove trailing slash
    if (result.back() == '/') {
        result = result.substr(0, result.size() - 1);
    }

    return result;
}

void iNode::close_inode() {
    if (lockbox > 0) {
        ::close(lockbox);
        lockbox = -1;
    }
}