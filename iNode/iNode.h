#pragma once

#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <OpenES/OES.h>
#include "Block.h"

// Function pointer type for walker callbacks
using WalkerCallback = std::function<void(Block*, const std::string&, class iNode*)>;

class iNode {
public:
    // Constructor: opens existing iNode file or creates new one
    // If path ends with .sc, opens existing lockbox
    // Otherwise creates new lockbox at path/lockbox.sc
    iNode(const std::string& path, OES* cipherEngine = nullptr);
    ~iNode();

    // === Core Operations ===

    // Display entire tree structure
    void display() const;

    // Save iNode metadata
    void save();

    // Export entire iNode to filesystem
    void exportTo(const std::string& exportPath);

    // Close the iNode file
    void close_inode();

    // === File/Directory Operations ===

    // Add file to iNode (encrypts if cipherEngine present)
    off64_t addFile(const std::string& internalPath, const char* data, size_t size);

    // Add directory to iNode
    off64_t addDirectory(const std::string& internalPath);

    // Remove file from iNode
    bool removeFile(const std::string& internalPath);

    // Remove directory (must be empty)
    bool removeDirectory(const std::string& internalPath);

    // Read file content (decrypts if cipherEngine present)
    std::pair<char*, size_t> readFile(const std::string& internalPath);

    // Update existing file content
    bool updateFile(const std::string& internalPath, const char* data, size_t size);

    // Check if path exists
    bool exists(const std::string& internalPath, bool isFile) const;

    // Search for file/directory
    Block* findBlock(const std::string& internalPath, bool isFile) const;

    // === Traversal Operations ===

    // Walk tree with callback for each entry
    void walk(const std::string& startPath, WalkerCallback callback);
    void walk(WalkerCallback callback); // From root

    // Count subdirectories in a path
    unsigned int countSubdirs(const std::string& path) const;

    // Count files in a path
    unsigned int countFiles(const std::string& path) const;

    // === Builder Function (Static) ===

    // Build iNode from filesystem directory/file
    static std::unique_ptr<iNode> buildFromFilesystem(
        const std::string& fsPath,
        const std::string& inodePath,
        OES* cipherEngine = nullptr
    );

private:
    std::unique_ptr<Block> root;
    int lockbox;
    OES* cipherEngine;
    std::string filePath;

    // Fragmentation management
    struct FragmentInfo {
        off64_t position;
        size_t size;
    };
    std::vector<FragmentInfo> freeList;

    // === Low-level IO ===
    size_t getLockboxSize() const;
    off64_t allocateSpace(size_t size);
    void freeSpace(off64_t pos, size_t size);
    void defragment(); // Slide content after modification

    bool write(const void* buf, off64_t pos, size_t size);
    bool read(off64_t pos, void* buf, size_t size) const;

    // === Block Operations ===
    bool readBlock(off64_t offset, Block* block) const;
    off64_t insertBlock(Block* block);
    bool updateBlock(Block* block);
    bool deleteBlock(off64_t pos);

    // === Navigation ===
    Block* navigateToPath(const std::string& path, bool createIfMissing, bool isFile) const;
    std::pair<Block*, Block*> findBlockAndParent(const std::string& path, bool isFile) const;

    // === Internal Helpers ===
    off64_t createDirectoryChain(const std::string& path);
    off64_t createFileBlock(const std::string& name, const char* data, size_t size, off64_t parentPos);
    bool unlinkBlock(Block* block);

    // Walker implementation
    void walkRecursive(off64_t blockPos, int level, const std::string& currentPath, WalkerCallback callback);

    // Filesystem scanner for builder
    void scanFilesystem(const std::string& fsPath, const std::string& internalPath);

    // Encryption helpers
    std::pair<char*, size_t> encryptData(const char* data, size_t size);
    std::pair<char*, size_t> decryptData(const char* data, size_t size);

    // Static callbacks for common operations
    static void displayCallback(Block* block, const std::string& path, iNode* node);
    static void exportCallback(Block* block, const std::string& path, iNode* node);

    // Utility
    Block* cloneBlock(const Block* src) const;
    std::string normalizePath(const std::string& path) const;

    // Disable copy
    iNode(const iNode&) = delete;
    iNode& operator=(const iNode&) = delete;
};