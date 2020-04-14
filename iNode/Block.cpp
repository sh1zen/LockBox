#include "Block.h"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>

// ====================== Constructor / Destructor ======================

Block::Block() {
    // Initialize all fields to zero/default
    reset();
}

Block::~Block() {
    // No dynamic memory to free since we use fixed-size array
    // This is intentional for disk I/O compatibility
}

// ====================== Core Methods ======================

void Block::reset() {
    // Clear name
    memset(name, 0, MAX_NAME_LENGTH);

    // Reset type
    isFile = false;

    // Reset counters
    files_n = 0;
    folders_n = 0;

    // Reset positions
    current = 0;
    parent = 0;
    subdir_pos = 0;
    data_pos = 0;
    size = 0;

    // Reset linked list pointers
    next = 0;
    previous = 0;

    // Reset depth
    level = 0;

    // Clear padding
    memset(_padding, 0, sizeof(_padding));
}

void Block::setName(const char* newName) {
    if (newName == nullptr) {
        name[0] = '\0';
        return;
    }

    // Copy name with bounds checking
    size_t len = strlen(newName);
    if (len >= MAX_NAME_LENGTH) {
        len = MAX_NAME_LENGTH - 1;
    }

    memcpy(name, newName, len);
    name[len] = '\0';
}

const char* Block::getName() const {
    return name;
}

bool Block::isFileBlock() const {
    return isFile;
}

bool Block::isDirectoryBlock() const {
    return !isFile;
}

void Block::copyFrom(const Block* other) {
    if (other == nullptr) {
        return;
    }

    // Deep copy all fields
    memcpy(this, other, sizeof(Block));
}

void Block::print() const {
    std::cout << "╔════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                           BLOCK INFO                               ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════════╣\n";

    std::cout << "║ Name:          " << std::left << std::setw(50) << name << " ║\n";
    std::cout << "║ Type:          " << std::left << std::setw(50)
              << (isFile ? "FILE" : "DIRECTORY") << " ║\n";
    std::cout << "║ Current Pos:   " << std::left << std::setw(50) << current << " ║\n";
    std::cout << "║ Parent Pos:    " << std::left << std::setw(50) << parent << " ║\n";
    std::cout << "║ Level:         " << std::left << std::setw(50) << level << " ║\n";

    if (isFile) {
        std::cout << "╠════════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ FILE SPECIFIC:                                                     ║\n";
        std::cout << "║ Data Pos:      " << std::left << std::setw(50) << data_pos << " ║\n";
        std::cout << "║ Size:          " << std::left << std::setw(50) << size << " ║\n";
    } else {
        std::cout << "╠════════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ DIRECTORY SPECIFIC:                                                ║\n";
        std::cout << "║ Subdir Pos:    " << std::left << std::setw(50) << subdir_pos << " ║\n";
        std::cout << "║ Data Pos:      " << std::left << std::setw(50) << data_pos << " ║\n";
        std::cout << "║ Files:         " << std::left << std::setw(50) << files_n << " ║\n";
        std::cout << "║ Folders:       " << std::left << std::setw(50) << folders_n << " ║\n";
    }

    std::cout << "╠════════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ LINKED LIST:                                                       ║\n";
    std::cout << "║ Next:          " << std::left << std::setw(50) << next << " ║\n";
    std::cout << "║ Previous:      " << std::left << std::setw(50) << previous << " ║\n";

    std::cout << "╚════════════════════════════════════════════════════════════════════╝\n";
}

bool Block::isValid() const {
    // Basic validation checks

    // Name should be null-terminated
    bool nameValid = false;
    for (size_t i = 0; i < MAX_NAME_LENGTH; i++) {
        if (name[i] == '\0') {
            nameValid = true;
            break;
        }
    }
    if (!nameValid) {
        return false;
    }

    // File-specific validation
    if (isFile) {
        // Files should not have subdirectories
        if (subdir_pos != 0) {
            return false;
        }

        // Files should not have folder counts
        if (folders_n != 0) {
            return false;
        }

        // Files should have valid size if they have data
        if (data_pos > 0 && size == 0) {
            return false; // File with data should have size > 0
        }
    } else {
        // Directories should not have file size
        if (size != 0) {
            return false;
        }
    }

    // Linked list consistency
    if (next < 0 || previous < 0) {
        return false;
    }

    // Position values should be non-negative
    if (current < 0 || parent < 0 || subdir_pos < 0 || data_pos < 0) {
        return false;
    }

    return true;
}

// ====================== Static Helper Functions ======================

namespace BlockHelper {

    /**
     * Create a new file block
     */
    Block* createFileBlock(const char* fileName, uint64_t fileSize,
                          int64_t parentPos, int64_t dataPos, uint32_t depth) {
        Block* block = new Block();
        block->setName(fileName);
        block->isFile = true;
        block->parent = parentPos;
        block->data_pos = dataPos;
        block->size = fileSize;
        block->level = depth;
        return block;
    }

    /**
     * Create a new directory block
     */
    Block* createDirectoryBlock(const char* dirName, int64_t parentPos, uint32_t depth) {
        Block* block = new Block();
        block->setName(dirName);
        block->isFile = false;
        block->parent = parentPos;
        block->level = depth;
        return block;
    }

    /**
     * Calculate total size of block structure
     */
    size_t getBlockSize() {
        return sizeof(Block);
    }

    /**
     * Check if two blocks are equivalent (deep comparison)
     */
    bool areEqual(const Block* a, const Block* b) {
        if (a == nullptr || b == nullptr) {
            return a == b;
        }

        return memcmp(a, b, sizeof(Block)) == 0;
    }

    /**
     * Clone a block (deep copy)
     */
    Block* clone(const Block* source) {
        if (source == nullptr) {
            return nullptr;
        }

        Block* copy = new Block();
        copy->copyFrom(source);
        return copy;
    }

    /**
     * Initialize a root block
     */
    void initializeRoot(Block* block) {
        if (block == nullptr) {
            return;
        }

        block->reset();
        block->setName("root");
        block->isFile = false;
        block->level = 0;
        block->parent = 0;
    }

    /**
     * Print block in compact format
     */
    void printCompact(const Block* block) {
        if (block == nullptr) {
            std::cout << "[NULL BLOCK]" << std::endl;
            return;
        }

        std::cout << (block->isFile ? "📄" : "📁") << " " << block->name << " ";

        if (block->isFile) {
            std::cout << "(" << block->size << " bytes)";
        } else {
            std::cout << "[" << block->folders_n << " dirs, "
                      << block->files_n << " files]";
        }

        std::cout << " @" << block->current
                  << " L" << block->level << std::endl;
    }

    /**
     * Validate block integrity
     */
    bool validateIntegrity(const Block* block, bool verbose = false) {
        if (block == nullptr) {
            if (verbose) std::cerr << "Block is NULL" << std::endl;
            return false;
        }

        if (!block->isValid()) {
            if (verbose) std::cerr << "Block validation failed" << std::endl;
            return false;
        }

        // Additional integrity checks
        if (block->isFile) {
            if (block->data_pos > 0 && block->size == 0) {
                if (verbose) std::cerr << "File has data position but zero size" << std::endl;
                return false;
            }
        }

        return true;
    }

    /**
     * Calculate memory footprint of block
     */
    size_t getMemoryFootprint() {
        return sizeof(Block);
    }

    /**
     * Get human-readable type string
     */
    const char* getTypeString(const Block* block) {
        if (block == nullptr) {
            return "NULL";
        }
        return block->isFile ? "FILE" : "DIRECTORY";
    }

    /**
     * Check if block is root
     */
    bool isRoot(const Block* block) {
        if (block == nullptr) {
            return false;
        }

        return block->level == 0 &&
               block->parent == 0 &&
               strcmp(block->name, "root") == 0;
    }

    /**
     * Check if block is leaf (no children)
     */
    bool isLeaf(const Block* block) {
        if (block == nullptr) {
            return false;
        }

        if (block->isFile) {
            return true; // Files are always leaves
        }

        return block->subdir_pos == 0 && block->data_pos == 0;
    }

    /**
     * Get total entries count (files + folders)
     */
    uint32_t getTotalEntries(const Block* block) {
        if (block == nullptr || block->isFile) {
            return 0;
        }

        return block->files_n + block->folders_n;
    }

} // namespace BlockHelper