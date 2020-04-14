#pragma once

#include <cstdint>
#include <type_traits>

// Maximum name length for files and directories
#define MAX_NAME_LENGTH 256

/**
 * Block structure representing both files and directories in the iNode filesystem
 *
 * This is a fixed-size structure that can be directly written to/read from disk.
 * Using fixed-size arrays instead of pointers for disk persistence.
 */
class Block {
public:
    // ====================== Data Members ======================

    // Name of the file or directory (fixed size for disk storage)
    char name[MAX_NAME_LENGTH];

    // Type identification
    bool isFile;                    // true if file, false if directory

    // Counters (for directories only)
    uint32_t files_n;              // Number of files in this directory
    uint32_t folders_n;            // Number of subdirectories in this directory

    // Position references (offsets in lockbox file)
    int64_t current;               // Position of this block in lockbox
    int64_t parent;                // Position of parent directory block

    // Directory-specific positions
    int64_t subdir_pos;            // Position of first subdirectory (for directories)

    // File-specific data
    int64_t data_pos;              // Position of actual file data (for files)
                                   // OR position of first file in directory (for directories)
    uint64_t size;                 // Size of file data in bytes (for files only)

    // Linked list pointers (for siblings in same directory)
    int64_t next;                  // Next sibling (file or directory)
    int64_t previous;              // Previous sibling

    // Tree depth
    uint32_t level;                // Depth in directory tree (root = 0)

    // Padding to ensure consistent size (optional, for alignment)
    char _padding[4];

    // ====================== Methods ======================

    Block();
    ~Block();

    // Reset all fields to default values
    void reset();

    // Set the name (with bounds checking)
    void setName(const char* newName);

    // Get the name
    const char* getName() const;

    // Check if this block represents a file
    bool isFileBlock() const;

    // Check if this block represents a directory
    bool isDirectoryBlock() const;

    // Copy from another block (deep copy)
    void copyFrom(const Block* other);

    // Print block information (for debugging)
    void print() const;

    // Validation
    bool isValid() const;

private:
    // Disable dynamic allocation for name to ensure fixed size
    // This makes the structure suitable for direct disk I/O
};

// Helper to calculate block size at compile time
static_assert(sizeof(Block) > 0, "Block must have non-zero size");

// Ensure Block is suitable for direct disk I/O (no virtual functions, no dynamic allocation)
static_assert(std::is_standard_layout<Block>::value, "Block must be standard layout for disk I/O");