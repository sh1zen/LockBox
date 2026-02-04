# LockBox Architecture Documentation

## Overview

LockBox is an encrypted file container application that provides a virtual filesystem within a single password-protected
file. It combines a custom encryption engine (OpenES) with a tree-based virtual filesystem (iNode) to securely store
files and directories.

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           APPLICATION LAYER                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐   │
│  │   Interactive   │  │   CLI Parser    │  │   Command Dispatcher        │   │
│  │   UI/Main Menu  │  │   (argc/argv)   │  │   (ls, cd, cat, etc.)       │   │
│  └────────┬────────┘  └────────┬────────┘  └─────────────┬───────────────┘   │
│           │                    │                         │                   │
│           └────────────────────┴─────────────────────────┘                   │
│                                      │                                       │
│                              main.cpp (Main Entry)                           │
└──────────────────────────────────────┼───────────────────────────────────────┘
                                       │
                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                        VIRTUAL FILESYSTEM LAYER (iNode/)                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────────────────────┐  │
│  │     iNode       │  │      Block      │  │        inode_raw              │  │
│  │  (Tree Manager) │◄─┤  (Data Unit)    │◄─┤   (Memory-Mapped I/O)         │  │
│  │                 │  │                 │  │                               │  │
│  │ • addFile()     │  │ • File/Dir data │  │ • File mapping                │  │
│  │ • addDir()      │  │ • Encrypted     │  │ • Page allocation             │  │
│  │ • remove()      │  │   names         │  │ • Defragmentation             │  │
│  │ • readFile()    │  │ • Tree pointers │  │ • Raw I/O                     │  │
│  │ • listDir()     │  │ • Timestamps    │  │ • Block I/O                   │  │
│  └────────┬────────┘  └────────┬────────┘  └─────────────┬─────────────────┘  │
│           │                    │                         │                    │
│           └────────────────────┴─────────────────────────┘                    │
│                                       │                                       │
│                    Tree Structure:    ▼                                       │
│                    ┌─────────┐                                                │
│                    │  Root   │──┐                                             │
│                    │ Block 0 │  │                                             │
│                    └────┬────┘  │                                             │
│                         │child │                                              │
│                    ┌────▼────┐  │ sibling                                     │
│                    │ Dir A   │◄─┘                                             │
│                    │ Block 1 │                                                │
│                    └────┬────┘                                                │
│                         │                                                     │
│                    ┌────▼────┐                                                │
│                    │ File B  │                                                │
│                    │ Block 2 │                                                │
│                    └─────────┘                                                │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      ENCRYPTION LAYER (OpenES/)                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                           OES (Engine)                                │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐ │  │
│  │  │   enc_*()   │  │   dec_*()   │  │    hash()   │  │     hmac()    │ │  │
│  │  │  ECB/CBC/   │  │  ECB/CBC/   │  │             │  │               │ │  │
│  │  │ CTR/CKE/    │  │ CTR/CKE/    │  │             │  │               │ │  │
│  │  │ adv (SPHINX)│  │ adv (SPHINX)│  │             │  │               │ │  │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬──────┘ │  │
│  │         └────────────────┴────────────────┴──────────────────┘        │  │
│  │                                    │                                  │  │
│  │  ┌─────────────────────────────────▼────────────────────────────────┐ │  │
│  │  │                    SPHINX Cipher v3.1                            │ │  │
│  │  │  • Wide-block cipher (1-16 blocks configurable)                  │ │  │
│  │  │  • Key Addition → Wide S-box → Algebraic S-box → Diffusion       │ │  │
│  │  │  • PHT → Round Constants                                         │ │  │
│  │  └──────────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      Data Block Layer (layer/)                        │  │
│  │                                                                       │  │
│  │   ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐   │  │
│  │   │   MBLOCK    │      │   m_block   │      │      defines.h      │   │  │
│  │   │  (Class)    │      │  (Type)     │      │  (Compile-time      │   │  │
│  │   │             │      │  uint8-128  │      │   configuration)    │   │  │
│  │   │ • Memory    │      │             │      │                     │   │  │
│  │   │   management│      │ • Rotations │      │ • Block sizes       │   │  │
│  │   │ • Padding   │      │ • Byte ops  │      │ • Type definitions  │   │  │
│  │   │ • XOR ops   │      │             │      │ • Constants         │   │  │
│  │   └─────────────┘      └─────────────┘      └─────────────────────┘   │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Supporting Algorithms (algo/)                      │  │
│  │                                                                       │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │   │  hashing    │  │  key_mgmt   │  │    PRNG     │  │block_ciphers│  │  │
│  │   │             │  │             │  │             │  │             │  │  │
│  │   │ • SHA-256   │  │ • Key exp.  │  │ • CSPRNG    │  │ • AES       │  │  │
│  │   │ • SHA-512   │  │ • PBKDF-like│  │ • SplitMix  │  │ • ChaCha    │  │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PLATFORM ABSTRACTION LAYER                             │
│  ┌─────────────────────────────┐  ┌─────────────────────────────────────┐   │
│  │     filesystem.cpp/.h       │  │           mman.cpp/.h               │   │
│  │                             │  │                                     │   │
│  │  Cross-platform file I/O:   │  │  Memory-mapped file abstraction:    │   │
│  │  • read/write files         │  │  • Windows: CreateFileMapping       │   │
│  │  • directory operations     │  │  • POSIX: mmap/munmap               │   │
│  │  • path manipulation        │  │  • Page-aligned allocation          │   │
│  └─────────────────────────────┘  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Application Layer

**File:** [`main.cpp`](main.cpp)

The entry point providing multiple interfaces:

- **Interactive Mode**: Menu-driven UI for creating/opening LockBoxes
- **CLI Mode**: Command-line arguments for batch operations
- **Shell Mode**: Unix-like command interface (`ls`, `cd`, `cat`, etc.)

Key classes:

| Class                               | Line    | Description                                           |
|-------------------------------------|---------|-------------------------------------------------------|
| [`ColorSupport`](main.cpp:26)       | 26-77   | Terminal color management with cross-platform support |
| [`ProgressTracker`](main.cpp:208)   | 208-243 | Progress bar display with ETA calculation             |
| [`CommandHistory`](main.cpp:312)    | 312-343 | Command history navigation (up/down arrows)           |
| [`LineEditor`](main.cpp:347)        | 347-539 | Command-line editing with tab completion              |
| [`PreCalculatedBatch`](main.cpp:89) | 89-103  | Batch file processing metadata                        |

CLI Commands:
| Command | Arguments | Description |
|---------|-----------|-------------|
| `ls` | `[path]` | List directory contents |
| `cd` | `<path>` | Change current directory |
| `pwd` | - | Print working directory |
| `cat` | `<file>` | Display file contents |
| `rm` | `<path>` | Remove file or directory |
| `mkdir` | `<path>` | Create directory |
| `mv` | `<src> <dst>` | Move/rename |
| `cp` | `<src> <dst>` | Copy file/directory |
| `rename` | `<path> <name>` | Rename file/directory |
| `find` | `<pattern>` | Search for files |
| `tree` | `[path]` | Display directory tree |
| `extract` | `[src] <dst>` | Export files to filesystem |
| `add` | `<file> [path]` | Add files from filesystem |
| `info` | `<path>` | Show file/directory details |
| `limit` | `[n]` | Set list display limit |
| `clear` | - | Clear screen |
| `help` | `[cmd]` | Show help |
| `exit` | - | Exit CLI mode |

Command-line arguments:

```
<src> <lockbox> <pass>      Create lockbox from source
-e <lockbox> <dest> <pass>  Extract lockbox to destination
-c <text> <password>        Encrypt text
-d <hex> <password>         Decrypt hex ciphertext
-cf <in> <out> <pass>       Encrypt file (raw)
-df <in> <out> <pass>       Decrypt file (raw)
-h                          Show help
```

### 2. Virtual Filesystem Layer (iNode/)

#### 2.1 iNode - Tree Manager

**Files:** [`iNode/iNode.h`](iNode/iNode.h), [`iNode/iNode.cpp`](iNode/iNode.cpp)

The main filesystem interface managing a tree of [`Block`](iNode/Block.h) objects.

Key responsibilities:

- File/directory CRUD operations
- Path resolution and navigation
- Tree traversal (walk callbacks)
- Import/export to host filesystem
- Encrypted activity logging
- Bulk update optimization

Key methods:

| Method                                   | Description                                    |
|------------------------------------------|------------------------------------------------|
| [`addFile()`](iNode/iNode.h:53)          | Add or overwrite a file (supports empty files) |
| [`addDirectory()`](iNode/iNode.h:55)     | Create directory chain                         |
| [`remove()`](iNode/iNode.h:63)           | Remove file or recursive directory             |
| [`readFile()`](iNode/iNode.h:65)         | Read and decrypt file content                  |
| [`updateFile()`](iNode/iNode.h:67)       | Update existing file content                   |
| [`move()`](iNode/iNode.h:73)             | Move/rename files or directories               |
| [`copy()`](iNode/iNode.h:75)             | Copy files or directories recursively          |
| [`exists()`](iNode/iNode.h:69)           | Check if path exists                           |
| [`listDirectory()`](iNode/iNode.h:87)    | List directory entries                         |
| [`search()`](iNode/iNode.h:89)           | Search files by name pattern                   |
| [`walk()`](iNode/iNode.h:99)             | Tree traversal with callback                   |
| [`exportTo()`](iNode/iNode.h:121)        | Export to host filesystem                      |
| [`beginBulkUpdate()`](iNode/iNode.h:124) | Start batch operation mode                     |
| [`endBulkUpdate()`](iNode/iNode.h:126)   | End batch mode, flush changes                  |
| [`defragment()`](iNode/iNode.h:143)      | Compact storage, reclaim space                 |
| [`getLog()`](iNode/iNode.h:132)          | Get encrypted activity log                     |
| [`clearLog()`](iNode/iNode.h:134)        | Clear activity log                             |

Types:

| Type         | Description                                                         |
|--------------|---------------------------------------------------------------------|
| DirEntry     | Directory entry with encrypted/decrypted names, type, and size      |
| Stats        | Container statistics (total size, used/free space, file/dir counts) |
| WalkCallback | Callback function for tree traversal                                |

#### 2.2 Block - Storage Unit

**Files:** [`iNode/Block.h`](iNode/Block.h), [`iNode/Block.cpp`](iNode/Block.cpp)

Represents a single file or directory in the virtual filesystem. Supports both inline and external name storage.

Structure:

- **Name storage**: Hybrid approach with inline buffer (up to 256 bytes) or external storage for long names
- **Type and hierarchy**: File/directory flag, depth level in tree
- **Tree pointers**: Links to parent, siblings, children
- **Directory-specific**: File/subdirectory counts, pointers to first entries
- **File-specific**: Encrypted data size and position
- **Timestamps**: Creation, modification, and access times (Unix epoch)
- **Reserved space**: 32 bytes for future extensions

Key methods:

| Method                                   | Description                       |
|------------------------------------------|-----------------------------------|
| [`setName()`](iNode/Block.h:75)          | Set and encrypt name              |
| [`getPlainName()`](iNode/Block.h:79)     | Get decrypted name                |
| [`getStoredName()`](iNode/Block.h:81)    | Get encrypted name                |
| [`nameEquals()`](iNode/Block.h:85)       | Compare with plaintext name       |
| [`setCreatedNow()`](iNode/Block.h:94)    | Set creation timestamp            |
| [`setModifiedNow()`](iNode/Block.h:96)   | Set modification timestamp        |
| [`setAccessedNow()`](iNode/Block.h:98)   | Set access timestamp              |
| [`isNameInline()`](iNode/Block.h:89)     | Check if name uses inline storage |
| [`isValid()`](iNode/Block.h:117)         | Validate block structure          |
| [`isLeaf()`](iNode/Block.h:126)          | Check if node has no children     |
| [`hasChildren()`](iNode/Block.h:128)     | Check if directory has entries    |
| [`linkAfter()`](iNode/Block.h:135)       | Link after another block          |
| [`unlink()`](iNode/Block.h:139)          | Remove from linked list           |
| [`clone()`](iNode/Block.h:145)           | Create deep copy                  |
| [`createFile()`](iNode/Block.h:147)      | Factory for file blocks           |
| [`createDirectory()`](iNode/Block.h:151) | Factory for directory blocks      |
| [`createRoot()`](iNode/Block.h:154)      | Factory for root block            |

Static configuration methods:

- `setCipherEngine()`: Set encryption engine for name encryption
- `setNameResolver()`: Set external name reader callback
- `setNameWriter()`: Set external name writer callback

#### 2.3 inode_raw - Physical Storage

**Files:** [`iNode/inode_raw.h`](iNode/inode_raw.h), [`iNode/inode_raw.cpp`](iNode/inode_raw.cpp)

Manages memory-mapped file I/O for the container with page-aligned allocation.

Features:

- 4KB page-aligned allocation
- Transparent memory mapping via [`mman.cpp`](mman.cpp)
- Defragmentation support with full pointer rewriting
- Atomic write operations
- Deferred sync for bulk operations

Key members:

- File descriptor and path
- Memory-mapped pointer and sizes
- Logical and allocated file sizes
- Dirty/modified flag

Key methods:

| Method                                  | Description             |
|-----------------------------------------|-------------------------|
| [`open()`](iNode/inode_raw.h:24)        | Open existing container |
| [`create()`](iNode/inode_raw.h:26)      | Create new container    |
| [`allocate()`](iNode/inode_raw.h:34)    | Allocate space at end   |
| [`reallocate()`](iNode/inode_raw.h:37)  | Reallocate data block   |
| [`defragment()`](iNode/inode_raw.h:41)  | Compact storage file    |
| [`write()`](iNode/inode_raw.h:44)       | Write raw data          |
| [`read()`](iNode/inode_raw.h:46)        | Read raw data           |
| [`ptr()`](iNode/inode_raw.h:48)         | Get pointer to offset   |
| [`readBlock()`](iNode/inode_raw.h:53)   | Read Block structure    |
| [`writeBlock()`](iNode/inode_raw.h:55)  | Write Block structure   |
| [`appendBlock()`](iNode/inode_raw.h:57) | Append Block to file    |
| [`sync()`](iNode/inode_raw.h:60)        | Flush to disk           |

Defragmentation process:

1. BFS traversal to find all reachable blocks
2. Collect blocks, file data, and external names
3. Calculate new compact layout
4. Update all internal pointers
5. Write new image to file
6. Truncate to new size

### 3. Encryption Layer (OpenES/)

#### 3.1 OES - Encryption Engine

**Files:** [`OpenES/OES.h`](OpenES/OES.h), [`OpenES/OES.cpp`](OpenES/OES.cpp)

Main interface for all cryptographic operations with secure memory management.

Key components:

- **oKey**: Original key from password
- **wKey**: Working/expanded key for encryption
- **plainBlock**: Input plaintext data
- **cipherBlock**: Output ciphertext data
- **IV**: Initialization vector for modes that require it
- **Stream state**: Counter, chain data, session for streaming modes

Supported modes:

| Mode | Method                         | Description                          |
|------|--------------------------------|--------------------------------------|
| ECB  | [`enc_ecb()`](OpenES/OES.h:72) | Electronic Codebook (deterministic)  |
| CBC  | [`enc_cbc()`](OpenES/OES.h:76) | Cipher Block Chaining                |
| CTR  | [`enc_ctr()`](OpenES/OES.h:80) | Counter mode (streaming)             |
| CKE  | [`enc_cke()`](OpenES/OES.h:84) | Custom CKE mode with stream chaining |
| ADV  | [`enc_adv()`](OpenES/OES.h:88) | SPHINX cipher (recommended, default) |

Key management:

| Method                                  | Description                  |
|-----------------------------------------|------------------------------|
| [`set_key()`](OpenES/OES.cpp:457)       | Set password from string     |
| [`deriveWKey()`](OpenES/OES.h:39)       | Derive working key with salt |
| [`extendWKey()`](OpenES/OES.h:41)       | PBKDF-like key expansion     |
| [`resetBlocks()`](OpenES/OES.h:58)      | Securely clear data blocks   |
| [`resetStreamState()`](OpenES/OES.h:60) | Reset streaming state        |

Data operations:

| Method                                      | Description                          |
|---------------------------------------------|--------------------------------------|
| [`load_data_raw()`](OpenES/OES.h:44)        | Load plaintext data                  |
| [`load_cipher_data_raw()`](OpenES/OES.h:46) | Load ciphertext data                 |
| [`load_cipher_block()`](OpenES/OES.h:48)    | Load existing MBLOCK                 |
| [`get_data()`](OpenES/OES.h:50)             | Get plaintext (with padding removed) |
| [`get_cipher_data()`](OpenES/OES.h:52)      | Get ciphertext                       |
| [`get_cipher_data_raw()`](OpenES/OES.h:56)  | Get raw ciphertext bytes             |
| [`get_cipherBlock()`](OpenES/OES.h:98)      | Clone cipher block                   |
| [`get_plainBlock()`](OpenES/OES.h:102)      | Clone plaintext block                |

#### 3.2 SPHINX Cipher

**Files:** [`OpenES/algo/sphinix.h`](OpenES/algo/sphinix.h), [`OpenES/algo/sphinix.cpp`](OpenES/algo/sphinix.cpp)

Custom wide-block cipher designed for high security with configurable block sizes.

Features:

- **Configurable width**: 1-16 blocks (default 16)
- **Block sizes**: 8-128 bits per block (configurable at compile time)
- **Security**: Scales with block count (N × block_size bits)
- **Quantum resistance**: Up to 1024-bit keys with 128-bit blocks
- **Side-channel resistant**: No table lookups, constant-time operations

Security levels:

| Block Size | Max Key Size | Security Level     |
|------------|--------------|--------------------|
| 8-bit      | 64-bit       | Basic              |
| 16-bit     | 128-bit      | AES-128 equivalent |
| 32-bit     | 256-bit      | AES-256 equivalent |
| 64-bit     | 512-bit      | Post-quantum ready |
| 128-bit    | 1024-bit     | Quantum-safe       |

Round structure:

```
Plaintext → [Key Addition] → [Wide S-box (Feistel)] → [Algebraic S-box]
          → [Diffusion Layer] → [PHT] → [Round Constants] → Ciphertext
```

Public interface (namespace SPHINX):

- `encrypt()`: Basic encryption with plaintext and key
- `decrypt()`: Basic decryption with ciphertext and key
- `create_context()`: Create reusable context for repeated operations
- `encrypt_with_context()`: Encrypt using pre-computed context
- `decrypt_with_context()`: Decrypt using pre-computed context

#### 3.3 MBLOCK - Core Data Structure

**Files:** [`OpenES/layer/m_block.h`](OpenES/layer/m_block.h), [`OpenES/layer/m_block.cpp`](OpenES/layer/m_block.cpp)

Memory block class managing cryptographic data with secure memory handling.

Key components:

- Data array pointer
- Number of blocks

Operations:

- XOR operations with other blocks
- Rotations (left/right)
- Padding (PKCS-like)
- Secure zeroing

The underlying type is configured at compile-time:

| Config  | Type          | Use Case         |
|---------|---------------|------------------|
| 8-bit   | `uint8_t`     | Embedded systems |
| 16-bit  | `uint16_t`    | Low memory       |
| 32-bit  | `uint32_t`    | General purpose  |
| 64-bit  | `uint64_t`    | High performance |
| 128-bit | `__uint128_t` | Maximum security |

Key methods:

| Method                                                   | Description                      |
|----------------------------------------------------------|----------------------------------|
| [`fromBytes()`](OpenES/layer/m_block.h:204)              | Create from bytes (with padding) |
| [`fromBytes_raw()`](OpenES/layer/m_block.h:207)          | Create from bytes (no padding)   |
| [`toBytes()`](OpenES/layer/m_block.h:212)                | Export to bytes (strip padding)  |
| [`toBytes_raw()`](OpenES/layer/m_block.h:209)            | Export raw bytes                 |
| [`clone()`](OpenES/layer/m_block.h:92)                   | Deep copy                        |
| [`secure_zero()`](OpenES/layer/m_block.h:145)            | Secure memory wipe               |
| [`xor_with()`](OpenES/layer/m_block.h:167)               | XOR with another block           |
| [`rotr()`](OpenES/layer/m_block.h:173)                   | Rotate right                     |
| [`rotl()`](OpenES/layer/m_block.h:175)                   | Rotate left                      |
| [`extend()`](OpenES/layer/m_block.h:143)                 | Resize with fill value           |
| [`add_padding_outer()`](OpenES/layer/m_block.h:187)      | Add PKCS-like padding            |
| [`get_padding_size_outer()`](OpenES/layer/m_block.h:189) | Calculate padding size           |
| [`dump()`](OpenES/layer/m_block.h:218)                   | Debug output                     |

#### 3.4 Configuration (defines.h)

**File:** [`OpenES/layer/defines.h`](OpenES/layer/defines.h)

Compile-time configuration:

| Constant               | Default | Description                              |
|------------------------|---------|------------------------------------------|
| `OES_NUM_OF_BLOCKS`    | 16      | Number of parallel blocks (must be even) |
| `OES_LOGIC_BLOCK_SIZE` | 128     | Bits per block (8-128, multiple of 8)    |
| `OES_MEM_SIZE`         | 128     | Derived memory size                      |

Derived constants:

- `OES_BYTES_X_BLOCK`: Bytes per block (MEM_SIZE / 8)

Data types (configured based on block size):

- 8-bit to 128-bit unsigned integers
- Size type

Export format constants:

- `OES_TYPE_RAW_UINT8`: Raw binary
- `OES_TYPE_MBLOCK`: Internal format
- `OES_TYPE_UINT8`: Byte array
- `OES_TYPE_HEX`: Hexadecimal string
- `OES_TYPE_CHAR`: Character string
- `OES_EXPORT_BASE64`: Base64 encoded

#### 3.5 Interface Layer

**File:** [`OpenES/layer/interface.h`](OpenES/layer/interface.h)

High-level import/export functions:

- `toOESBlock()`: Convert raw bytes to MBLOCK
- `exportBlock()`: Export MBLOCK to specified format
- `importBlock()`: Import from specified format to MBLOCK

### 4. Platform Abstraction Layer

#### 4.1 Filesystem

**Files:** [`filesystem.h`](filesystem.h), [`filesystem.cpp`](filesystem.cpp)

Cross-platform file operations supporting Windows and POSIX systems.

Directory entry structure:

- Name
- Directory flag
- Size

File I/O operations:

- Read file (returns size and buffer)
- Write file
- Append to file

Path operations:

- Get current directory
- Get parent directory
- Get filename, basename, extension
- Join and normalize paths

File/Directory checks:

- Existence check
- File vs directory check
- Get file size

Directory operations:

- Create directory (with recursive option)
- Remove file
- Remove directory (with recursive option)
- List directory contents

Utilities:

- Fix path separators
- Convert to absolute path

#### 4.2 Memory Mapping

**Files:** [`mman.h`](mman.h), [`mman.cpp`](mman.cpp)

Abstracts platform-specific memory-mapped file APIs:

- **Windows**: `CreateFileMapping` / `MapViewOfFile`
- **POSIX**: `mmap` / `munmap`

Protection modes:

- Read
- Write
- ReadWrite

Map flags:

- Private
- Shared

Map result contains:

- Pointer to mapped memory
- Size of mapping
- Success status

Operations:

- `map()`: Create memory mapping
- `unmap()`: Remove memory mapping
- `sync()`: Synchronize with disk

## Data Flow

### Encryption Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Plaintext   │────►│   MBLOCK     │────►│    SPHINX    │────►│   MBLOCK     │
│   (bytes)    │     │  (blocks)    │     │   encrypt()  │     │ (encrypted)  │
└──────────────┘     └──────────────┘     └──────────────┘     └──────┬───────┘
                                                                       │
                                                                       ▼
                                                                ┌──────────────┐
                                                                │  Ciphertext  │
                                                                │   (bytes)    │
                                                                └──────────────┘
```

### File Storage Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  User File   │────►│  Encryption  │────►│    Block     │────►│  inode_raw   │
│   (host FS)  │     │    (OES)     │     │  (metadata + │     │  (mmapped)   │
└──────────────┘     └──────────────┘     │ encrypted    │     └──────────────┘
                                          │   data)      │            │
                                          └──────────────┘            │
                                                                       ▼
                                                                ┌──────────────┐
                                                                │  LockBox     │
                                                                │   (.lb file) │
                                                                └──────────────┘
```

### Container File Format

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LockBox File (.lb)                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ Offset 0                                                                    │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                           Block 0 (Root Directory)                      │ │
│ │  ┌─────────────┬─────────────┬─────────────┬──────────────────────────┐ │ │
│ │  │  Metadata   │  Encrypted  │   Parent    │   Next/Prev/Child ptrs   │ │ │
│ │  │  (headers)  │   name      │   offset    │   (8 bytes each)         │ │ │
│ │  └─────────────┴─────────────┴─────────────┴──────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Offset N                                                                    │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                        Block 1..N (Files/Directories)                   │ │
│ │  ┌─────────────┬─────────────┬────────────────────────────────────────┐ │ │
│ │  │  Metadata   │  Encrypted  │      Encrypted file data (if file)     │ │ │
│ │  │             │   name      │      or subdirectory blocks (if dir)   │ │ │
│ │  └─────────────┴─────────────┴────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ ... additional blocks ...                                                   │
│                                                                             │
│ After defragmentation:                                                      │
│ [Blocks Section][Padding][File Data Section][Padding][External Names]       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Architecture

### Key Derivation

```
User Password ──► MBLOCK.fromBytes() ──► oKey (original key)
                                               │
                                               ▼
                                         extendWKey()
                                               │
                                               ▼
                                         wKey (working key)
                                               │
                                               ▼
                                         SPHINX encrypt/decrypt
```

Key expansion process:

1. Password converted to MBLOCK (oKey)
2. oKey cloned to wKey
3. wKey expanded via PBKDF-like iterative hashing
4. Expansion strength configurable (default: 16 rounds)
5. Salt derived from golden ratio constant

### Encryption Chain

1. **Name encryption**: Every filename encrypted with SPHINX
2. **Data encryption**: File contents encrypted with SPHINX cipher
3. **No plaintext metadata**: All metadata encrypted (sizes stored as encrypted data length)
4. **Tree obfuscation**: Block positions reveal no structural information
5. **Activity logging**: Operations logged to encrypted `.lockbox_log` file

### Threat Model

| Threat            | Mitigation                                          |
|-------------------|-----------------------------------------------------|
| Password guessing | Configurable key expansion (default: 16 iterations) |
| Known-plaintext   | Wide-block SPHINX cipher with full diffusion        |
| Side-channel      | Constant-time operations, no table lookups          |
| Quantum computing | Support for 1024-bit keys (128-bit blocks)          |
| File carving      | No magic numbers or predictable headers             |
| Memory dumps      | Secure zeroing of keys after use                    |
| Timing attacks    | Page-aligned memory, constant-time comparison       |

## Build Configuration

**File:** [`CMakeLists.txt`](CMakeLists.txt)

### Options

| Option        | Default | Description                |
|---------------|---------|----------------------------|
| `BUILD_APP`   | ON      | Build the main application |
| `BUILD_TESTS` | OFF     | Build the test suite       |

### Compiler Requirements

- C++23 standard required
- Release optimizations: `-O3 -march=native -funroll-loops`
- Static linking on Windows

### Source Organization

Common sources (library core):

- Memory mapping (mman)
- Filesystem abstraction
- Base64 encoding
- OES engine and layers
- Block ciphers and hashing
- Support utilities
- iNode filesystem components

Application sources:

- Main entry point

Test sources:

- Test framework
- OES tests
- PRNG tests

### Include Directories

- Root directory
- OpenES and subdirectories
- iNode directory

## Testing

**Directory:** [`test/`](test/)

| File                                  | Description                                   |
|---------------------------------------|-----------------------------------------------|
| [`oes_tests.cpp`](test/oes_tests.cpp) | Encryption/decryption correctness tests       |
| [`prngtest.cpp`](test/prngtest.cpp)   | Statistical randomness tests (NIST SP 800-22) |
| [`prngtest.h`](test/prngtest.h)       | PRNG test headers                             |
| [`tester.h`](test/tester.h)           | Test framework utilities                      |

Build tests:

```bash
cmake -DBUILD_TESTS=ON ..
make LockBoxTests
```

## Performance Considerations

### Optimizations

1. **Memory-mapped I/O**: Zero-copy access via mmap
2. **Bulk updates**: Deferred sync for batch operations
3. **Page alignment**: 4KB allocation reduces fragmentation
4. **Configurable block sizes**: Tune for target hardware
5. **Context reuse**: SPHINX contexts for repeated operations

### Bottlenecks

| Operation       | Cost           | Mitigation               |
|-----------------|----------------|--------------------------|
| Encryption      | O(n) per block | Parallel SPHINX rounds   |
| Disk sync       | I/O bound      | Bulk mode, deferred sync |
| Tree traversal  | O(n)           | Iterative, not recursive |
| Path lookup     | O(depth)       | Cached root block        |
| Defragmentation | O(n log n)     | Background operation     |

## Future Considerations

### Extensibility Points

1. **Alternative ciphers**: Interface supports plugging in new algorithms
2. **Compression**: Could be added before encryption stage
3. **Authentication**: HMAC support already present in OES class
4. **Streaming**: Large file support via chunking
5. **Snapshots**: Copy-on-write for versioning

### Planned Features

- [ ] Asynchronous I/O for large files
- [ ] Compression layer (zlib/lz4)
- [ ] Public key encryption for key exchange
- [ ] Multi-threaded encryption
- [ ] Container format versioning
- [ ] Encrypted metadata caching

---

*Documentation generated from codebase analysis. Last updated: 2026-03-02*
