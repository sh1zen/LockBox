# LockBox

**LockBox** is an encrypted file container that allows you to securely store files and directories in a single
password-protected file. It provides a virtual filesystem where all contents—including filenames, directory structures,
and file data—are encrypted using the SPHINX cipher.

## Features

- **Virtual Filesystem**: Organize files and folders in a tree structure like a regular filesystem
- **Strong Encryption**: Uses SPHINX, a modern wide-block cipher with configurable security levels (128-bit to 1024-bit)
- **Encrypted Metadata**: Filenames, directory names, timestamps, and file sizes are all encrypted
- **Interactive CLI**: Unix-like shell interface with tab completion and command history
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Memory Efficient**: Memory-mapped I/O for handling large files
- **Activity Logging**: Built-in encrypted operation log for audit trails
- **Defragmentation**: Reclaim space from deleted files without compromising security

## Quick Start

### Installation

#### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/LockBox.git
cd LockBox

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make -j$(nproc)

# Run tests (optional)
cmake -DBUILD_TESTS=ON ..
make LockBoxTests
./LockBoxTests
```

#### Requirements

- C++23 compatible compiler (GCC 12+, Clang 15+, MSVC 2022+)
- CMake 3.15 or higher
- 64-bit operating system

### Interactive Mode

Running LockBox without arguments opens the main menu:

```bash
./LockBox
```

```
+==========================================+
|          LOCKBOX - Main Menu             |
+==========================================+

  [1] Open LockBox
  [2] Create LockBox
  [3] Encrypt text
  [4] Decrypt text
  [0] Exit

>>
```

### Creating a LockBox

```bash
# Interactive mode - follow the prompts
./LockBox
# Select option [2] Create LockBox

# Or command-line mode
./LockBox /path/to/folder output.lb "yourpassword"
```

### Opening a LockBox

```bash
# Interactive mode
./LockBox
# Select option [1] Open LockBox

# Command-line extraction
./LockBox -e archive.lb /destination "yourpassword"
```

## Command Line Usage

### Basic Commands

```bash
# Create a LockBox from a folder
./LockBox /path/to/folder output.lb "mypassword"

# Extract entire LockBox
./LockBox -e archive.lb /destination "mypassword"

# Encrypt text (outputs hex)
./LockBox -c "secret text" "password"

# Decrypt text (hex input)
./LockBox -d "a1b2c3d4e5f6..." "password"

# Encrypt a file (raw binary output)
./LockBox -cf input.txt output.enc "password"

# Decrypt a file (raw binary output)
./LockBox -df output.enc decrypted.txt "password"

# Show help
./LockBox -h
```

### Command-Line Arguments Summary

| Arguments                     | Description                     |
|-------------------------------|---------------------------------|
| `<src> <lockbox> <pass>`      | Create LockBox from file/folder |
| `-e <lockbox> <dest> <pass>`  | Extract LockBox to destination  |
| `-c <text> <password>`        | Encrypt text to hex             |
| `-d <hex> <password>`         | Decrypt hex to text             |
| `-cf <input> <output> <pass>` | Encrypt file (raw output)       |
| `-df <input> <output> <pass>` | Decrypt file (raw output)       |
| `-h`                          | Show help                       |

## CLI Mode

Once a LockBox is opened, CLI mode provides a Unix-like shell interface:

```
lockbox:/$ ls
  📁 documents/
  📁 images/
  📄 config.json (2.4 KB)
Total: 3 items

lockbox:/documents$ cat report.txt
This is the content of my encrypted file...

lockbox:/documents$ cd ..
lockbox:/$ tree
/
├── 📁 documents/
│   ├── 📄 report.txt
│   └── 📄 notes.txt
├── 📁 images/
│   └── 📄 photo.jpg
└── 📄 config.json

lockbox:/$ exit
```

### Available Commands

| Command   | Syntax                    | Description               |
|-----------|---------------------------|---------------------------|
| `ls`      | `ls [path]`               | List directory contents   |
| `cd`      | `cd <path>`               | Change directory          |
| `pwd`     | `pwd`                     | Print working directory   |
| `cat`     | `cat <file>`              | Display file contents     |
| `mkdir`   | `mkdir <path>`            | Create directory          |
| `rm`      | `rm <path>`               | Remove file/directory     |
| `mv`      | `mv <src> <dst>`          | Move or rename            |
| `cp`      | `cp <src> <dst>`          | Copy file/directory       |
| `rename`  | `rename <path> <newname>` | Rename item               |
| `find`    | `find <pattern>`          | Search by name            |
| `tree`    | `tree [path]`             | Display tree structure    |
| `add`     | `add <file> [path]`       | Import from filesystem    |
| `extract` | `extract [src] <dst>`     | Export to filesystem      |
| `info`    | `info <path>`             | Show detailed information |
| `limit`   | `limit [n]`               | Set max items displayed   |
| `clear`   | `clear`                   | Clear screen              |
| `help`    | `help [cmd]`              | Show help                 |
| `exit`    | `exit`                    | Return to menu            |

### Interactive Features

- **Tab Completion**: Press TAB to auto-complete paths
- **Command History**: Use UP/DOWN arrows to navigate previous commands
- **Path Navigation**: Supports `.` (current), `..` (parent), and absolute `/` paths
- **Quotes**: Use quotes for paths with spaces: `"my folder/file.txt"`

## Management Menu

After opening a LockBox, the management menu provides:

| Option          | Function                                              |
|-----------------|-------------------------------------------------------|
| **Extract**     | Export all or part of the contents to the filesystem  |
| **CLI Mode**    | Access the interactive shell for file operations      |
| **Search**      | Search files by name pattern                          |
| **Defragment**  | Compact the file, reclaiming space from deleted items |
| **View Log**    | Display encrypted operation log                       |
| **Clear Log**   | Clear the activity log                                |
| **Save & Exit** | Save changes and exit                                 |

### Defragmentation

Over time, deleting files leaves unused space in the container. Defragmentation:

- Removes gaps from deleted files
- Rewrites all pointers securely
- Truncates file to minimum size
- **Note**: Creates temporary memory overhead during operation

### Activity Log

LockBox maintains an encrypted log of operations:

- File additions, deletions, modifications
- Directory creation and removal
- Import/export operations
- Timestamps for each action

## Security

### Password Recommendations

1. **Minimum 16 characters** (20+ recommended)
2. **Mix character types**: uppercase, lowercase, numbers, symbols
3. **Avoid dictionary words** or personal information
4. **Use a password manager** to generate and store strong passwords
5. **Never share passwords** over unencrypted channels

### Encryption Details

LockBox uses the **SPHINX cipher**, a modern wide-block encryption algorithm:

- **Configurable security**: 128-bit to 1024-bit key strength
- **Wide-block design**: Encrypts multiple blocks together for better security
- **Side-channel resistant**: No table lookups, constant-time operations
- **Quantum-resistant**: 1024-bit mode available for post-quantum security

Default configuration provides **256-bit security** (16 blocks × 16-bit words).

### What Gets Encrypted

✅ File contents  
✅ File names  
✅ Directory names  
✅ Directory structure (via encrypted pointers)  
✅ Timestamps  
✅ Activity log

The only unencrypted data is the raw container file size (which reveals approximate storage usage).

## Architecture Overview

LockBox consists of three main layers:

```
┌─────────────────────────────────────┐
│         APPLICATION LAYER           │
│    (Interactive UI, CLI Parser)     │
├─────────────────────────────────────┤
│      VIRTUAL FILESYSTEM (iNode)     │
│   (Tree structure, file operations) │
├─────────────────────────────────────┤
│      ENCRYPTION ENGINE (OpenES)     │
│      (SPHINX cipher, key mgmt)      │
├─────────────────────────────────────┤
│      PLATFORM ABSTRACTION LAYER     │
│   (File I/O, memory mapping)        │
└─────────────────────────────────────┘
```

For detailed technical documentation, see [`doc/architecture.md`](doc/architecture.md).

## Best Practices

### Creating Secure LockBoxes

1. **Use strong, unique passwords** for each LockBox
2. **Keep backups** of your LockBox file in multiple locations
3. **Verify extraction** before deleting original files
4. **Run defragment periodically** to reclaim space
5. **Use CLI mode** for batch operations (faster than individual commands)

### Managing Large Archives

1. **Create directories first**, then add files
2. **Use bulk add** for importing folders (more efficient)
3. **Run defragment** after major deletions
4. **Consider splitting** very large archives (>10GB)

### Security Hygiene

1. **Clear shell history** after using command-line passwords:
   ```bash
   history -c  # Bash
   Clear-History  # PowerShell
   ```
2. **Use interactive mode** when possible (password not in shell history)
3. **Secure erase** deleted LockBox files (use `shred` on Linux)
4. **Never reuse passwords** across different LockBoxes

## Troubleshooting

### Common Issues

**"Failed to open LockBox"**

- Wrong password
- Corrupted file
- Insufficient permissions

**"Out of memory" during defragment**

- Large archives need ~2x memory during defrag
- Try extracting and recreating the LockBox instead

**"Permission denied"**

- Check file permissions on the LockBox file
- Ensure write access to destination directory

**Slow performance**

- Enable release build (`-O3` optimizations)
- Consider defragmenting to improve locality
- Large files may be slower due to encryption overhead

### Building Issues

**CMake version too old**

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install cmake

# macOS
brew install cmake
```

**Compiler doesn't support C++23**

- GCC 12+ required
- Clang 15+ required
- MSVC 2022+ required

### Getting Help

1. Check [`doc/architecture.md`](doc/architecture.md) for technical details
2. Review [`doc/oes.md`](doc/oes.md) for SPHINX cipher specification
3. Run tests: `./LockBoxTests` (if built with `-DBUILD_TESTS=ON`)

## Security Considerations

### Threats Addressed

| Threat                  | Mitigation                              |
|-------------------------|-----------------------------------------|
| Unauthorized access     | Strong encryption, password required    |
| Known-plaintext attacks | Wide-block cipher with full diffusion   |
| Side-channel attacks    | Constant-time operations, no lookups    |
| Memory dumps            | Secure zeroing of keys                  |
| File carving            | No predictable headers or magic numbers |

### Limitations

- **Brute force**: Short passwords can be cracked
- **Memory exposure**: Keys exist in memory while open
- **Container size**: File size reveals approximate content size
- **No integrity check**: Malicious modification possible (will decrypt to garbage)

## Performance

Typical performance on modern hardware:

| Operation    | Speed                 |
|--------------|-----------------------|
| Encryption   | ~50-100 MB/s          |
| Decryption   | ~50-100 MB/s          |
| File listing | <100ms for 1000 files |
| Defragment   | ~10-20 MB/s           |

*Actual performance depends on hardware, block size configuration, and data patterns.*

## Contributing

Contributions are welcome! Areas for improvement:

- Compression layer (before encryption)
- Public key support for key exchange
- Multi-threaded encryption
- Additional cipher algorithms
- GUI frontend

See source code documentation in [`doc/architecture.md`](doc/architecture.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- SPHINX cipher design inspired by Threefish, ChaCha, and AES
- Memory mapping abstraction uses platform-native APIs
- Uses standard cryptographic primitives where applicable

---

**Note**: This software is provided as-is without warranty. Always maintain backups of important data.
