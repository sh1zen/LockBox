# LockBox

**LockBox** is an encrypted file container that allows you to securely store files and directories in a single password-protected file.

## Overview

LockBox works as an encrypted virtual filesystem: files and folders are organized in a tree structure, individually encrypted, and saved into a single container file. Only those with the correct password can access the contents.

```
┌─────────────────────────────────────────┐
│            LockBox File (.lb)           │
├─────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│  │ Block 0 │ │ Block 1 │ │ Block 2 │    │
│  │  (root) │ │  (dir)  │ │ (file)  │    │
│  └─────────┘ └─────────┘ └─────────┘    │
│         ↓         ↓           ↓         │
│   [encrypted] [encrypted] [encrypted]   │
└─────────────────────────────────────────┘
```

## Architecture

### Main Components

| Component | Description |
|-----------|-------------|
| **OES** | Encryption engine (OpenES) handling encrypt/decrypt operations |
| **iNode** | Manages the virtual filesystem and file/directory operations |
| **Block** | Base storage unit containing metadata and encrypted data |
| **inode_raw** | Physical storage layer for disk persistence |

### Block Structure

Each element (file or directory) is represented by a **Block** containing:

- **Encrypted name** of the file/directory
- **Type** (file or directory)
- **Size** of the data
- **Pointers** to parent, sibling, and child (for tree structure)
- **Encrypted data** (for files)

### Tree Structure

```
root (Block 0)
├── documents/
│   ├── report.pdf
│   └── notes.txt
├── images/
│   └── photo.jpg
└── config.json
```

Blocks are linked through pointers:
- **Parent**: parent block (containing directory)
- **Child**: first child (for directories)
- **Sibling**: next sibling (same level)

## Usage

### Interactive Mode

Running LockBox without arguments opens the main menu:

```
+==========================================+
|          LOCKBOX - Main Menu             |
+==========================================+

  [1] Open LockBox
  [2] Create LockBox
  [3] Encrypt text
  [4] Decrypt text
  [0] Exit
```

### Command Line Interface

```bash
# Create a LockBox from a folder
./lockbox /path/to/folder output.lb "mypassword"

# Extract a LockBox
./lockbox -e archive.lb /destination "mypassword"

# Encrypt text
./lockbox -c "secret text" "password"

# Decrypt text (hex)
./lockbox -d "a1b2c3..." "password"
```

## CLI Mode

Once a LockBox is opened, CLI mode provides a Unix-like shell interface:

```
lockbox:/$ ls
  📁 documents/
  📁 images/
  📄 config.json (2.4 KB)
Total: 3 items

lockbox:/$ cd documents
lockbox:/documents$ cat notes.txt
```

### Available Commands

| Command   | Syntax                | Description             |
|-----------|-----------------------|-------------------------|
| `ls`      | `ls [path]`           | List directory contents |
| `cd`      | `cd <path>`           | Change directory        |
| `pwd`     | `pwd`                 | Print working directory |
| `cat`     | `cat <file>`          | Display file contents   |
| `mkdir`   | `mkdir <path>`        | Create directory        |
| `rm`      | `rm <path>`           | Remove file/directory   |
| `mv`      | `mv <src> <dst>`      | Move/rename             |
| `cp`      | `cp <src> <dst>`      | Copy file/directory     |
| `rename`  | `rename <path> <n>`   | Rename                  |
| `find`    | `find <pattern>`      | Search by name          |
| `tree`    | `tree [path]`         | Display tree structure  |
| `add`     | `add <file> [path]`   | Import from filesystem  |
| `extract` | `extract [src] <dst>` | Export to filesystem    |
| `info`    | `info <path>`         | Detailed information    |
| `limit`   | `limit [n]`           | Max items displayed     |
| `clear`   | `clear`               | Clear screen            |
| `help`    | `help [cmd]`          | Show help               |
| `exit`    | `exit`                | Return to menu          |

### Advanced Features

- **Tab completion**: auto-complete paths with TAB
- **Command history**: navigate with UP/DOWN arrows
- **Relative/absolute paths**: support for `.`, `..`, `/path`

## Management Menu

The management menu provides access to:

| Option          | Function                           |
|-----------------|------------------------------------|
| **Extract**     | Export all or part of the contents |
| **CLI Mode**    | Access the interactive shell       |
| **Search**      | Search files by name               |
| **Defragment**  | Compact the file, reclaiming space |
| **View Log**    | Display operation log              |
| **Clear Log**   | Clear the log                      |
| **Save & Exit** | Save changes and exit              |

### Best Practices

1. Use passwords of at least 16 characters (20+ recommended)
2. Combine letters, numbers, and symbols
3. Always save after modifications (`Save & Exit`)
4. Run `defragment` periodically to reclaim space
5. Keep backups of your LockBox file

---

# SPHINX Cipher v3.1

LockBox uses **SPHINX**, a modern wide-block cipher designed for high security and flexibility.

## Architectural Overview

SPHINX is a **wide-block cipher** with configurable size from 1 to 16 blocks. The architecture combines modern design elements inspired by constructions like Threefish, ChaCha, and AES.

### Fundamental Parameters

| Parameter | Value |
|-----------|-------|
| Blocks | 1-16 (configurable) |
| Block size | 8-128 bits per block |
| Rounds | log₂(total bits) + corrections |
| Target security | N × block_size bits |

## Round Structure

Each encryption round applies in sequence:

```
Plaintext → [Key Addition] → [Wide S-box] → [Algebraic S-box] 
         → [Diffusion] → [PHT] → [Round Constant] → Ciphertext
```

### 1. Key Addition Layer
Direct XOR with the round subkey. Prevents direct analysis of internal state.

### 2. Wide S-box (Feistel Cross-Block)
Balanced Feistel structure creating **cross-block dependency**:
- State is split into left/right halves
- Each left block depends on ALL right blocks
- F function: accumulates contributions from all blocks + AES S-box byte-by-byte
- Fully invertible thanks to Feistel structure

**Key property**: Security scales with the number of blocks (N × size).

### 3. Algebraic S-box (8 Rounds)
Key-dependent non-linear transformation for each block:
- 8 rounds of mixing: rotations, XOR, modular multiplications
- Keys derived from master key with non-linear mixing
- High algebraic degree for resistance to algebraic attacks

### 4. Diffusion Layer
Combines three mechanisms:
- **Quarter-round** (ChaCha/ARX style): mixes groups of 4 blocks
- **Cross-group mixing**: diffusion between groups
- **Cross-half mixing**: for wide configurations (≥8 blocks)

### 5. Pseudo-Hadamard Transform (PHT)
Reversible non-linear transformation that increases local diffusion.

## Key Schedule

Based on **sponge construction**:

1. **Absorb**: Master key is absorbed into internal state
2. **Permute**: Iterative state mixing (8-12 rounds)
3. **Squeeze**: Extraction of subkeys for each round

Characteristics:
- Domain separation for different uses
- Forward security: compromise of one subkey doesn't reveal others
- Automatic expansion if key is shorter than wide-block

## Global Diffusion

Applied pre/post main rounds to guarantee complete avalanche:

```
Forward pass → Forward chain → Backward chain → Backward pass → Cross-half → Final pass
```

```
──────────────────────────────────────────────────────────────────────────────
                     SPHINX CIPHER v3.1 - ENCRYPTION FLOW
──────────────────────────────────────────────────────────────────────────────

     ┌────────────────────────────────────────────────────────────────┐
     │                        PLAINTEXT BLOCKS                        │
     │                  [P0] [P1] [P2] ... [Pn-1]                     │
     └───────────────────────────┬────────────────────────────────────┘
                                 │
     ┌───────────────────────────┴────────────────────────────────────┐
     │                                                                │
     │  ┌──────────────────────────────────────────────────────────┐  │
     │  │              MASTER KEY EXPANSION                        │  │
     │  │  ┌─────────┐    ┌──────────────┐    ┌────────────────┐   │  │
     │  │  │   KEY   │───>│   SPONGE     │───>│  ROUND KEYS    │   │  │
     │  │  └─────────┘    │  SCHEDULER   │    │  RK0...RKn+1   │   │  │
     │  │                 └──────────────┘    └────────────────┘   │  │
     │  └──────────────────────────────────────────────────────────┘  │
     │                                                                │
     └───────────────────────────┬────────────────────────────────────┘
                                 │
                                 v
     ┌────────────────────────────────────────────────────────────────┐
     │               XOR INITIAL WHITENING (XOR with RK0)             │
     └───────────────────────────┬────────────────────────────────────┘
                                 │
                                 v
     ┌────────────────────────────────────────────────────────────────┐
     │                 INITIAL GLOBAL DIFFUSION                       │
     │  ┌──────────────────────────────────────────────────────────┐  │
     │  │  Forward Pass ──> Forward Chain ──> Backward Chain       │  │
     │  │       │                                   │              │  │
     │  │       v                                   v              │  │
     │  │  Backward Pass <── Cross-Half Mix <── Final Pass         │  │
     │  └──────────────────────────────────────────────────────────┘  │
     └───────────────────────────┬────────────────────────────────────┘
                                 │
                                 v
     ┌────────────────────────────────────────────────────────────────┐
     │                                                                │
     │                    ┌─────────────────────┐                     │
     │    ┌──────────────>│   ROUND r = 0..N    │<─────────────┐      │
     │    │               └──────────┬──────────┘              │      │
     │    │                          │                         │      │
     │    │                          v                         │      │
     │    │  ┌─────────────────────────────────────────────┐   │      │
     │    │  │         XOR KEY ADDITION (XOR with RKr+1)   │   │      │
     │    │  └──────────────────────┬──────────────────────┘   │      │
     │    │                         │                          │      │
     │    │                         v                          │      │
     │    │  ┌─────────────────────────────────────────────┐   │      │
     │    │  │            WIDE S-BOX (Feistel)             │   │      │
     │    │  │  ┌───────────────────────────────────────┐  │   │      │
     │    │  │  │    LEFT HALF     │    RIGHT HALF      │  │   │      │
     │    │  │  │   [L0][L1]...    │   [R0][R1]...      │  │   │      │
     │    │  │  │        │         │        │           │  │   │      │
     │    │  │  │        │         │        v           │  │   │      │
     │    │  │  │        │       ┌─┴────────────────┐   │  │   │      │
     │    │  │  │        │       │  F(ALL Ri, key)  │   │  │   │      │
     │    │  │  │        │       │  ┌────────────┐  │   │  │   │      │
     │    │  │  │        │       │  │ AES S-box  │  │   │  │   │      │
     │    │  │  │        │       │  │ per byte   │  │   │  │   │      │
     │    │  │  │        │       │  └────────────┘  │   │  │   │      │
     │    │  │  │        │       └────────┬─────────┘   │  │   │      │
     │    │  │  │        │                │             │  │   │      │
     │    │  │  │        v                │             │  │   │      │
     │    │  │  │      XOR<───────────────┘             │  │   │      │
     │    │  │  │        │                              │  │   │      │
     │    │  │  │        v        SWAP (except last)    │  │   │      │
     │    │  │  │   [L'0][L'1]... <==================>  │  │   │      │
     │    │  │  └───────────────────────────────────────┘  │   │      │
     │    │  │            x WIDE_SBOX_ROUNDS (2-4)         │   │      │
     │    │  └──────────────────────┬──────────────────────┘   │      │
     │    │                         │                          │      │
     │    │                         v                          │      │
     │    │  ┌─────────────────────────────────────────────┐   │      │
     │    │  │         ALGEBRAIC S-BOX (8 rounds)          │   │      │
     │    │  │  ┌───────────────────────────────────────┐  │   │      │
     │    │  │  │  For each block Bi:                   │  │   │      │
     │    │  │  │                                       │  │   │      │
     │    │  │  │    XOR RK ──> x (RK|1) ──> ROTL       │  │   │      │
     │    │  │  │      │                      │         │  │   │      │
     │    │  │  │      v                      v         │  │   │      │
     │    │  │  │    XOR RK ──> ROTR ──> x PHI ──> XOR  │  │   │      │
     │    │  │  │      │                          │     │  │   │      │
     │    │  │  │      v         ... x 8 ...      v     │  │   │      │
     │    │  │  │    x (RK|1) ──> ROTL ──> XOR ──> x PI │  │   │      │
     │    │  │  └───────────────────────────────────────┘  │   │      │
     │    │  └──────────────────────┬──────────────────────┘   │      │
     │    │                         │                          │      │
     │    │                         v                          │      │
     │    │  ┌─────────────────────────────────────────────┐   │      │
     │    │  │              DIFFUSION LAYER                │   │      │
     │    │  │  ┌───────────────────────────────────────┐  │   │      │
     │    │  │  │         QUARTER ROUNDS (ARX)          │  │   │      │
     │    │  │  │                                       │  │   │      │
     │    │  │  │   [B0][B1][B2][B3]   [B4][B5][B6][B7] │  │   │      │
     │    │  │  │     │   │   │   │      │   │   │   │  │  │   │      │
     │    │  │  │     └───┴───┴───┘      └───┴───┴───┘  │  │   │      │
     │    │  │  │             │                │        │  │   │      │
     │    │  │  │     ┌───────┴────────────────┴─────┐  │  │   │      │
     │    │  │  │     │  a += b; d = rotl(d XOR a)   │  │  │   │      │
     │    │  │  │     │  c += d; b = rotl(b XOR c)   │  │  │   │      │
     │    │  │  │     │  a += b; d = rotl(d XOR a)   │  │  │   │      │
     │    │  │  │     │  c += d; b = rotl(b XOR c)   │  │  │   │      │
     │    │  │  │     │  a XOR= c; b XOR= d          │  │  │   │      │
     │    │  │  │     └──────────────────────────────┘  │  │   │      │
     │    │  │  │                    │                  │  │   │      │
     │    │  │  │                    v                  │  │   │      │
     │    │  │  │         CROSS-GROUP MIXING            │  │   │      │
     │    │  │  │         CROSS-HALF MIXING             │  │   │      │
     │    │  │  └───────────────────────────────────────┘  │   │      │
     │    │  └──────────────────────┬──────────────────────┘   │      │
     │    │                         │                          │      │
     │    │                         v                          │      │
     │    │  ┌─────────────────────────────────────────────┐   │      │
     │    │  │         PSEUDO-HADAMARD TRANSFORM           │   │      │
     │    │  │                                             │   │      │
     │    │  │      For each block: PHT(x) = 2a+b, a+b     │   │      │
     │    │  └──────────────────────┬──────────────────────┘   │      │
     │    │                         │                          │      │
     │    │                         v                          │      │
     │    │  ┌─────────────────────────────────────────────┐   │      │
     │    │  │          XOR ROUND CONSTANT INJECTION       │   │      │
     │    │  │                                             │   │      │
     │    │  │    B0 XOR= RC[r]     Bn-1 XOR= rotl(RC[r])  │   │      │
     │    │  │    Bn/2 XOR= rotr(RC[r])  (if N>=4)         │   │      │
     │    │  └──────────────────────┬──────────────────────┘   │      │
     │    │                         │                          │      │
     │    │                         │      r < NUM_ROUNDS?     │      │
     │    │                         │             │            │      │
     │    │          YES            │             │     NO     │      │
     │    └─────────────────────────┘             │            │      │
     │                                            v            │      │
     │                                       ┌────────┐        │      │
     │                                       │  EXIT  │        │      │
     │                                       └────┬───┘        │      │
     └────────────────────────────────────────────┼────────────┘
                                                  │
                                                  v
     ┌────────────────────────────────────────────────────────────────┐
     │                  FINAL GLOBAL DIFFUSION                        │
     │           (same structure, different seeds from RKn+1)         │
     └───────────────────────────┬────────────────────────────────────┘
                                 │
                                 v
     ┌────────────────────────────────────────────────────────────────┐
     │                XOR FINAL WHITENING (XOR with RKn+1)            │
     └───────────────────────────┬────────────────────────────────────┘
                                 │
                                 v
     ┌────────────────────────────────────────────────────────────────┐
     │                        CIPHERTEXT BLOCKS                       │
     │                  [C0] [C1] [C2] ... [Cn-1]                     │
     └────────────────────────────────────────────────────────────────┘


──────────────────────────────────────────────────────────────────────────────
                              SYMBOL LEGEND
──────────────────────────────────────────────────────────────────────────────

    XOR     Exclusive OR
    x       Modular multiplication
    ROTL    Left rotation
    ROTR    Right rotation
    PHI     Constant phi (golden ratio)
    PI      Constant PI
    RC[r]   Round constant for round r
    RKi     Round key i
    (x|1)   x with least significant bit forced to 1 (for invertibility)

──────────────────────────────────────────────────────────────────────────────
```