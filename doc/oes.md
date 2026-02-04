# OpenES (OES) Encryption System Architecture

## Overview

OpenES (OES) is a comprehensive cryptographic library providing block ciphers, hashing, and key management. It features
a custom-designed wide-block cipher called **SPHINX** alongside standard encryption modes.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              OES ENCRYPTION SYSTEM                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                         OES ENGINE (OES.h/cpp)                          │    │
│  │                                                                         │    │
│  │   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │    │
│  │   │   oKey       │   │   wKey       │   │     IV       │                │    │
│  │   │ (Original)   │   │ (Working)    │   │              │                │    │
│  │   └──────────────┘   └──────────────┘   └──────────────┘                │    │
│  │          │                  │                  │                        │    │
│  │          └──────────────────┴──────────────────┘                        │    │
│  │                         │                                               │    │
│  │   ┌─────────────────────┴─────────────────────┐                         │    │
│  │   │                                           │                         │    │
│  │   ▼                                           ▼                         │    │
│  │ ┌──────────────┐                      ┌──────────────┐                  │    │
│  │ │ plainBlock   │◄──── Operations ────►│ cipherBlock  │                  │    │
│  │ │  (input)     │                      │   (output)   │                  │    │
│  │ └──────────────┘                      └──────────────┘                  │    │
│  │                                                                         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│           ┌────────────────────────┼────────────────────────┐                   │
│           │                        │                        │                   │
│           ▼                        ▼                        ▼                   │
│  ┌─────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐          │
│  │  BLOCK CIPHERS  │  │      HASHING        │  │   KEY MANAGEMENT    │          │
│  │  (block_ciphers │  │    (hashing.cpp)    │  │ (key_management.cpp)│          │
│  │      .cpp)      │  │                     │  │                     │          │
│  │                 │  │                     │  │                     │          │
│  │ • ECB Mode      │  │ • OESHasher         │  │ • key_expansion()   │          │
│  │ • CBC Mode      │  │ • sponge construct  │  │ • PBKDF()           │          │
│  │ • CTR Mode      │  │ • 64-byte state     │  │ • key_scheduler()   │          │
│  │ • CKE Mode      │  │ • 32 rounds         │  │ • HMAC expansion    │          │
│  │ • ADV Mode      │  │                     │  │                     │          │
│  │                 │  │                     │  │                     │          │
│  └────────┬────────┘  └──────────┬──────────┘  └──────────┬──────────┘          │
│           │                      │                        │                     │
│           └──────────────────────┴────────────────────────┘                     │
│                                  │                                              │
│                                  ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                         SPHINX CIPHER v3.1                              │    │
│  │                    (sphinix.cpp / sphinix.h)                            │    │
│  │                                                                         │    │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │    │
│  │  │                    ENCRYPTION ROUNDS                             │   │    │
│  │  │                                                                  │   │    │
│  │  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐   │   │    │
│  │  │  │Key Addition │───►│ Wide S-box  │───►│ Algebraic S-box     │   │   │    │
│  │  │  │  (XOR)      │    │ (Feistel)   │    │ (8 rounds of ARX)   │   │   │    │
│  │  │  └─────────────┘    └─────────────┘    └─────────────────────┘   │   │    │
│  │  │           │                                               │      │   │    │
│  │  │           ▼                                               ▼      │   │    │
│  │  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐   │   │    │
│  │  │  │  Diffusion  │───►│    PHT      │───►│ Round Constant      │   │   │    │
│  │  │  │   Layer     │    │ (Mix)       │    │    Injection        │   │   │    │
│  │  │  └─────────────┘    └─────────────┘    └─────────────────────┘   │   │    │
│  │  │                                                                  │   │    │
│  │  └──────────────────────────────────────────────────────────────────┘   │    │
│  │                                                                         │    │
│  │  ┌─────────────────────────────────────────────────────────────────┐    │    │
│  │  │              KEY SCHEDULE (Sponge Construction)                 │    │    │
│  │  │                                                                 │    │    │
│  │  │   Master Key ──► Absorb ──► Permute ──► Squeeze ──► Round Keys  │    │    │
│  │  │                                                                 │    │    │
│  │  └─────────────────────────────────────────────────────────────────┘    │    │
│  │                                                                         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. OES Engine Core

The OES class serves as the main interface for all cryptographic operations.

### Key Management Flow

The OES engine maintains three types of keys:

1. **Original Key (oKey)**: The password or key material provided by the user
2. **Working Key (wKey)**: Derived from oKey through expansion
3. **Round Keys**: Generated by the key scheduler for each encryption round

### Encryption Modes

The OES engine supports multiple encryption modes through a consistent interface:

| Method                   | Description                                          |
|--------------------------|------------------------------------------------------|
| `set_key()`              | Set encryption key from string                       |
| `extendWKey()`           | Expand key to specified strength using key expansion |
| `deriveWKey()`           | Derive working key with salt (HMAC-based)            |
| `load_data_raw()`        | Load plaintext data for encryption                   |
| `load_cipher_data_raw()` | Load ciphertext for decryption                       |

---

## 2. Block Cipher Modes

All block cipher modes are implemented using SPHINX as the underlying cipher.

### 2.1 ECB (Electronic Codebook)

**Security**: Low - patterns preserved across blocks  
**Parallelizable**: Yes (fully)  
**Error Propagation**: None

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Block 1 │────►│ SPHINX  │────►│Cipher 1 │
├─────────┤     │ Encrypt │     ├─────────┤
│ Block 2 │────►│         │────►│Cipher 2 │
├─────────┤     │         │     ├─────────┤
│ Block 3 │────►│         │────►│Cipher 3 │
└─────────┘     └─────────┘     └─────────┘
       ▲                              │
       │         Same Key             │
       └──────────────────────────────┘
```

ECB mode encrypts each block independently with the same key. Identical plaintext blocks produce identical ciphertext,
which can leak information about patterns in the data. Not recommended for most use cases.

### 2.2 CBC (Cipher Block Chaining)

**Security**: High (with random IV)  
**Parallelizable**: Decryption only  
**Error Propagation**: Limited (current + next block)

```
         IV
          │
          ▼
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Block 1 │◄───►│   XOR   │◄────│Cipher 1 │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     │          ┌────▼────┐          │
     └─────────►│ SPHINX  │──────────┘
                │ Encrypt │
                └────┬────┘
                     │
     ┌───────────────┘
     ▼
┌─────────┐     ┌─────────┐
│ Block 2 │◄───►│   XOR   │◄─── ...
└─────────┘     └─────────┘
```

CBC mode XORs each plaintext block with the previous ciphertext block before encryption. This ensures identical
plaintext blocks produce different ciphertext. Requires a random initialization vector (IV) for the first block.

### 2.3 CTR (Counter Mode)

**Security**: High (with unique nonce)  
**Parallelizable**: Yes (fully)  
**Error Propagation**: None (bit errors stay localized)

```
         Counter = N              Counter = N+1
              │                        │
              ▼                        ▼
┌─────────────────────────┐  ┌─────────────────────────┐
│    SPHINX Encrypt       │  │    SPHINX Encrypt       │
│      (Nonce||Ctr)       │  │      (Nonce||Ctr)       │
└───────────┬─────────────┘  └───────────┬─────────────┘
            │                            │
            ▼                            ▼
┌─────────┐     ┌─────────┐    ┌─────────┐     ┌─────────┐
│Keystream│────►│   XOR   │◄───│Keystream│────►│   XOR   │◄─── ...
└─────────┘     └────┬────┘    └─────────┘     └────┬────┘
                     │                               │
                ┌────▼────┐                     ┌────▼────┐
                │ Block 1 │                     │ Block 2 │
                │(plain)  │                     │(plain)  │
                └────┬────┘                     └────┬────┘
                     │                               │
                     ▼                               ▼
                ┌─────────┐                     ┌─────────┐
                │Cipher 1 │                     │Cipher 2 │
                └─────────┘                     └─────────┘
```

CTR mode generates a keystream by encrypting a counter value. The keystream is then XORed with the plaintext. This
effectively turns a block cipher into a stream cipher, enabling parallel encryption and decryption.

### 2.4 CKE (Chained Key Expansion) - Proprietary Mode

**Security**: High - key evolution prevents pattern analysis  
**Parallelizable**: No (sequential dependency)  
**Features**: Forward secrecy through key evolution

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CKE ENCRYPTION FLOW                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ChainState₀ = Seed                                                  │
│         │                                                            │
│         ▼                                                            │
│  ┌─────────────────────────────────────────────────────────────┐     │
│  │ BLOCK 0                                                     │     │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │     │
│  │  │ KeyExpand   │───►│  SPHINX     │───►│ XOR with Mask   │──┼───► │ ──┐
│  │  │ (ChainState)│    │  Encrypt    │    │                 │  │     │   │
│  │  └─────────────┘    └─────────────┘    └─────────────────┘  │     │   │
│  │                                                             │     │   │
│  │  ChainState₁ = CiphertextBlock₀ (last block)                │     │   │
│  └─────────────────────────────────────────────────────────────┘     │   │
│                              │                                       │   │
│                              ▼                                       │   │
│  ┌─────────────────────────────────────────────────────────────┐     │   │
│  │ BLOCK 1                                                     │     │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │     │   │
│  │  │ KeyExpand   │───►│  SPHINX     │───►│ XOR with Mask   │──┼───► │   │
│  │  │(ChainState₁)│    │  Encrypt    │    │                 │  │     │   │
│  │  └─────────────┘    └─────────────┘    └─────────────────┘  │     │   │
│  │                                                             │     │   │
│  │  ChainState₂ = CiphertextBlock₁                             │     │   │
│  └─────────────────────────────────────────────────────────────┘     │   │
│                              │                                       │   │
│                              ▼                                       │   │
│                             ...                                      │   │
│                                                                      │   │
│  Ciphertext Output ◄─────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

CKE mode derives a new key for each block from the previous ciphertext block. This creates a chain where each block's
encryption depends on all previous blocks, providing forward secrecy properties.

### 2.5 ADV (Advanced Mode) - Recommended

**Security**: Very High - multi-phase protection  
**Features**: Combines multiple protection layers

**Encryption Phases**:

```
┌──────────────────────────────────────────────────────────────────────┐
│                     ADV ENCRYPTION PIPELINE                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PHASE 1: PREPROCESSING                                              │
│  ├─ Add outer padding                                                │
│  ├─ Inject PRNG block (anti-pattern)                                 │
│  └─ Rotate right by 2 positions                                      │
│                                                                      │
│  PHASE 2: PRE-CIPHER DIFFUSION                                       │
│  ├─ Global diffusion (forward/backward passes)                       │
│  └─ Data correlation (correlate_data)                                │
│                                                                      │
│  PHASE 3: KEY DERIVATION                                             │
│  └─ PBKDF with session-based salt (16 iterations)                    │
│                                                                      │
│  PHASE 4: SPHINX ENCRYPTION                                          │
│  └─ Full SPHINX cipher with derived session key                      │
│                                                                      │
│  PHASE 5: POST-CIPHER MIXING                                         │
│  ├─ Data correlation                                                 │
│  └─ Global diffusion (inverse pattern)                               │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

ADV mode is the recommended encryption mode combining multiple security layers: preprocessing to hide patterns,
diffusion to spread entropy, session-based key derivation, full SPHINX encryption, and post-cipher mixing. Provides the
strongest security guarantee.

---

## 3. SPHINX Cipher v3.1

### Overview

SPHINX is a custom-designed wide-block cipher featuring:

- **Configurable width**: 1-16 blocks (default 16)
- **Block size**: 8-128 bits per block (compile-time configurable)
- **Security**: N × block_size bits (e.g., 16 × 128 = 2048 bits default)
- **Resistance**: Side-channel, differential, linear, algebraic attacks

### SPHINX Encryption Round

Each encryption round consists of six sequential operations:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          SPHINX SINGLE ROUND                                 │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Input Blocks: [B0] [B1] [B2] ... [Bn-1]                                    │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │ 1. KEY ADDITION                                                     │    │
│   │    Each block: Bi = Bi ^ RoundKey[i]                                │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │ 2. WIDE S-BOX (Feistel Structure)                                   │    │
│   │                                                                     │    │
│   │    Split: Left = [B0..Bn/2-1], Right = [Bn/2..Bn-1]                 │    │
│   │                                                                     │    │
│   │    For each left block Li:                                          │    │
│   │      F = AES_Sbox( sum of all Right blocks + key )                  │    │
│   │      Li = Li ^ F                                                    │    │
│   │                                                                     │    │
│   │    Swap halves (except last round)                                  │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │ 3. ALGEBRAIC S-BOX (8 rounds per block)                             │    │
│   │                                                                     │    │
│   │    For each block:                                                  │    │
│   │      x = Bi ^ SubKey                                                │    │
│   │      x = x × (SubKey | 1)    (modular mult)                         │    │
│   │      x = ROTL(x, n)                                                 │    │
│   │      x = x ^ ROTR(x, m)                                             │    │
│   │      x = x × PHI_CONST                                              │    │
│   │      ... (8 rounds total)                                           │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │ 4. DIFFUSION LAYER (ARX-based)                                      │    │
│   │                                                                     │    │
│   │    Quarter-round mixing (ChaCha-style):                             │    │
│   │      a += b; d = ROTL(d ^ a, r0)                                    │    │
│   │      c += d; b = ROTL(b ^ c, r1)                                    │    │
│   │      a += b; d = ROTL(d ^ a, r2)                                    │    │
│   │      c += d; b = ROTL(b ^ c, r3)                                    │    │
│   │                                                                     │    │
│   │    Cross-group mixing                                               │    │
│   │    Cross-half mixing (for wide configs)                             │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │ 5. PSEUDO-HADAMARD TRANSFORM (PHT)                                  │    │
│   │                                                                     │    │
│   │    For each block pair:                                             │    │
│   │      a' = 2a + b                                                    │    │
│   │      b' = a + b                                                     │    │
│   │                                                                     │    │
│   │    Provides additional mixing and non-linearity                     │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │ 6. ROUND CONSTANT INJECTION                                         │    │
│   │                                                                     │    │
│   │    B0 = B0 ^ RC[round]                                              │    │
│   │    Bn-1 = Bn-1 ^ ROTL(RC[round])                                    │    │
│   │    Bn/2 = Bn/2 ^ ROTR(RC[round])   (if n >= 4)                      │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                         │                                                    │
│                         ▼                                                    │
│   Output Blocks: [B0'] [B1'] [B2'] ... [Bn-1']                               │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Key Schedule (Sponge Construction)

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                      SPHINX KEY SCHEDULE                                      │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   Master Key ──►┌──────────────┐                                              │
│                 │   ABSORB     │                                              │
│                 │              │                                              │
│                 │  XOR key     │                                              │
│                 │  into state  │                                              │
│                 └──────┬───────┘                                              │
│                        │                                                      │
│                        ▼                                                      │
│                 ┌──────────────┐                                              │
│                 │  PERMUTE     │                                              │
│                 │              │                                              │
│                 │  8-12 rounds │                                              │
│                 │  of mixing   │                                              │
│                 └──────┬───────┘                                              │
│                        │                                                      │
│                        ▼                                                      │
│                 ┌──────────────┐                                              │
│                 │   SQUEEZE    │◄──────────────────────────┐                  │
│                 │              │                           │                  │
│                 │ Extract      │    Need more key material?│                  │
│                 │ round keys   │                           │                  │
│                 └──────┬───────┘                           │                  │
│                        │                                   │                  │
│                        ▼                                   │                  │
│              Round Keys for each round                     │                  │
│                 [RK0] [RK1] ... [RKn]                      │                  │
│                                                            │                  │
│                 Domain separation constants ───────────────┘                  │
│                 (0x01 for whitening, 0x02 for rounds, etc.)                   │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

The SPHINX key schedule uses a sponge construction to absorb the master key, permute the internal state through multiple
rounds of mixing, then squeeze out round keys. Domain separation constants ensure different uses of the key schedule
produce independent outputs.

---

## 4. Hashing System

### OESHasher Architecture

The OESHasher implements a cryptographic hash function based on sponge construction with a 64-element state.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       OES HASH ARCHITECTURE                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   STATE (64 m_blocks arranged as 8×8 matrix):                                │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │  S00  S01  S02  S03  S04  S05  S06  S07  │ Row 0                    │    │
│   │  S10  S11  S12  S13  S14  S15  S16  S17  │ Row 1                    │    │
│   │  ...                                         ...                    │    │
│   │  S70  S71  S72  S73  S74  S75  S76  S77  │ Row 7                    │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│   CARRY (4 m_blocks): Used for feedback between rounds                       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Hash Computation Pipeline

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                        HASH COMPUTATION PIPELINE                              │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  1. INITIALIZATION                                                            │
│     • Initialize 64-block state to zero                                       │
│     • Generate hash constants using smix()                                    │
│     • Initialize carry vector based on data length and padding                │
│                                                                               │
│  2. ABSORPTION (absorbData)                                                   │
│     For each 4-block chunk of input:                                          │
│       • Apply data-dependent rotations                                        │
│       • Use SBOX64 for non-linear routing                                     │
│       • Mix with hash constants                                               │
│       • Update state with XOR and multiplication                              │
│                                                                               │
│  3. DOMAIN SEPARATION                                                         │
│     • XOR domain markers into state boundaries                                │
│     • Prevents collision between different message types                      │
│                                                                               │
│  4. PERMUTATION ROUNDS (32 rounds)                                            │
│     Each round consists of:                                                   │
│                                                                               │
│     a) THETA (Mix Columns)                                                    │
│        • Compute column parity                                                │
│        • XOR with rotated neighboring columns                                 │
│                                                                               │
│     b) PI-RHO (Shuffle & Rotate)                                              │
│        • Permute using PI_BOX lookup table                                    │
│        • Apply data-dependent rotations from ROT3D table                      │
│                                                                               │
│     c) CHI (Non-linear Layer)                                                 │
│        • Apply χ: a ^ (~b & c) per row                                        │
│        • Mix row and column operations                                        │
│        • Additional multiplicative mixing                                     │
│                                                                               │
│     d) Round Constant Injection                                               │
│        • XOR ROUND_CONSTANTS[i] into state[0]                                 │
│                                                                               │
│     e) Carry Evolution                                                        │
│        • Update 4-element carry vector                                        │
│        • Cross-mix carry elements                                             │
│                                                                               │
│  5. SQUEEZE (squeezeRounds)                                                   │
│     Every 4 rounds:                                                           │
│       • XOR state into output hash                                            │
│       • Mix in carry values                                                   │
│       • Create serial dependency (feedback)                                   │
│                                                                               │
│  6. FINALIZATION                                                              │
│     • Additional permutation round                                            │
│     • Final carry mixing                                                      │
│     • Position-dependent rotation                                             │
│                                                                               │
│  7. IV MIXING (optional)                                                      │
│     • XOR initialization vector into output                                   │
│     • Update IV for chained hashing                                           │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

The OES hash function uses a sponge-like construction with a 4096-bit internal state. It absorbs input data in chunks,
applies 32 rounds of permutation with Theta, Pi-Rho, Chi operations, and squeezes out the final hash value.

---

## 5. Key Management

### Key Expansion (PBKDF)

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                    KEY EXPANSION (PBKDF)                                      │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   Input: Key, Output Length, Salt, Iterations                                 │
│                                                                               │
│   Step 1: Create counter block [Salt || 1]                                    │
│                                                                               │
│   Step 2: Generate U₁ = HMAC(Key, [Salt||1]) expanded to output length        │
│                                                                               │
│   Step 3: For iteration 2 to N:                                               │
│           Uᵢ = HMAC(Key, Uᵢ₋₁)                                                │
│           Result = Result ^ Uᵢ                                                │
│                                                                               │
│   Output: Expanded key material                                               │
│                                                                               │
│   ─────────────────────────────────────────────────────────────────────────   │
│                                                                               │
│   PBKDF (Password-Based Key Derivation Function):                             │
│   • Generates multiple derived keys from single master key                    │
│   • Uses evolving salt for each derived key                                   │
│   • Default: 16 iterations                                                    │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Key Scheduler

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                      KEY SCHEDULER FOR ROUNDS                                 │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   Purpose: Generate round-specific subkeys from master key                    │
│                                                                               │
│   Process:                                                                    │
│   1. If key length ≠ output length: expand key                                │
│   2. For each output position i:                                              │
│      • Compute RCON = oesRcon(session, i)                                     │
│      • Apply rotation based on position                                       │
│      • XOR with feedback value                                                │
│      • Update feedback = xtime(block) ^ block                                 │
│   3. Final rotation of entire key                                             │
│                                                                               │
│   Session-based: Different session = completely different round keys          │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Core Cryptographic Primitives

### Global Diffusion

Located in core operations:

- **Three-pass diffusion**: forward, backward, forward
- Uses Pseudo-Hadamard Transform for mixing
- Provides avalanche effect across entire data

**Purpose**: Ensure that a change in any input bit affects all output bits.

### Data Correlation

- Creates dependencies between adjacent blocks
- Uses xTime multiplication and Hadamard transform
- Reversible transformation for decryption

**Purpose**: Bind adjacent blocks together so they cannot be independently manipulated.

### Pseudo-Hadamard Transform (PHT)

```
PHT(a, b) = (2a + b, a + b)
```

Provides fast, reversible mixing of paired values. Used extensively in diffusion operations.

---

## 7. Security Properties

### SPHINX Cipher

| Property     | Implementation                      |
|--------------|-------------------------------------|
| Block Size   | Configurable: 8-128 bits × N blocks |
| Key Size     | Scales with block configuration     |
| Rounds       | log₂(total_bits) + corrections      |
| S-box        | Wide Feistel + Algebraic ARX        |
| Diffusion    | Quarter-round ARX + PHT             |
| Key Schedule | Sponge construction                 |

### Side-Channel Resistance

- No table lookups (constant-time)
- Data-independent memory access patterns
- No branching on secret data

### Hash Function

| Property   | Value                    |
|------------|--------------------------|
| State Size | 4096 bits (64 × 64)      |
| Capacity   | 256 bits                 |
| Rounds     | 32                       |
| Output     | Configurable 1-64 blocks |

---

## 8. Configuration Constants

Compile-time configuration affects security level and performance:

| Constant               | Default | Description               |
|------------------------|---------|---------------------------|
| `OES_NUM_OF_BLOCKS`    | 16      | Number of parallel blocks |
| `OES_LOGIC_BLOCK_SIZE` | 128     | Bits per block            |
| `OES_MEM_SIZE`         | 128     | Derived memory size       |

Mathematical constants:

| Constant        | Value              | Origin              |
|-----------------|--------------------|---------------------|
| `PHI_CONST`     | 0x9E3779B97F4A7C15 | Golden ratio × 2^64 |
| `DIFFUSE_CONST` | 0x54A6B2C94D5A6C3B | √11, √13 fractions  |
| `PRNG_SEED`     | 0xB5AD4ECEDA1CE2A9 | SplitMix64 constant |

---

## 9. Usage Guidelines

### Choosing an Encryption Mode

| Mode | Use Case                         | Security      |
|------|----------------------------------|---------------|
| ECB  | Never (for testing only)         | Low           |
| CBC  | Sequential data, disk encryption | High          |
| CTR  | Streaming, parallel processing   | High          |
| CKE  | Sequential with key evolution    | High          |
| ADV  | **Default, general purpose**     | **Very High** |

### Security Levels by Block Size

| Block Size | Max Key Size | Security Level     |
|------------|--------------|--------------------|
| 8-bit      | 64-bit       | Basic              |
| 16-bit     | 128-bit      | AES-128 equivalent |
| 32-bit     | 256-bit      | AES-256 equivalent |
| 64-bit     | 512-bit      | Post-quantum ready |
| 128-bit    | 1024-bit     | Quantum-safe       |

---

For implementation details and API reference, see [`architecture.md`](architecture.md).
