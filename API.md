# ChaCha20-Poly1305 API Documentation

This document provides comprehensive documentation for all public functions in the ChaCha20-Poly1305 RISC-V implementation.

## Table of Contents

1. [AEAD Interface](#aead-interface)
2. [ChaCha20 Stream Cipher](#chacha20-stream-cipher)
3. [Poly1305 MAC](#poly1305-mac)
4. [Utility Functions](#utility-functions)
5. [Error Handling](#error-handling)
6. [Usage Examples](#usage-examples)

---

## AEAD Interface

The AEAD (Authenticated Encryption with Associated Data) interface provides the primary encryption and decryption functions.

### Header File

```c
#include "chacha20poly1305.h"
```

### Data Types

#### `chacha20poly1305_error_t`

Error codes returned by AEAD functions:

```c
typedef enum {
    CHACHA20POLY1305_OK = 0,                    // Success
    CHACHA20POLY1305_ERROR_NULL_POINTER,        // Null pointer argument
    CHACHA20POLY1305_ERROR_INVALID_LENGTH,      // Invalid length parameter
    CHACHA20POLY1305_ERROR_AUTH_FAILED,         // Authentication tag verification failed
    CHACHA20POLY1305_ERROR_INVALID_KEY,         // Invalid key format
    CHACHA20POLY1305_ERROR_INVALID_NONCE,       // Invalid nonce format
    CHACHA20POLY1305_ERROR_FILE_IO,             // File I/O error
    CHACHA20POLY1305_ERROR_MEMORY               // Memory allocation error
} chacha20poly1305_error_t;
```

### Functions

#### `chacha20poly1305_encrypt()`

Encrypts plaintext and generates an authentication tag.

```c
int chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);
```

**Parameters:**
- `key`: 256-bit encryption key (32 bytes)
- `nonce`: 96-bit nonce (12 bytes) - must be unique for each encryption with the same key
- `aad`: Additional authenticated data (can be NULL if `aad_len` is 0)
- `aad_len`: Length of AAD in bytes
- `plaintext`: Input plaintext data
- `plaintext_len`: Length of plaintext in bytes
- `ciphertext`: Output buffer for ciphertext (must be at least `plaintext_len` bytes)
- `tag`: Output buffer for 16-byte authentication tag

**Returns:**
- `CHACHA20POLY1305_OK` on success
- Error code on failure

**Notes:**
- The ciphertext buffer must be pre-allocated and at least `plaintext_len` bytes
- The same key-nonce pair must NEVER be reused
- AAD is authenticated but not encrypted

**Example:**
```c
uint8_t key[32] = { /* your key */ };
uint8_t nonce[12] = { /* unique nonce */ };
uint8_t plaintext[] = "Secret message";
uint8_t ciphertext[sizeof(plaintext)];
uint8_t tag[16];

int result = chacha20poly1305_encrypt(
    key, nonce,
    NULL, 0,  // No AAD
    plaintext, sizeof(plaintext),
    ciphertext, tag
);

if (result == CHACHA20POLY1305_OK) {
    // Encryption successful
}
```

#### `chacha20poly1305_decrypt()`

Verifies authentication tag and decrypts ciphertext.

```c
int chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);
```

**Parameters:**
- `key`: 256-bit encryption key (32 bytes)
- `nonce`: 96-bit nonce (12 bytes) - same as used for encryption
- `aad`: Additional authenticated data (must match encryption AAD)
- `aad_len`: Length of AAD in bytes
- `ciphertext`: Input ciphertext data
- `ciphertext_len`: Length of ciphertext in bytes
- `tag`: 16-byte authentication tag from encryption
- `plaintext`: Output buffer for plaintext (must be at least `ciphertext_len` bytes)

**Returns:**
- `CHACHA20POLY1305_OK` on success
- `CHACHA20POLY1305_ERROR_AUTH_FAILED` if tag verification fails
- Other error codes on failure

**Security Notes:**
- Tag verification is performed BEFORE decryption
- If tag verification fails, no plaintext is output
- Uses constant-time comparison to prevent timing attacks
- All intermediate data is securely zeroed on failure

**Example:**
```c
uint8_t key[32] = { /* your key */ };
uint8_t nonce[12] = { /* same nonce as encryption */ };
uint8_t ciphertext[] = { /* encrypted data */ };
uint8_t tag[16] = { /* authentication tag */ };
uint8_t plaintext[sizeof(ciphertext)];

int result = chacha20poly1305_decrypt(
    key, nonce,
    NULL, 0,  // No AAD
    ciphertext, sizeof(ciphertext),
    tag, plaintext
);

if (result == CHACHA20POLY1305_OK) {
    // Decryption successful, plaintext is valid
} else if (result == CHACHA20POLY1305_ERROR_AUTH_FAILED) {
    // Authentication failed - data may be corrupted or tampered
}
```

---

## ChaCha20 Stream Cipher

Low-level ChaCha20 stream cipher interface.

### Header File

```c
#include "chacha20.h"
```

### Data Types

#### `chacha20_ctx`

ChaCha20 context structure:

```c
typedef struct {
    uint32_t state[16];      // ChaCha20 state matrix (4x4)
    uint32_t initial[16];    // Initial state (used for final addition)
    uint32_t counter;        // Block counter
} chacha20_ctx;
```

### Functions

#### `chacha20_init()`

Initializes ChaCha20 context with key, nonce, and counter.

```c
void chacha20_init(chacha20_ctx *ctx, 
                   const uint8_t key[32],
                   const uint8_t nonce[12],
                   uint32_t counter);
```

**Parameters:**
- `ctx`: Pointer to ChaCha20 context to initialize
- `key`: 256-bit key (32 bytes)
- `nonce`: 96-bit nonce (12 bytes)
- `counter`: Initial block counter (usually 1; 0 is reserved for Poly1305 key derivation)

**Notes:**
- Must be called before using other ChaCha20 functions
- The same key-nonce pair must not be reused

**Example:**
```c
chacha20_ctx ctx;
uint8_t key[32] = { /* your key */ };
uint8_t nonce[12] = { /* unique nonce */ };

chacha20_init(&ctx, key, nonce, 1);
```

#### `chacha20_block()`

Generates one 64-byte keystream block.

```c
void chacha20_block(chacha20_ctx *ctx, uint8_t output[64]);
```

**Parameters:**
- `ctx`: Pointer to initialized ChaCha20 context
- `output`: Output buffer for 64-byte keystream block

**Notes:**
- Automatically increments the block counter after generation
- Used internally by `chacha20_crypt()`

**Example:**
```c
chacha20_ctx ctx;
chacha20_init(&ctx, key, nonce, 1);

uint8_t keystream[64];
chacha20_block(&ctx, keystream);
```

#### `chacha20_crypt()`

Encrypts or decrypts data (XOR with keystream).

```c
void chacha20_crypt(chacha20_ctx *ctx,
                    uint8_t *data,
                    size_t len);
```

**Parameters:**
- `ctx`: Pointer to initialized ChaCha20 context
- `data`: Data buffer to encrypt/decrypt (in-place operation)
- `len`: Length of data in bytes

**Notes:**
- Performs in-place encryption/decryption
- Handles arbitrary data lengths (including partial blocks)
- Automatically increments counter for each 64-byte block

**Example:**
```c
chacha20_ctx ctx;
chacha20_init(&ctx, key, nonce, 1);

uint8_t data[] = "Hello, World!";
chacha20_crypt(&ctx, data, sizeof(data));  // Encrypt
// data now contains ciphertext

// To decrypt, initialize with same key/nonce and call again
chacha20_init(&ctx, key, nonce, 1);
chacha20_crypt(&ctx, data, sizeof(data));  // Decrypt
// data now contains original plaintext
```

#### `quarter_round()`

Performs ChaCha20 Quarter Round operation (internal function).

```c
void quarter_round(uint32_t *a, uint32_t *b, 
                   uint32_t *c, uint32_t *d);
```

**Parameters:**
- `a`, `b`, `c`, `d`: Pointers to four 32-bit state words

**Notes:**
- This is an internal function used by the ChaCha20 block function
- Typically not called directly by applications
- Implements the core ChaCha20 mixing operation

---

## Poly1305 MAC

Low-level Poly1305 message authentication code interface.

### Header File

```c
#include "poly1305.h"
```

### Data Types

#### `poly1305_ctx`

Poly1305 context structure:

```c
typedef struct {
    uint32_t r[5];           // r value (clamped), 130-bit in 5 26-bit limbs
    uint32_t h[5];           // Accumulator h, 130-bit
    uint32_t pad[4];         // s value (pad), 128-bit
    uint8_t buffer[16];      // Input buffer
    size_t buf_used;         // Bytes used in buffer
} poly1305_ctx;
```

### Functions

#### `poly1305_init()`

Initializes Poly1305 context with a key.

```c
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);
```

**Parameters:**
- `ctx`: Pointer to Poly1305 context to initialize
- `key`: 32-byte key (first 16 bytes for r, last 16 bytes for s)

**Notes:**
- Must be called before using other Poly1305 functions
- The r value is automatically clamped according to RFC 8439

**Example:**
```c
poly1305_ctx ctx;
uint8_t key[32] = { /* your key */ };

poly1305_init(&ctx, key);
```

#### `poly1305_update()`

Updates Poly1305 MAC with additional data.

```c
void poly1305_update(poly1305_ctx *ctx, 
                     const uint8_t *data, 
                     size_t len);
```

**Parameters:**
- `ctx`: Pointer to initialized Poly1305 context
- `data`: Input data to authenticate
- `len`: Length of input data in bytes

**Notes:**
- Can be called multiple times to process data incrementally
- Handles arbitrary data lengths
- Buffers incomplete 16-byte blocks internally

**Example:**
```c
poly1305_ctx ctx;
poly1305_init(&ctx, key);

poly1305_update(&ctx, data1, len1);
poly1305_update(&ctx, data2, len2);
// ... more updates as needed
```

#### `poly1305_final()`

Finalizes Poly1305 computation and outputs the MAC tag.

```c
void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16]);
```

**Parameters:**
- `ctx`: Pointer to Poly1305 context
- `mac`: Output buffer for 16-byte MAC tag

**Notes:**
- Must be called after all data has been processed with `poly1305_update()`
- Processes any remaining buffered data
- After calling, the context should not be reused

**Example:**
```c
poly1305_ctx ctx;
poly1305_init(&ctx, key);
poly1305_update(&ctx, data, len);

uint8_t mac[16];
poly1305_final(&ctx, mac);
// mac now contains the authentication tag
```

#### `poly1305_block()`

Processes one 16-byte block (internal function).

```c
void poly1305_block(poly1305_ctx *ctx, 
                    const uint8_t block[16], 
                    int final);
```

**Parameters:**
- `ctx`: Pointer to Poly1305 context
- `block`: 16-byte input block
- `final`: Whether this is the final block (affects padding)

**Notes:**
- This is an internal function used by `poly1305_update()` and `poly1305_final()`
- Typically not called directly by applications

---

## Utility Functions

Helper functions for byte operations and security.

### Header File

```c
#include "utils.h"
```

### Functions

#### `rotl32()`

32-bit rotate left operation.

```c
static inline uint32_t rotl32(uint32_t x, int n);
```

**Parameters:**
- `x`: Value to rotate
- `n`: Number of bits to rotate (0-31)

**Returns:**
- Rotated value

**Notes:**
- Pure C implementation
- Optimized versions available with `USE_ASM` or RISC-V B extension

#### `load_le32()`

Loads a 32-bit little-endian integer from a byte array.

```c
static inline uint32_t load_le32(const uint8_t *p);
```

**Parameters:**
- `p`: Pointer to byte array (must have at least 4 bytes)

**Returns:**
- 32-bit integer value

**Notes:**
- Optimized for RISC-V little-endian architecture
- Handles unaligned access on platforms that support it

#### `store_le32()`

Stores a 32-bit integer as little-endian bytes.

```c
static inline void store_le32(uint8_t *p, uint32_t v);
```

**Parameters:**
- `p`: Pointer to output byte array (must have space for 4 bytes)
- `v`: Value to store

**Notes:**
- Optimized for RISC-V little-endian architecture

#### `secure_zero()`

Securely zeros memory (prevents compiler optimization).

```c
void secure_zero(void *ptr, size_t len);
```

**Parameters:**
- `ptr`: Pointer to memory to zero
- `len`: Length in bytes

**Notes:**
- Uses volatile to prevent compiler from optimizing away the zeroing
- Essential for clearing sensitive data like keys

**Example:**
```c
uint8_t key[32] = { /* sensitive data */ };
// ... use key ...
secure_zero(key, sizeof(key));  // Securely erase
```

#### `secure_compare()`

Constant-time memory comparison.

```c
int secure_compare(const uint8_t *a, const uint8_t *b, size_t len);
```

**Parameters:**
- `a`: First buffer
- `b`: Second buffer
- `len`: Length to compare in bytes

**Returns:**
- `1` if buffers are equal
- `0` if buffers are different

**Notes:**
- Executes in constant time regardless of where differences occur
- Prevents timing attacks
- Used for authentication tag comparison

**Example:**
```c
uint8_t tag1[16], tag2[16];
if (secure_compare(tag1, tag2, 16)) {
    // Tags match
} else {
    // Tags differ
}
```

---

## Error Handling

### Error Codes

All AEAD functions return integer error codes:

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `CHACHA20POLY1305_OK` | Operation successful |
| 1 | `CHACHA20POLY1305_ERROR_NULL_POINTER` | Null pointer argument |
| 2 | `CHACHA20POLY1305_ERROR_INVALID_LENGTH` | Invalid length parameter |
| 3 | `CHACHA20POLY1305_ERROR_AUTH_FAILED` | Authentication failed |
| 4 | `CHACHA20POLY1305_ERROR_INVALID_KEY` | Invalid key format |
| 5 | `CHACHA20POLY1305_ERROR_INVALID_NONCE` | Invalid nonce format |
| 6 | `CHACHA20POLY1305_ERROR_FILE_IO` | File I/O error |
| 7 | `CHACHA20POLY1305_ERROR_MEMORY` | Memory allocation error |

### Error Handling Best Practices

1. **Always check return values:**
```c
int result = chacha20poly1305_encrypt(...);
if (result != CHACHA20POLY1305_OK) {
    // Handle error
}
```

2. **Handle authentication failures specially:**
```c
int result = chacha20poly1305_decrypt(...);
if (result == CHACHA20POLY1305_ERROR_AUTH_FAILED) {
    // Data may be corrupted or tampered
    // Do NOT use the plaintext output
}
```

3. **Clean up on errors:**
```c
uint8_t *plaintext = malloc(len);
int result = chacha20poly1305_decrypt(...);
if (result != CHACHA20POLY1305_OK) {
    secure_zero(plaintext, len);
    free(plaintext);
    return result;
}
```

---

## Usage Examples

### Complete Encryption/Decryption Example

```c
#include "chacha20poly1305.h"
#include <stdio.h>
#include <string.h>

int main() {
    // Key and nonce (in practice, generate these securely)
    uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    
    uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    
    // Plaintext
    const char *message = "Ladies and Gentlemen of the class of '99";
    size_t msg_len = strlen(message);
    
    // Buffers
    uint8_t ciphertext[msg_len];
    uint8_t tag[16];
    uint8_t decrypted[msg_len];
    
    // Encrypt
    int result = chacha20poly1305_encrypt(
        key, nonce,
        NULL, 0,  // No AAD
        (const uint8_t *)message, msg_len,
        ciphertext, tag
    );
    
    if (result != CHACHA20POLY1305_OK) {
        fprintf(stderr, "Encryption failed: %d\n", result);
        return 1;
    }
    
    printf("Encryption successful\n");
    
    // Decrypt
    result = chacha20poly1305_decrypt(
        key, nonce,
        NULL, 0,  // No AAD
        ciphertext, msg_len,
        tag, decrypted
    );
    
    if (result == CHACHA20POLY1305_ERROR_AUTH_FAILED) {
        fprintf(stderr, "Authentication failed!\n");
        return 1;
    } else if (result != CHACHA20POLY1305_OK) {
        fprintf(stderr, "Decryption failed: %d\n", result);
        return 1;
    }
    
    printf("Decryption successful\n");
    
    // Verify
    if (memcmp(message, decrypted, msg_len) == 0) {
        printf("Plaintext matches!\n");
    }
    
    return 0;
}
```

### Encryption with AAD

```c
// Additional authenticated data (not encrypted, but authenticated)
const char *aad_data = "metadata:version=1.0";
size_t aad_len = strlen(aad_data);

// Encrypt with AAD
int result = chacha20poly1305_encrypt(
    key, nonce,
    (const uint8_t *)aad_data, aad_len,
    plaintext, plaintext_len,
    ciphertext, tag
);

// Decrypt with same AAD
result = chacha20poly1305_decrypt(
    key, nonce,
    (const uint8_t *)aad_data, aad_len,  // Must match encryption AAD
    ciphertext, ciphertext_len,
    tag, decrypted
);
```

### Streaming Data Processing

```c
#include "chacha20.h"

// Process large file in chunks
void encrypt_file(FILE *in, FILE *out, 
                  const uint8_t key[32], 
                  const uint8_t nonce[12]) {
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce, 1);
    
    uint8_t buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        chacha20_crypt(&ctx, buffer, bytes_read);
        fwrite(buffer, 1, bytes_read, out);
    }
    
    // Clean up
    secure_zero(&ctx, sizeof(ctx));
}
```

### Computing MAC Only

```c
#include "poly1305.h"

void compute_mac(const uint8_t *data, size_t len,
                 const uint8_t key[32],
                 uint8_t mac[16]) {
    poly1305_ctx ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, data, len);
    poly1305_final(&ctx, mac);
    
    // Clean up
    secure_zero(&ctx, sizeof(ctx));
}
```

---

## Thread Safety

**Important:** The ChaCha20-Poly1305 implementation is **not thread-safe**. Each thread must use its own context structures. Do not share context structures between threads without proper synchronization.

## Memory Management

- All context structures can be allocated on the stack or heap
- No dynamic memory allocation is performed by the library
- Caller is responsible for allocating output buffers
- Use `secure_zero()` to clear sensitive data before freeing

## Performance Considerations

1. **Buffer alignment**: For best performance on RISC-V, ensure buffers are 4-byte aligned
2. **Batch processing**: Process larger chunks of data when possible
3. **Reuse contexts**: For multiple operations with the same key, reuse contexts when appropriate
4. **Compiler optimizations**: Build with `-O2` or `-O3` for best performance

## Platform-Specific Notes

### RISC-V Optimizations

- Little-endian byte order is assumed (native to RISC-V)
- Optional B extension support for hardware rotate instructions
- Optional assembly implementations for critical functions
- RV64I uses 64-bit registers for improved performance

### Compile-Time Options

- `USE_ASM`: Enable RISC-V assembly optimizations
- `__riscv_bitmanip`: Enable B extension instructions
- `__riscv_xlen`: Automatically detected (32 or 64)

---

## Security Considerations

See [SECURITY.md](SECURITY.md) for detailed security guidelines.

**Critical Rules:**
1. Never reuse a key-nonce pair
2. Always verify authentication tags before using decrypted data
3. Use secure random number generators for keys and nonces
4. Clear sensitive data with `secure_zero()` after use
5. Handle authentication failures appropriately

---

## References

- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [RISC-V Instruction Set Manual](https://riscv.org/technical/specifications/)

---

*Last updated: 2026-05-26*
