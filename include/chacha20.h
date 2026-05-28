#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief ChaCha20 context structure
 * 
 * Contains the 4x4 state matrix and counter for ChaCha20 stream cipher
 */
typedef struct {
    uint32_t state[16];      // ChaCha20 state matrix (4x4)
    uint32_t initial[16];    // Initial state (used for final addition)
    uint32_t counter;        // Block counter
} chacha20_ctx;

/**
 * @brief Initialize ChaCha20 context
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param key 256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param counter Initial block counter (usually 1, 0 reserved for Poly1305 key)
 * 
 * @note Same key and nonce combination must not be reused
 * @warning Caller must ensure key and nonce pointers are valid
 */
void chacha20_init(chacha20_ctx *ctx, 
                   const uint8_t key[32],
                   const uint8_t nonce[12],
                   uint32_t counter);

/**
 * @brief Generate one 64-byte keystream block
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param output Output buffer for 64-byte keystream block
 */
void chacha20_block(chacha20_ctx *ctx, uint8_t output[64]);

/**
 * @brief Encrypt/decrypt data (in-place operation)
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param data Data buffer to encrypt/decrypt
 * @param len Length of data in bytes
 */
void chacha20_crypt(chacha20_ctx *ctx,
                    uint8_t *data,
                    size_t len);

/**
 * @brief Quarter Round operation (internal function)
 * 
 * @param a Pointer to first state word
 * @param b Pointer to second state word
 * @param c Pointer to third state word
 * @param d Pointer to fourth state word
 */
void quarter_round(uint32_t *a, uint32_t *b, 
                   uint32_t *c, uint32_t *d);

#endif // CHACHA20_H
