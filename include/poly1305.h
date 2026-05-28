#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Poly1305 context structure
 * 
 * Uses 5 26-bit limbs to represent 130-bit integers for efficient
 * computation on 32-bit platforms
 */
typedef struct {
    uint32_t r[5];           // r value (clamped), 130-bit in 5 26-bit limbs
    uint32_t h[5];           // Accumulator h, 130-bit
    uint32_t pad[4];         // s value (pad), 128-bit
    uint8_t buffer[16];      // Input buffer
    size_t buf_used;         // Bytes used in buffer
} poly1305_ctx;

/**
 * @brief Initialize Poly1305 context
 * 
 * @param ctx Pointer to Poly1305 context
 * @param key 32-byte key (first 16 bytes for r, last 16 bytes for s)
 */
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);

/**
 * @brief Update Poly1305 with additional data
 * 
 * @param ctx Pointer to Poly1305 context
 * @param data Input data
 * @param len Length of input data in bytes
 */
void poly1305_update(poly1305_ctx *ctx, 
                     const uint8_t *data, 
                     size_t len);

/**
 * @brief Finalize Poly1305 and output 16-byte tag
 * 
 * @param ctx Pointer to Poly1305 context
 * @param mac Output buffer for 16-byte MAC tag
 */
void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16]);

/**
 * @brief Process one 16-byte block (internal function)
 * 
 * @param ctx Pointer to Poly1305 context
 * @param block 16-byte input block
 * @param final Whether this is the final block
 */
void poly1305_block(poly1305_ctx *ctx, 
                    const uint8_t block[16], 
                    int final);

#endif // POLY1305_H
