#include "chacha20.h"
#include "utils.h"
#include <string.h>

/**
 * @brief Quarter Round operation
 * 
 * Performs the core ChaCha20 quarter round operation on four 32-bit words.
 * This is the fundamental building block of the ChaCha20 algorithm.
 * 
 * The operation is:
 *   a += b; d ^= a; d <<<= 16;
 *   c += d; b ^= c; b <<<= 12;
 *   a += b; d ^= a; d <<<= 8;
 *   c += d; b ^= c; b <<<= 7;
 * 
 * @param a Pointer to first state word
 * @param b Pointer to second state word
 * @param c Pointer to third state word
 * @param d Pointer to fourth state word
 */
void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

/**
 * @brief Initialize ChaCha20 context
 * 
 * Sets up the ChaCha20 state matrix with the constant, key, nonce, and counter.
 * The state layout is:
 *   Row 0: Constants "expand 32-byte k"
 *   Row 1-2: 256-bit key
 *   Row 3: Counter + 96-bit nonce
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param key 256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param counter Initial block counter
 */
void chacha20_init(chacha20_ctx *ctx, 
                   const uint8_t key[32],
                   const uint8_t nonce[12],
                   uint32_t counter) {
    // ChaCha20 constants: "expand 32-byte k" in little-endian
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    
    // Load 256-bit key (8 x 32-bit words)
    ctx->state[4] = load_le32(key + 0);
    ctx->state[5] = load_le32(key + 4);
    ctx->state[6] = load_le32(key + 8);
    ctx->state[7] = load_le32(key + 12);
    ctx->state[8] = load_le32(key + 16);
    ctx->state[9] = load_le32(key + 20);
    ctx->state[10] = load_le32(key + 24);
    ctx->state[11] = load_le32(key + 28);
    
    // Set counter
    ctx->state[12] = counter;
    ctx->counter = counter;
    
    // Load 96-bit nonce (3 x 32-bit words)
    ctx->state[13] = load_le32(nonce + 0);
    ctx->state[14] = load_le32(nonce + 4);
    ctx->state[15] = load_le32(nonce + 8);
    
    // Save initial state for later addition
    memcpy(ctx->initial, ctx->state, sizeof(ctx->state));
}

/**
 * @brief Generate one 64-byte ChaCha20 keystream block
 * 
 * Performs 20 rounds (10 double rounds) of ChaCha20 operations,
 * then adds the initial state to produce the final keystream block.
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param output Output buffer for 64-byte keystream block
 */
void chacha20_block(chacha20_ctx *ctx, uint8_t output[64]) {
    uint32_t working_state[16];
    
    // Copy current state to working state
    memcpy(working_state, ctx->state, sizeof(working_state));
    
    // Perform 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column round
        quarter_round(&working_state[0], &working_state[4], &working_state[8],  &working_state[12]);
        quarter_round(&working_state[1], &working_state[5], &working_state[9],  &working_state[13]);
        quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        
        // Diagonal round
        quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        quarter_round(&working_state[2], &working_state[7], &working_state[8],  &working_state[13]);
        quarter_round(&working_state[3], &working_state[4], &working_state[9],  &working_state[14]);
    }
    
    // Add initial state to working state and serialize to output
    for (int i = 0; i < 16; i++) {
        uint32_t result = working_state[i] + ctx->state[i];
        store_le32(output + (i * 4), result);
    }
    
    // Increment counter for next block
    ctx->state[12]++;
    ctx->counter++;
}

/**
 * @brief Encrypt or decrypt data using ChaCha20
 * 
 * ChaCha20 is a stream cipher, so encryption and decryption are the same operation.
 * This function XORs the input data with the ChaCha20 keystream.
 * Handles arbitrary length messages, including incomplete blocks.
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param data Data buffer to encrypt/decrypt (in-place)
 * @param len Length of data in bytes
 */
void chacha20_crypt(chacha20_ctx *ctx, uint8_t *data, size_t len) {
    uint8_t keystream[64];
    size_t offset = 0;
    
    while (len > 0) {
        // Generate one block of keystream
        chacha20_block(ctx, keystream);
        
        // Determine how many bytes to process from this block
        size_t block_len = (len < 64) ? len : 64;
        
        // XOR data with keystream
        for (size_t i = 0; i < block_len; i++) {
            data[offset + i] ^= keystream[i];
        }
        
        offset += block_len;
        len -= block_len;
    }
    
    // Clear keystream from memory for security
    secure_zero(keystream, sizeof(keystream));
}
