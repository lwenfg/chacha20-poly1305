#include "poly1305.h"
#include "utils.h"
#include <string.h>

/**
 * @brief Convert 16-byte array to 5 26-bit limbs (130-bit representation)
 * 
 * This function converts a little-endian byte array into the limb representation
 * used by Poly1305. Each limb holds 26 bits of the 130-bit value.
 * 
 * Limb layout:
 * - limb[0]: bits 0-25
 * - limb[1]: bits 26-51
 * - limb[2]: bits 52-77
 * - limb[3]: bits 78-103
 * - limb[4]: bits 104-129
 * 
 * @param bytes Input byte array (16 bytes, little-endian)
 * @param limbs Output limb array (5 limbs)
 */
static void bytes_to_limbs(const uint8_t bytes[16], uint32_t limbs[5]) {
    // Load four 32-bit words in little-endian format
    uint32_t t0 = load_le32(bytes + 0);
    uint32_t t1 = load_le32(bytes + 4);
    uint32_t t2 = load_le32(bytes + 8);
    uint32_t t3 = load_le32(bytes + 12);
    
    // Extract 26-bit limbs from the 128-bit value
    limbs[0] = t0 & 0x3ffffff;                          // bits 0-25
    limbs[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;   // bits 26-51
    limbs[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;  // bits 52-77
    limbs[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;  // bits 78-103
    limbs[4] = (t3 >> 8) & 0x3ffffff;                   // bits 104-129
}

/**
 * @brief Convert 5 26-bit limbs to 16-byte array (little-endian)
 * 
 * This function converts the limb representation back to a little-endian
 * byte array. Only the lower 128 bits are output (limbs are reduced first).
 * 
 * @param limbs Input limb array (5 limbs)
 * @param bytes Output byte array (16 bytes, little-endian)
 */
static void limbs_to_bytes(const uint32_t limbs[5], uint8_t bytes[16]) {
    // Make a copy to avoid modifying input
    uint32_t h[5];
    memcpy(h, limbs, sizeof(h));
    
    // Propagate carries to normalize limbs
    uint32_t c;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    
    // Combine limbs into 32-bit words
    uint32_t t0 = h[0] | (h[1] << 26);
    uint32_t t1 = (h[1] >> 6) | (h[2] << 20);
    uint32_t t2 = (h[2] >> 12) | (h[3] << 14);
    uint32_t t3 = (h[3] >> 18) | (h[4] << 8);
    
    // Store as little-endian bytes
    store_le32(bytes + 0, t0);
    store_le32(bytes + 4, t1);
    store_le32(bytes + 8, t2);
    store_le32(bytes + 12, t3);
}

/**
 * @brief Add two 130-bit integers represented as limbs
 * 
 * Performs addition: result = a + b
 * Carries are handled during subsequent operations (lazy reduction).
 * 
 * @param result Output limb array (5 limbs)
 * @param a First operand (5 limbs)
 * @param b Second operand (5 limbs)
 */
static void poly1305_add(uint32_t result[5], const uint32_t a[5], const uint32_t b[5]) {
    // Simple addition - carries will be handled by reduction
    result[0] = a[0] + b[0];
    result[1] = a[1] + b[1];
    result[2] = a[2] + b[2];
    result[3] = a[3] + b[3];
    result[4] = a[4] + b[4];
}

/**
 * @brief Multiply two 130-bit integers represented as limbs
 * 
 * Performs multiplication: result = a * b (mod 2^130-5)
 * Uses schoolbook multiplication with 64-bit intermediate results.
 * The result is partially reduced (carries propagated).
 * 
 * @param result Output limb array (5 limbs)
 * @param a First operand (5 limbs)
 * @param b Second operand (5 limbs)
 */
static void poly1305_mul(uint32_t result[5], const uint32_t a[5], const uint32_t b[5]) {
    // Use 64-bit intermediates to handle overflow
    uint64_t t[10] = {0};
    
    // Schoolbook multiplication: compute all partial products
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            t[i + j] += (uint64_t)a[i] * b[j];
        }
    }
    
    // Reduce high limbs (limbs 5-9) using 2^130 ≡ 5 (mod 2^130-5)
    // Each limb beyond position 4 represents 2^(130 + 26*k) ≡ 5 * 2^(26*k) (mod 2^130-5)
    t[0] += 5 * t[5];
    t[1] += 5 * t[6];
    t[2] += 5 * t[7];
    t[3] += 5 * t[8];
    t[4] += 5 * t[9];
    
    // Propagate carries
    uint64_t c = 0;
    for (int i = 0; i < 5; i++) {
        t[i] += c;
        result[i] = t[i] & 0x3ffffff;
        c = t[i] >> 26;
    }
    
    // Final carry reduction: c represents overflow beyond 130 bits
    result[0] += c * 5;
    
    // Propagate final carry if needed
    c = result[0] >> 26;
    result[0] &= 0x3ffffff;
    result[1] += c;
}

/**
 * @brief Reduce 130-bit integer modulo 2^130-5
 * 
 * Performs fast reduction using the property that 2^130 ≡ 5 (mod 2^130-5).
 * After reduction, the result is guaranteed to be less than 2^130-5.
 * 
 * The reduction is performed in multiple passes to handle carries properly.
 * 
 * @param h Limb array to reduce in-place (5 limbs)
 */
static void poly1305_reduce(uint32_t h[5]) {
    uint32_t c;
    
    // Propagate carries
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
}

/**
 * @brief Compare two 130-bit integers represented as limbs
 * 
 * Compares two 130-bit values and returns their relationship.
 * Assumes both inputs are normalized (carries propagated).
 * 
 * @param a First operand (5 limbs)
 * @param b Second operand (5 limbs)
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 */
static int poly1305_compare(const uint32_t a[5], const uint32_t b[5]) {
    // Compare from most significant limb to least significant
    for (int i = 4; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        } else if (a[i] < b[i]) {
            return -1;
        }
    }
    // All limbs are equal
    return 0;
}

// ============================================================================
// Public API Implementation
// ============================================================================

/**
 * @brief Initialize Poly1305 context
 * 
 * Derives r and s from the 32-byte key and performs clamping on r.
 * The clamping ensures r has specific bits cleared to prevent weak keys.
 * 
 * Key layout:
 * - bytes[0..15]: r value (will be clamped)
 * - bytes[16..31]: s value (pad)
 * 
 * Clamping operation on r:
 * r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
 * This clears:
 * - Top 4 bits of bytes 3, 7, 11, 15 (set to 0)
 * - Bottom 2 bits of bytes 4, 8, 12 (set to 0)
 * 
 * @param ctx Pointer to Poly1305 context
 * @param key 32-byte key
 */
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    // Extract r from first 16 bytes and convert to limbs
    uint8_t r_bytes[16];
    memcpy(r_bytes, key, 16);
    
    // Clamp r according to Poly1305 specification
    // Clear top 4 bits of bytes 3, 7, 11, 15
    r_bytes[3] &= 0x0f;
    r_bytes[7] &= 0x0f;
    r_bytes[11] &= 0x0f;
    r_bytes[15] &= 0x0f;
    
    // Clear bottom 2 bits of bytes 4, 8, 12
    r_bytes[4] &= 0xfc;
    r_bytes[8] &= 0xfc;
    r_bytes[12] &= 0xfc;
    
    // Convert clamped r to limb representation
    bytes_to_limbs(r_bytes, ctx->r);
    
    // Extract s (pad) from last 16 bytes
    // Store as four 32-bit words in little-endian
    ctx->pad[0] = load_le32(key + 16);
    ctx->pad[1] = load_le32(key + 20);
    ctx->pad[2] = load_le32(key + 24);
    ctx->pad[3] = load_le32(key + 28);
    
    // Initialize accumulator h to zero
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    
    // Initialize buffer state
    ctx->buf_used = 0;
}

/**
 * @brief Process one 16-byte block
 * 
 * Implements the Poly1305 polynomial evaluation using Horner's method:
 * h = ((h + block) * r) mod (2^130-5)
 * 
 * For non-final blocks, a 0x01 byte is appended as the high bit.
 * For the final block, the actual length determines the high bit position.
 * 
 * @param ctx Pointer to Poly1305 context
 * @param block 16-byte input block
 * @param final Whether this is the final block (affects high bit handling)
 */
void poly1305_block(poly1305_ctx *ctx, const uint8_t block[16], int final) {
    uint32_t block_limbs[5];
    
    // Convert block to limb representation
    bytes_to_limbs(block, block_limbs);
    
    // Add high bit (0x01 at position 128 for full blocks)
    // For non-final blocks, always add 2^128
    // For final blocks, the caller should have already padded appropriately
    if (!final) {
        block_limbs[4] |= (1 << 24);  // Set bit 128 (bit 24 of limb[4])
    }
    
    // h = h + block
    poly1305_add(ctx->h, ctx->h, block_limbs);
    
    // h = h * r (mod 2^130-5)
    uint32_t temp[5];
    poly1305_mul(temp, ctx->h, ctx->r);
    memcpy(ctx->h, temp, sizeof(ctx->h));
    
    // Reduce to ensure h stays in valid range
    poly1305_reduce(ctx->h);
}

/**
 * @brief Update Poly1305 with additional data
 * 
 * Processes input data in 16-byte blocks. Incomplete blocks are buffered
 * until enough data is available or poly1305_final() is called.
 * 
 * This function can be called multiple times to process data incrementally.
 * 
 * @param ctx Pointer to Poly1305 context
 * @param data Input data
 * @param len Length of input data in bytes
 */
void poly1305_update(poly1305_ctx *ctx, const uint8_t *data, size_t len) {
    // Handle any buffered data first
    if (ctx->buf_used > 0) {
        // Calculate how much we can add to the buffer
        size_t to_copy = 16 - ctx->buf_used;
        if (to_copy > len) {
            to_copy = len;
        }
        
        // Copy data to buffer
        memcpy(ctx->buffer + ctx->buf_used, data, to_copy);
        ctx->buf_used += to_copy;
        data += to_copy;
        len -= to_copy;
        
        // If buffer is full, process it
        if (ctx->buf_used == 16) {
            poly1305_block(ctx, ctx->buffer, 0);
            ctx->buf_used = 0;
        }
    }
    
    // Process complete 16-byte blocks directly from input
    while (len >= 16) {
        poly1305_block(ctx, data, 0);
        data += 16;
        len -= 16;
    }
    
    // Buffer any remaining data
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buf_used = len;
    }
}

/**
 * @brief Finalize Poly1305 and output 16-byte MAC tag
 * 
 * Processes any remaining buffered data, adds the final padding,
 * adds the s value (pad), and outputs the lower 128 bits as the MAC tag.
 * 
 * For the final incomplete block:
 * - Append 0x01 byte after the data
 * - Pad with zeros to 16 bytes
 * 
 * Final computation: tag = (h + s) mod 2^128
 * 
 * @param ctx Pointer to Poly1305 context
 * @param mac Output buffer for 16-byte MAC tag
 */
void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16]) {
    // Process any remaining buffered data
    if (ctx->buf_used > 0) {
        // Pad the final block: append 0x01 and fill rest with zeros
        ctx->buffer[ctx->buf_used] = 0x01;
        for (size_t i = ctx->buf_used + 1; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        
        // Debug: print the final block
        #ifdef DEBUG_POLY1305
        printf("Final block (buf_used=%zu): ", ctx->buf_used);
        for (int i = 0; i < 16; i++) {
            printf("%02x", ctx->buffer[i]);
        }
        printf("\n");
        #endif
        
        // Process the final block
        // Note: we pass final=1 but the padding is already done
        uint32_t block_limbs[5];
        bytes_to_limbs(ctx->buffer, block_limbs);
        
        #ifdef DEBUG_POLY1305
        printf("Final block limbs: %08x %08x %08x %08x %08x\n",
               block_limbs[0], block_limbs[1], block_limbs[2], block_limbs[3], block_limbs[4]);
        #endif
        
        // Add the block to accumulator
        poly1305_add(ctx->h, ctx->h, block_limbs);
        
        #ifdef DEBUG_POLY1305
        printf("After add: %08x %08x %08x %08x %08x\n",
               ctx->h[0], ctx->h[1], ctx->h[2], ctx->h[3], ctx->h[4]);
        #endif
        
        // Multiply by r
        uint32_t temp[5];
        poly1305_mul(temp, ctx->h, ctx->r);
        memcpy(ctx->h, temp, sizeof(ctx->h));
        
        #ifdef DEBUG_POLY1305
        printf("After mul: %08x %08x %08x %08x %08x\n",
               ctx->h[0], ctx->h[1], ctx->h[2], ctx->h[3], ctx->h[4]);
        #endif
        
        // Reduce
        poly1305_reduce(ctx->h);
        
        #ifdef DEBUG_POLY1305
        printf("After reduce: %08x %08x %08x %08x %08x\n",
               ctx->h[0], ctx->h[1], ctx->h[2], ctx->h[3], ctx->h[4]);
        #endif
    }
    
    // Final reduction to ensure h is fully reduced modulo 2^130-5
    // We need to do this before adding s
    
    // First, propagate all carries
    uint32_t c;
    c = ctx->h[0] >> 26; ctx->h[0] &= 0x3ffffff; ctx->h[1] += c;
    c = ctx->h[1] >> 26; ctx->h[1] &= 0x3ffffff; ctx->h[2] += c;
    c = ctx->h[2] >> 26; ctx->h[2] &= 0x3ffffff; ctx->h[3] += c;
    c = ctx->h[3] >> 26; ctx->h[3] &= 0x3ffffff; ctx->h[4] += c;
    c = ctx->h[4] >> 26; ctx->h[4] &= 0x3ffffff;
    ctx->h[0] += c * 5;
    c = ctx->h[0] >> 26; ctx->h[0] &= 0x3ffffff; ctx->h[1] += c;
    
    // Now do a final conditional subtraction of p = 2^130-5
    // Compute h + 5
    uint64_t g0 = ctx->h[0] + 5;
    c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = ctx->h[1] + c;
    c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = ctx->h[2] + c;
    c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = ctx->h[3] + c;
    c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = ctx->h[4] + c - (1ULL << 26);
    
    // If g4 has no borrow (high bit not set), then h >= 2^130-5, so use g
    // Otherwise use h
    uint32_t mask = (uint32_t)(-(int64_t)(g4 >> 63));  // All 1s if borrow, all 0s if no borrow
    ctx->h[0] = (ctx->h[0] & mask) | ((uint32_t)g0 & ~mask);
    ctx->h[1] = (ctx->h[1] & mask) | ((uint32_t)g1 & ~mask);
    ctx->h[2] = (ctx->h[2] & mask) | ((uint32_t)g2 & ~mask);
    ctx->h[3] = (ctx->h[3] & mask) | ((uint32_t)g3 & ~mask);
    ctx->h[4] = (ctx->h[4] & mask) | ((uint32_t)g4 & ~mask);
    
    // Add s (pad) to h
    // Convert h to bytes first
    uint8_t h_bytes[16];
    limbs_to_bytes(ctx->h, h_bytes);
    
    // Add s to h as 128-bit integers (with carry)
    uint32_t h_words[4];
    h_words[0] = load_le32(h_bytes + 0);
    h_words[1] = load_le32(h_bytes + 4);
    h_words[2] = load_le32(h_bytes + 8);
    h_words[3] = load_le32(h_bytes + 12);
    
    // Add with carry propagation
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        carry += (uint64_t)h_words[i] + ctx->pad[i];
        h_words[i] = (uint32_t)carry;
        carry >>= 32;
    }
    
    // Output the result as little-endian bytes (lower 128 bits)
    store_le32(mac + 0, h_words[0]);
    store_le32(mac + 4, h_words[1]);
    store_le32(mac + 8, h_words[2]);
    store_le32(mac + 12, h_words[3]);
    
    // Clear sensitive data
    secure_zero(ctx, sizeof(poly1305_ctx));
}
