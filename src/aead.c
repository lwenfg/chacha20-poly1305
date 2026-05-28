#include "chacha20poly1305.h"
#include "utils.h"
#include <string.h>

/**
 * @brief Derive Poly1305 key using ChaCha20 with counter=0
 * 
 * According to RFC 8439, the Poly1305 key is derived by running ChaCha20
 * with counter=0 and taking the first 32 bytes of output.
 * 
 * @param key ChaCha20 key (32 bytes)
 * @param nonce ChaCha20 nonce (12 bytes)
 * @param poly_key Output buffer for Poly1305 key (32 bytes)
 */
static void derive_poly1305_key(const uint8_t key[32], 
                                const uint8_t nonce[12],
                                uint8_t poly_key[32]) {
    chacha20_ctx ctx;
    uint8_t block[64];
    
    // Initialize ChaCha20 with counter=0
    chacha20_init(&ctx, key, nonce, 0);
    
    // Generate one block
    chacha20_block(&ctx, block);
    
    // Take first 32 bytes as Poly1305 key
    memcpy(poly_key, block, 32);
    
    // Clear the block for security
    secure_zero(block, sizeof(block));
}

/**
 * @brief Pad to 16-byte boundary
 * 
 * @param len Current length
 * @return Number of padding bytes needed
 */
static size_t pad16(size_t len) {
    size_t remainder = len % 16;
    return (remainder == 0) ? 0 : (16 - remainder);
}

/**
 * @brief Store 64-bit integer as little-endian bytes
 * 
 * @param p Output buffer (8 bytes)
 * @param v Value to store
 */
static void store_le64(uint8_t *p, uint64_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
    p[4] = (v >> 32) & 0xff;
    p[5] = (v >> 40) & 0xff;
    p[6] = (v >> 48) & 0xff;
    p[7] = (v >> 56) & 0xff;
}

/**
 * @brief Construct Poly1305 input according to RFC 8439
 * 
 * The input format is:
 *   AAD || pad16(AAD) || 
 *   Ciphertext || pad16(Ciphertext) ||
 *   len(AAD) as uint64_le || len(Ciphertext) as uint64_le
 * 
 * @param poly_ctx Poly1305 context to update
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD
 * @param ciphertext Ciphertext data
 * @param ciphertext_len Length of ciphertext
 */
static void construct_poly1305_input(poly1305_ctx *poly_ctx,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ciphertext_len) {
    uint8_t padding[16] = {0};
    uint8_t length_block[16];
    
    // Add AAD
    if (aad_len > 0) {
        poly1305_update(poly_ctx, aad, aad_len);
        
        // Add padding for AAD
        size_t aad_pad = pad16(aad_len);
        if (aad_pad > 0) {
            poly1305_update(poly_ctx, padding, aad_pad);
        }
    }
    
    // Add ciphertext
    if (ciphertext_len > 0) {
        poly1305_update(poly_ctx, ciphertext, ciphertext_len);
        
        // Add padding for ciphertext
        size_t ct_pad = pad16(ciphertext_len);
        if (ct_pad > 0) {
            poly1305_update(poly_ctx, padding, ct_pad);
        }
    }
    
    // Add lengths as 64-bit little-endian integers
    store_le64(length_block, (uint64_t)aad_len);
    store_le64(length_block + 8, (uint64_t)ciphertext_len);
    poly1305_update(poly_ctx, length_block, 16);
}

/**
 * @brief AEAD encryption with ChaCha20-Poly1305
 * 
 * Implements RFC 8439 AEAD encryption:
 * 1. Derive Poly1305 key using ChaCha20 with counter=0
 * 2. Encrypt plaintext using ChaCha20 starting with counter=1
 * 3. Compute Poly1305 MAC over AAD and ciphertext
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD in bytes
 * @param plaintext Plaintext input (can be NULL if plaintext_len is 0)
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext Output buffer for ciphertext (same length as plaintext)
 * @param tag Output buffer for 16-byte authentication tag
 * @return Error code
 */
int chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
) {
    // Validate required pointers
    if (key == NULL || nonce == NULL || tag == NULL) {
        return CHACHA20POLY1305_ERROR_NULL_POINTER;
    }
    
    // Validate data pointers if lengths are non-zero
    if ((aad_len > 0 && aad == NULL) || 
        (plaintext_len > 0 && (plaintext == NULL || ciphertext == NULL))) {
        return CHACHA20POLY1305_ERROR_NULL_POINTER;
    }
    
    chacha20_ctx chacha_ctx;
    poly1305_ctx poly_ctx;
    uint8_t poly_key[32];
    
    // Step 1: Derive Poly1305 key using counter=0
    derive_poly1305_key(key, nonce, poly_key);
    
    // Step 2: Encrypt plaintext using counter=1
    if (plaintext_len > 0) {
        // Copy plaintext to ciphertext buffer
        memcpy(ciphertext, plaintext, plaintext_len);
        
        // Initialize ChaCha20 with counter=1
        chacha20_init(&chacha_ctx, key, nonce, 1);
        
        // Encrypt in-place
        chacha20_crypt(&chacha_ctx, ciphertext, plaintext_len);
        
        // Clear ChaCha20 context
        secure_zero(&chacha_ctx, sizeof(chacha_ctx));
    }
    
    // Step 3: Compute Poly1305 MAC
    poly1305_init(&poly_ctx, poly_key);
    construct_poly1305_input(&poly_ctx, aad, aad_len, ciphertext, plaintext_len);
    poly1305_final(&poly_ctx, tag);
    
    // Clear sensitive data
    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(&poly_ctx, sizeof(poly_ctx));
    
    return CHACHA20POLY1305_OK;
}

/**
 * @brief AEAD decryption with ChaCha20-Poly1305
 * 
 * Implements RFC 8439 AEAD decryption:
 * 1. Derive Poly1305 key using ChaCha20 with counter=0
 * 2. Compute Poly1305 MAC over AAD and ciphertext
 * 3. Verify tag in constant time
 * 4. Only decrypt if tag verification succeeds
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD in bytes
 * @param ciphertext Ciphertext input (can be NULL if ciphertext_len is 0)
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Output buffer for plaintext (same length as ciphertext)
 * @return CHACHA20POLY1305_OK on success, 
 *         CHACHA20POLY1305_ERROR_AUTH_FAILED if tag verification fails
 */
int chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext
) {
    // Validate required pointers
    if (key == NULL || nonce == NULL || tag == NULL) {
        return CHACHA20POLY1305_ERROR_NULL_POINTER;
    }
    
    // Validate data pointers if lengths are non-zero
    if ((aad_len > 0 && aad == NULL) || 
        (ciphertext_len > 0 && (ciphertext == NULL || plaintext == NULL))) {
        return CHACHA20POLY1305_ERROR_NULL_POINTER;
    }
    
    chacha20_ctx chacha_ctx;
    poly1305_ctx poly_ctx;
    uint8_t poly_key[32];
    uint8_t computed_tag[16];
    
    // Step 1: Derive Poly1305 key using counter=0
    derive_poly1305_key(key, nonce, poly_key);
    
    // Step 2: Compute Poly1305 MAC over AAD and ciphertext
    poly1305_init(&poly_ctx, poly_key);
    construct_poly1305_input(&poly_ctx, aad, aad_len, ciphertext, ciphertext_len);
    poly1305_final(&poly_ctx, computed_tag);
    
    // Step 3: Verify tag in constant time
    if (!secure_compare(tag, computed_tag, 16)) {
        // Tag verification failed - clear everything and return error
        secure_zero(poly_key, sizeof(poly_key));
        secure_zero(&poly_ctx, sizeof(poly_ctx));
        secure_zero(computed_tag, sizeof(computed_tag));
        
        // Zero the plaintext buffer to ensure no data leaks
        if (ciphertext_len > 0 && plaintext != NULL) {
            secure_zero(plaintext, ciphertext_len);
        }
        
        return CHACHA20POLY1305_ERROR_AUTH_FAILED;
    }
    
    // Step 4: Tag verified - now decrypt the ciphertext
    if (ciphertext_len > 0) {
        // Copy ciphertext to plaintext buffer
        memcpy(plaintext, ciphertext, ciphertext_len);
        
        // Initialize ChaCha20 with counter=1
        chacha20_init(&chacha_ctx, key, nonce, 1);
        
        // Decrypt in-place
        chacha20_crypt(&chacha_ctx, plaintext, ciphertext_len);
        
        // Clear ChaCha20 context
        secure_zero(&chacha_ctx, sizeof(chacha_ctx));
    }
    
    // Clear sensitive data
    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(&poly_ctx, sizeof(poly_ctx));
    secure_zero(computed_tag, sizeof(computed_tag));
    
    return CHACHA20POLY1305_OK;
}
