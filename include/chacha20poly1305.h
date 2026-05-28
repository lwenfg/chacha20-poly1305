#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include "chacha20.h"
#include "poly1305.h"

/**
 * @brief Error codes for ChaCha20-Poly1305 operations
 */
typedef enum {
    CHACHA20POLY1305_OK = 0,
    CHACHA20POLY1305_ERROR_NULL_POINTER,
    CHACHA20POLY1305_ERROR_INVALID_LENGTH,
    CHACHA20POLY1305_ERROR_AUTH_FAILED,
    CHACHA20POLY1305_ERROR_INVALID_KEY,
    CHACHA20POLY1305_ERROR_INVALID_NONCE,
    CHACHA20POLY1305_ERROR_FILE_IO,
    CHACHA20POLY1305_ERROR_MEMORY
} chacha20poly1305_error_t;

/**
 * @brief ChaCha20-Poly1305 AEAD context
 */
typedef struct {
    chacha20_ctx chacha_ctx;
    poly1305_ctx poly_ctx;
    uint8_t poly_key[32];
} chacha20poly1305_ctx;

/**
 * @brief AEAD encryption with ChaCha20-Poly1305
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD in bytes
 * @param plaintext Plaintext input
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
);

/**
 * @brief AEAD decryption with ChaCha20-Poly1305
 * 
 * @param key 256-bit key (32 bytes)
 * @param nonce 96-bit nonce (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of AAD in bytes
 * @param ciphertext Ciphertext input
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Output buffer for plaintext (same length as ciphertext)
 * @return Error code (CHACHA20POLY1305_OK on success, 
 *         CHACHA20POLY1305_ERROR_AUTH_FAILED if tag verification fails)
 */
int chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

#endif // CHACHA20POLY1305_H
