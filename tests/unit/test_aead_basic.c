#include "chacha20poly1305.h"
#include <stdio.h>
#include <string.h>

// Simple test framework
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        printf("Running %s...", #name); \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf(" PASSED\n"); \
    } \
    static void name(void)

#define ASSERT(condition) \
    do { \
        if (!(condition)) { \
            printf("\n  FAILED: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return; \
        } \
    } while(0)

#define ASSERT_BYTES_EQUAL(expected, actual, len) \
    do { \
        if (memcmp(expected, actual, len) != 0) { \
            printf("\n  FAILED: %s:%d: bytes not equal\n", __FILE__, __LINE__); \
            printf("  Expected: "); \
            for (size_t i = 0; i < len; i++) printf("%02x", (expected)[i]); \
            printf("\n  Actual:   "); \
            for (size_t i = 0; i < len; i++) printf("%02x", (actual)[i]); \
            printf("\n"); \
            return; \
        } \
    } while(0)

// Test basic encryption and decryption round-trip
TEST(test_aead_roundtrip) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    // Initialize key and nonce
    for (int i = 0; i < 32; i++) key[i] = i;
    for (int i = 0; i < 12; i++) nonce[i] = i;
    
    uint8_t plaintext[] = "Hello, ChaCha20-Poly1305!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[100];
    uint8_t tag[16];
    uint8_t decrypted[100];
    
    // Encrypt
    int result = chacha20poly1305_encrypt(
        key, nonce,
        NULL, 0,  // No AAD
        plaintext, plaintext_len,
        ciphertext, tag
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Decrypt
    result = chacha20poly1305_decrypt(
        key, nonce,
        NULL, 0,  // No AAD
        ciphertext, plaintext_len,
        tag, decrypted
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Verify plaintext matches
    ASSERT_BYTES_EQUAL(plaintext, decrypted, plaintext_len);
}

// Test with AAD
TEST(test_aead_with_aad) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = i;
    for (int i = 0; i < 12; i++) nonce[i] = i + 32;
    
    uint8_t aad[] = "Additional authenticated data";
    size_t aad_len = strlen((char*)aad);
    
    uint8_t plaintext[] = "Secret message";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[100];
    uint8_t tag[16];
    uint8_t decrypted[100];
    
    // Encrypt with AAD
    int result = chacha20poly1305_encrypt(
        key, nonce,
        aad, aad_len,
        plaintext, plaintext_len,
        ciphertext, tag
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Decrypt with AAD
    result = chacha20poly1305_decrypt(
        key, nonce,
        aad, aad_len,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Verify plaintext matches
    ASSERT_BYTES_EQUAL(plaintext, decrypted, plaintext_len);
}

// Test authentication failure with wrong tag
TEST(test_aead_auth_failure) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = i;
    for (int i = 0; i < 12; i++) nonce[i] = i;
    
    uint8_t plaintext[] = "Test message";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[100];
    uint8_t tag[16];
    uint8_t decrypted[100];
    
    // Encrypt
    int result = chacha20poly1305_encrypt(
        key, nonce,
        NULL, 0,
        plaintext, plaintext_len,
        ciphertext, tag
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Corrupt the tag
    tag[0] ^= 0x01;
    
    // Decrypt should fail
    result = chacha20poly1305_decrypt(
        key, nonce,
        NULL, 0,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    ASSERT(result == CHACHA20POLY1305_ERROR_AUTH_FAILED);
}

// Test authentication failure with wrong AAD
TEST(test_aead_wrong_aad) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = i;
    for (int i = 0; i < 12; i++) nonce[i] = i;
    
    uint8_t aad1[] = "AAD version 1";
    uint8_t aad2[] = "AAD version 2";
    size_t aad_len = strlen((char*)aad1);
    
    uint8_t plaintext[] = "Test message";
    size_t plaintext_len = strlen((char*)plaintext);
    
    uint8_t ciphertext[100];
    uint8_t tag[16];
    uint8_t decrypted[100];
    
    // Encrypt with aad1
    int result = chacha20poly1305_encrypt(
        key, nonce,
        aad1, aad_len,
        plaintext, plaintext_len,
        ciphertext, tag
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Try to decrypt with aad2 (should fail)
    result = chacha20poly1305_decrypt(
        key, nonce,
        aad2, aad_len,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    ASSERT(result == CHACHA20POLY1305_ERROR_AUTH_FAILED);
}

// Test empty message
TEST(test_aead_empty_message) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = i;
    for (int i = 0; i < 12; i++) nonce[i] = i;
    
    uint8_t tag[16];
    
    // Encrypt empty message
    int result = chacha20poly1305_encrypt(
        key, nonce,
        NULL, 0,
        NULL, 0,
        NULL, tag
    );
    ASSERT(result == CHACHA20POLY1305_OK);
    
    // Decrypt empty message
    result = chacha20poly1305_decrypt(
        key, nonce,
        NULL, 0,
        NULL, 0,
        tag, NULL
    );
    ASSERT(result == CHACHA20POLY1305_OK);
}

// Test null pointer validation
TEST(test_aead_null_pointers) {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t plaintext[10];
    uint8_t ciphertext[10];
    uint8_t tag[16];
    
    // Null key should fail
    int result = chacha20poly1305_encrypt(
        NULL, nonce,
        NULL, 0,
        plaintext, 10,
        ciphertext, tag
    );
    ASSERT(result == CHACHA20POLY1305_ERROR_NULL_POINTER);
    
    // Null nonce should fail
    result = chacha20poly1305_encrypt(
        key, NULL,
        NULL, 0,
        plaintext, 10,
        ciphertext, tag
    );
    ASSERT(result == CHACHA20POLY1305_ERROR_NULL_POINTER);
    
    // Null tag should fail
    result = chacha20poly1305_encrypt(
        key, nonce,
        NULL, 0,
        plaintext, 10,
        ciphertext, NULL
    );
    ASSERT(result == CHACHA20POLY1305_ERROR_NULL_POINTER);
}

int test_aead_basic(void) {
    printf("=== ChaCha20-Poly1305 AEAD Basic Tests ===\n\n");
    
    tests_run = 0;
    tests_passed = 0;
    
    run_test_aead_roundtrip();
    run_test_aead_with_aad();
    run_test_aead_auth_failure();
    run_test_aead_wrong_aad();
    run_test_aead_empty_message();
    run_test_aead_null_pointers();
    
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    
    return (tests_run == tests_passed) ? 0 : 1;
}
