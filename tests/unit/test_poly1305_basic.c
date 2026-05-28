#include "poly1305.h"
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

// RFC 8439 Test Vector for Poly1305
TEST(test_poly1305_rfc8439) {
    // Test vector from RFC 8439 Section 2.5.2
    uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    
    uint8_t message[] = "Cryptographic Forum Research Group";
    size_t msg_len = strlen((char*)message);
    
    uint8_t expected_tag[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };
    
    uint8_t tag[16];
    
    poly1305_ctx ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, message, msg_len);
    poly1305_final(&ctx, tag);
    
    ASSERT_BYTES_EQUAL(expected_tag, tag, 16);
}

// Test empty message
TEST(test_poly1305_empty) {
    uint8_t key[32] = {0};
    uint8_t tag[16];
    
    poly1305_ctx ctx;
    poly1305_init(&ctx, key);
    poly1305_final(&ctx, tag);
    
    // With zero key and empty message, tag should be zero
    uint8_t expected[16] = {0};
    ASSERT_BYTES_EQUAL(expected, tag, 16);
}

// Test single byte message
TEST(test_poly1305_single_byte) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    uint8_t message[1] = {0x42};
    uint8_t tag[16];
    
    poly1305_ctx ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, message, 1);
    poly1305_final(&ctx, tag);
    
    // Just verify it doesn't crash and produces some output
    int all_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (tag[i] != 0) all_zero = 0;
    }
    ASSERT(!all_zero); // Tag should not be all zeros with non-zero key
}

// Test incremental update
TEST(test_poly1305_incremental) {
    uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    
    uint8_t message[] = "Cryptographic Forum Research Group";
    size_t msg_len = strlen((char*)message);
    
    // Compute tag in one go
    uint8_t tag1[16];
    poly1305_ctx ctx1;
    poly1305_init(&ctx1, key);
    poly1305_update(&ctx1, message, msg_len);
    poly1305_final(&ctx1, tag1);
    
    // Compute tag incrementally
    uint8_t tag2[16];
    poly1305_ctx ctx2;
    poly1305_init(&ctx2, key);
    poly1305_update(&ctx2, message, 10);
    poly1305_update(&ctx2, message + 10, msg_len - 10);
    poly1305_final(&ctx2, tag2);
    
    ASSERT_BYTES_EQUAL(tag1, tag2, 16);
}

int test_poly1305_basic(void) {
    printf("=== Poly1305 Basic Tests ===\n\n");
    
    tests_run = 0;
    tests_passed = 0;
    
    run_test_poly1305_rfc8439();
    run_test_poly1305_empty();
    run_test_poly1305_single_byte();
    run_test_poly1305_incremental();
    
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    
    return (tests_run == tests_passed) ? 0 : 1;
}
