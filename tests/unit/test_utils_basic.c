/**
 * @file test_utils_basic.c
 * @brief Basic unit tests for utility functions
 * 
 * Tests the utility functions including:
 * - Little-endian load/store operations
 * - 32-bit rotation operations
 * - Secure memory zeroing
 * - Constant-time comparison
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "utils.h"

/**
 * @brief Test load_le32 and store_le32 functions
 */
void test_endian_conversion(void) {
    printf("Testing endian conversion functions...\n");
    
    // Test 1: Basic round-trip
    uint8_t bytes[4] = {0x12, 0x34, 0x56, 0x78};
    uint32_t value = load_le32(bytes);
    
    // Little-endian: 0x78563412
    assert(value == 0x78563412);
    
    // Test 2: Store and verify
    uint8_t output[4];
    store_le32(output, value);
    assert(memcmp(bytes, output, 4) == 0);
    
    // Test 3: Zero value
    uint8_t zeros[4] = {0, 0, 0, 0};
    assert(load_le32(zeros) == 0);
    
    // Test 4: Max value
    uint8_t max_bytes[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    assert(load_le32(max_bytes) == 0xFFFFFFFF);
    
    printf("  ✓ Endian conversion tests passed\n");
}

/**
 * @brief Test rotl32 function
 */
void test_rotl32(void) {
    printf("Testing 32-bit rotation functions...\n");
    
    // Test 1: Rotate 0x12345678 left by 8 bits
    uint32_t x = 0x12345678;
    uint32_t result = rotl32(x, 8);
    assert(result == 0x34567812);
    
    // Test 2: Rotate by 0 (no change)
    assert(rotl32(x, 0) == x);
    
    // Test 3: Rotate by 32 (full rotation, back to original)
    // Note: This is undefined behavior in C, but should work in practice
    // We'll test rotate by 16 twice instead
    uint32_t half_rot = rotl32(x, 16);
    assert(rotl32(half_rot, 16) == x);
    
    // Test 4: Rotate 0x80000000 left by 1
    assert(rotl32(0x80000000, 1) == 0x00000001);
    
    // Test 5: Rotate 0x00000001 left by 31
    assert(rotl32(0x00000001, 31) == 0x80000000);
    
    // Test 6: Common ChaCha20 rotation amounts
    uint32_t test_val = 0xABCDEF01;
    uint32_t rot16 = rotl32(test_val, 16);
    uint32_t rot12 = rotl32(test_val, 12);
    uint32_t rot8 = rotl32(test_val, 8);
    uint32_t rot7 = rotl32(test_val, 7);
    
    assert(rot16 == 0xEF01ABCD);
    assert(rot12 == 0xDEF01ABC);
    assert(rot8 == 0xCDEF01AB);
    assert(rot7 == 0xE6F780D5);
    
    printf("  ✓ Rotation tests passed\n");
}

/**
 * @brief Test ROTL32 macro (selects implementation based on flags)
 */
void test_rotl32_macro(void) {
    printf("Testing ROTL32 macro...\n");
    
    uint32_t x = 0x12345678;
    
    // Test all ChaCha20 rotation amounts
    assert(ROTL32(x, 16) == 0x56781234);
    assert(ROTL32(x, 12) == 0x45678123);
    assert(ROTL32(x, 8) == 0x34567812);
    assert(ROTL32(x, 7) == 0x1A2B3C09);
    
    printf("  ✓ ROTL32 macro tests passed\n");
}

/**
 * @brief Test secure_zero function
 */
void test_secure_zero(void) {
    printf("Testing secure_zero function...\n");
    
    // Test 1: Zero a buffer
    uint8_t buffer[32];
    memset(buffer, 0xFF, sizeof(buffer));
    secure_zero(buffer, sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        assert(buffer[i] == 0);
    }
    
    // Test 2: Zero partial buffer
    memset(buffer, 0xAA, sizeof(buffer));
    secure_zero(buffer, 16);
    
    for (size_t i = 0; i < 16; i++) {
        assert(buffer[i] == 0);
    }
    for (size_t i = 16; i < sizeof(buffer); i++) {
        assert(buffer[i] == 0xAA);
    }
    
    // Test 3: Zero single byte
    buffer[0] = 0xFF;
    secure_zero(buffer, 1);
    assert(buffer[0] == 0);
    
    printf("  ✓ Secure zero tests passed\n");
}

/**
 * @brief Test secure_compare function
 */
void test_secure_compare(void) {
    printf("Testing secure_compare function...\n");
    
    // Test 1: Equal buffers
    uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t b[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    assert(secure_compare(a, b, 16) == 1);
    
    // Test 2: Different buffers (first byte)
    b[0] = 0;
    assert(secure_compare(a, b, 16) == 0);
    b[0] = 1;
    
    // Test 3: Different buffers (last byte)
    b[15] = 0;
    assert(secure_compare(a, b, 16) == 0);
    b[15] = 16;
    
    // Test 4: Different buffers (middle byte)
    b[8] = 0;
    assert(secure_compare(a, b, 16) == 0);
    b[8] = 9;
    
    // Test 5: All zeros
    uint8_t zeros1[16] = {0};
    uint8_t zeros2[16] = {0};
    assert(secure_compare(zeros1, zeros2, 16) == 1);
    
    // Test 6: Single byte comparison
    uint8_t x = 0x42;
    uint8_t y = 0x42;
    assert(secure_compare(&x, &y, 1) == 1);
    y = 0x43;
    assert(secure_compare(&x, &y, 1) == 0);
    
    printf("  ✓ Secure compare tests passed\n");
}

/**
 * @brief Main test runner
 */
int test_utils_basic(void) {
    printf("\n");
    printf("===========================================\n");
    printf("  ChaCha20-Poly1305 Utils Module Tests\n");
    printf("===========================================\n");
    printf("\n");
    
    test_endian_conversion();
    test_rotl32();
    test_rotl32_macro();
    test_secure_zero();
    test_secure_compare();
    
    printf("\n");
    printf("===========================================\n");
    printf("  All utils tests passed! ✓\n");
    printf("===========================================\n");
    printf("\n");
    
    return 0;
}
