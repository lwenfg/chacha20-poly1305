/**
 * @file test_runner.c
 * @brief Unified test runner for all unit tests
 */

#include <stdio.h>
#include <stdlib.h>

// External test functions
extern int test_aead_basic(void);
extern int test_poly1305_basic(void);
extern int test_utils_basic(void);

int main(void) {
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;
    
    printf("==============================================\n");
    printf("ChaCha20-Poly1305 Unit Test Suite\n");
    printf("==============================================\n\n");
    
    // Run AEAD tests
    printf("Running AEAD tests...\n");
    int aead_result = test_aead_basic();
    total_tests++;
    if (aead_result == 0) {
        passed_tests++;
        printf("✓ AEAD tests PASSED\n\n");
    } else {
        failed_tests++;
        printf("✗ AEAD tests FAILED\n\n");
    }
    
    // Run Poly1305 tests
    printf("Running Poly1305 tests...\n");
    int poly1305_result = test_poly1305_basic();
    total_tests++;
    if (poly1305_result == 0) {
        passed_tests++;
        printf("✓ Poly1305 tests PASSED\n\n");
    } else {
        failed_tests++;
        printf("✗ Poly1305 tests FAILED\n\n");
    }
    
    // Run Utils tests
    printf("Running Utils tests...\n");
    int utils_result = test_utils_basic();
    total_tests++;
    if (utils_result == 0) {
        passed_tests++;
        printf("✓ Utils tests PASSED\n\n");
    } else {
        failed_tests++;
        printf("✗ Utils tests FAILED\n\n");
    }
    
    // Print summary
    printf("==============================================\n");
    printf("Test Summary\n");
    printf("==============================================\n");
    printf("Total test suites: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", failed_tests);
    printf("==============================================\n");
    
    if (failed_tests == 0) {
        printf("\n✓ ALL TESTS PASSED!\n\n");
        return 0;
    } else {
        printf("\n✗ SOME TESTS FAILED\n\n");
        return 1;
    }
}
