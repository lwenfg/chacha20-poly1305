#include "utils.h"

/**
 * @brief Secure memory zeroing (prevents compiler optimization)
 * 
 * Uses volatile pointer to prevent the compiler from optimizing away
 * the memory clearing operation. This is important for clearing sensitive
 * data like keys and intermediate cryptographic values.
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length in bytes
 */
void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * @brief Constant-time memory comparison
 * 
 * Compares two memory regions in constant time to prevent timing attacks.
 * Always examines all bytes regardless of where differences are found.
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare in bytes
 * @return 1 if equal, 0 if different
 */
int secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}
