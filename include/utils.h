#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief 32-bit rotate left (pure C implementation)
 * 
 * @param x Value to rotate
 * @param n Number of bits to rotate (0-31)
 * @return Rotated value
 */
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/**
 * @brief Load 32-bit little-endian integer from byte array
 * 
 * @param p Pointer to byte array
 * @return 32-bit integer value
 */
static inline uint32_t load_le32(const uint8_t *p) {
#ifdef __riscv
    // RISC-V is little-endian, can load directly if aligned
    return *(const uint32_t *)p;
#else
    return (uint32_t)p[0] | 
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
#endif
}

/**
 * @brief Store 32-bit integer as little-endian bytes
 * 
 * @param p Pointer to output byte array
 * @param v Value to store
 */
static inline void store_le32(uint8_t *p, uint32_t v) {
#ifdef __riscv
    // RISC-V is little-endian, can store directly if aligned
    *(uint32_t *)p = v;
#else
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
#endif
}

/**
 * @brief Secure memory zeroing (prevents compiler optimization)
 * 
 * @param ptr Pointer to memory to zero
 * @param len Length in bytes
 */
void secure_zero(void *ptr, size_t len);

/**
 * @brief Constant-time memory comparison
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare in bytes
 * @return 1 if equal, 0 if different
 */
int secure_compare(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef USE_ASM
/**
 * @brief 32-bit rotate left using RISC-V inline assembly
 * 
 * @param x Value to rotate
 * @param n Number of bits to rotate
 * @return Rotated value
 */
static inline uint32_t rotl32_asm(uint32_t x, int n) {
    uint32_t result;
    __asm__ (
        "slli %0, %1, %2\n\t"
        "srli t0, %1, %3\n\t"
        "or %0, %0, t0"
        : "=r"(result)
        : "r"(x), "i"(n), "i"(32-n)
        : "t0"
    );
    return result;
}
#endif

#ifdef __riscv_bitmanip
/**
 * @brief 32-bit rotate left using RISC-V B extension
 * 
 * @param x Value to rotate
 * @param n Number of bits to rotate
 * @return Rotated value
 */
static inline uint32_t rotl32_rori(uint32_t x, int n) {
    uint32_t result;
    __asm__ ("rori %0, %1, %2" 
             : "=r"(result) 
             : "r"(x), "i"(32-n));
    return result;
}
#endif

// Select rotation implementation based on compile-time flags
#ifdef __riscv_bitmanip
    #define ROTL32(x, n) rotl32_rori(x, n)
#elif defined(USE_ASM)
    #define ROTL32(x, n) rotl32_asm(x, n)
#else
    #define ROTL32(x, n) rotl32(x, n)
#endif

#endif // UTILS_H
