/**
 * @file cli.c
 * @brief Command-line interface for ChaCha20-Poly1305 AEAD
 * 
 * Provides encryption and decryption commands for files using
 * ChaCha20-Poly1305 authenticated encryption.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "chacha20poly1305.h"

// ============================================================================
// Hex String Parsing (Task 12.1)
// ============================================================================

/**
 * @brief Convert a hexadecimal character to its numeric value
 * 
 * @param c Hex character ('0'-'9', 'a'-'f', 'A'-'F')
 * @return Numeric value (0-15), or -1 if invalid
 */
static int hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/**
 * @brief Convert hexadecimal string to byte array
 * 
 * Supports both uppercase and lowercase hex characters.
 * Validates input format and length.
 * 
 * @param hex_str Null-terminated hex string (must have even length)
 * @param bytes Output buffer for decoded bytes
 * @param expected_len Expected number of output bytes
 * @return 0 on success, -1 on error
 * 
 * Requirements: 10.3
 */
int hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t expected_len) {
    if (!hex_str || !bytes) {
        return -1;
    }
    
    size_t hex_len = strlen(hex_str);
    
    // Hex string must have even length
    if (hex_len % 2 != 0) {
        return -1;
    }
    
    // Check if length matches expected
    if (hex_len / 2 != expected_len) {
        return -1;
    }
    
    // Convert each pair of hex characters to a byte
    for (size_t i = 0; i < expected_len; i++) {
        int high = hex_char_to_value(hex_str[i * 2]);
        int low = hex_char_to_value(hex_str[i * 2 + 1]);
        
        if (high < 0 || low < 0) {
            return -1;  // Invalid hex character
        }
        
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    
    return 0;
}


// ============================================================================
// File I/O Helper Functions (Task 12.3)
// ============================================================================

/**
 * @brief Read entire file into memory
 * 
 * Allocates memory for file contents. Caller must free the returned buffer.
 * 
 * @param filename Path to file to read
 * @param size Output parameter for file size in bytes
 * @return Pointer to allocated buffer containing file data, or NULL on error
 * 
 * Requirements: 10.1, 10.2
 */
uint8_t* read_file(const char *filename, size_t *size) {
    if (!filename || !size) {
        return NULL;
    }
    
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file '%s' for reading\n", filename);
        return NULL;
    }
    
    // Get file size
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Cannot seek to end of file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    
    long file_size = ftell(fp);
    if (file_size < 0) {
        fprintf(stderr, "Error: Cannot determine size of file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: Cannot seek to start of file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    
    // Allocate buffer
    uint8_t *buffer = (uint8_t*)malloc(file_size);
    if (!buffer) {
        fprintf(stderr, "Error: Cannot allocate %ld bytes for file '%s'\n", 
                file_size, filename);
        fclose(fp);
        return NULL;
    }
    
    // Read file contents
    size_t bytes_read = fread(buffer, 1, file_size, fp);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Error: Read %zu bytes but expected %ld from file '%s'\n",
                bytes_read, file_size, filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }
    
    fclose(fp);
    *size = (size_t)file_size;
    return buffer;
}

/**
 * @brief Write data to file
 * 
 * @param filename Path to file to write
 * @param data Data buffer to write
 * @param size Number of bytes to write
 * @return 0 on success, -1 on error
 * 
 * Requirements: 10.1, 10.2
 */
int write_file(const char *filename, const uint8_t *data, size_t size) {
    if (!filename || !data) {
        return -1;
    }
    
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file '%s' for writing\n", filename);
        return -1;
    }
    
    size_t bytes_written = fwrite(data, 1, size, fp);
    if (bytes_written != size) {
        fprintf(stderr, "Error: Wrote %zu bytes but expected %zu to file '%s'\n",
                bytes_written, size, filename);
        fclose(fp);
        return -1;
    }
    
    if (fclose(fp) != 0) {
        fprintf(stderr, "Error: Failed to close file '%s'\n", filename);
        return -1;
    }
    
    return 0;
}


// ============================================================================
// Encryption Command (Task 12.4)
// ============================================================================

/**
 * @brief Execute encryption command
 * 
 * Reads plaintext from input file, encrypts it using ChaCha20-Poly1305,
 * and writes ciphertext and authentication tag to output files.
 * 
 * @param key_hex 64-character hex string (256-bit key)
 * @param nonce_hex 24-character hex string (96-bit nonce)
 * @param input_file Path to plaintext input file
 * @param output_file Path to ciphertext output file
 * @param tag_file Path to authentication tag output file
 * @param aad_hex Optional AAD hex string (can be NULL)
 * @return 0 on success, -1 on error
 * 
 * Requirements: 10.1
 */
int cmd_encrypt(const char *key_hex, const char *nonce_hex,
                const char *input_file, const char *output_file,
                const char *tag_file, const char *aad_hex) {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t *aad = NULL;
    size_t aad_len = 0;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint8_t *ciphertext = NULL;
    uint8_t tag[16];
    int result = -1;
    
    // Parse key (64 hex chars = 32 bytes)
    if (hex_to_bytes(key_hex, key, 32) != 0) {
        fprintf(stderr, "Error: Invalid key format (expected 64 hex characters)\n");
        goto cleanup;
    }
    
    // Parse nonce (24 hex chars = 12 bytes)
    if (hex_to_bytes(nonce_hex, nonce, 12) != 0) {
        fprintf(stderr, "Error: Invalid nonce format (expected 24 hex characters)\n");
        goto cleanup;
    }
    
    // Parse AAD if provided
    if (aad_hex && strlen(aad_hex) > 0) {
        aad_len = strlen(aad_hex) / 2;
        aad = (uint8_t*)malloc(aad_len);
        if (!aad) {
            fprintf(stderr, "Error: Cannot allocate memory for AAD\n");
            goto cleanup;
        }
        if (hex_to_bytes(aad_hex, aad, aad_len) != 0) {
            fprintf(stderr, "Error: Invalid AAD format (must be hex string with even length)\n");
            goto cleanup;
        }
    }
    
    // Read plaintext from input file
    plaintext = read_file(input_file, &plaintext_len);
    if (!plaintext) {
        goto cleanup;
    }
    
    // Allocate ciphertext buffer (same size as plaintext)
    ciphertext = (uint8_t*)malloc(plaintext_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Cannot allocate memory for ciphertext\n");
        goto cleanup;
    }
    
    // Perform encryption
    int encrypt_result = chacha20poly1305_encrypt(
        key, nonce,
        aad, aad_len,
        plaintext, plaintext_len,
        ciphertext, tag
    );
    
    if (encrypt_result != CHACHA20POLY1305_OK) {
        fprintf(stderr, "Error: Encryption failed with code %d\n", encrypt_result);
        goto cleanup;
    }
    
    // Write ciphertext to output file
    if (write_file(output_file, ciphertext, plaintext_len) != 0) {
        goto cleanup;
    }
    
    // Write tag to tag file
    if (write_file(tag_file, tag, 16) != 0) {
        goto cleanup;
    }
    
    printf("Encryption successful:\n");
    printf("  Input:  %s (%zu bytes)\n", input_file, plaintext_len);
    printf("  Output: %s (%zu bytes)\n", output_file, plaintext_len);
    printf("  Tag:    %s (16 bytes)\n", tag_file);
    
    result = 0;
    
cleanup:
    if (aad) free(aad);
    if (plaintext) free(plaintext);
    if (ciphertext) free(ciphertext);
    
    return result;
}


// ============================================================================
// Decryption Command (Task 12.5)
// ============================================================================

/**
 * @brief Execute decryption command
 * 
 * Reads ciphertext and tag from input files, verifies authentication tag,
 * and decrypts to plaintext output file. Only outputs plaintext if tag
 * verification succeeds.
 * 
 * @param key_hex 64-character hex string (256-bit key)
 * @param nonce_hex 24-character hex string (96-bit nonce)
 * @param input_file Path to ciphertext input file
 * @param tag_file Path to authentication tag input file
 * @param output_file Path to plaintext output file
 * @param aad_hex Optional AAD hex string (can be NULL)
 * @return 0 on success, -1 on error
 * 
 * Requirements: 10.2, 10.4
 */
int cmd_decrypt(const char *key_hex, const char *nonce_hex,
                const char *input_file, const char *tag_file,
                const char *output_file, const char *aad_hex) {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t *aad = NULL;
    size_t aad_len = 0;
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t *tag_data = NULL;
    size_t tag_size = 0;
    uint8_t tag[16];
    uint8_t *plaintext = NULL;
    int result = -1;
    
    // Parse key (64 hex chars = 32 bytes)
    if (hex_to_bytes(key_hex, key, 32) != 0) {
        fprintf(stderr, "Error: Invalid key format (expected 64 hex characters)\n");
        goto cleanup;
    }
    
    // Parse nonce (24 hex chars = 12 bytes)
    if (hex_to_bytes(nonce_hex, nonce, 12) != 0) {
        fprintf(stderr, "Error: Invalid nonce format (expected 24 hex characters)\n");
        goto cleanup;
    }
    
    // Parse AAD if provided
    if (aad_hex && strlen(aad_hex) > 0) {
        aad_len = strlen(aad_hex) / 2;
        aad = (uint8_t*)malloc(aad_len);
        if (!aad) {
            fprintf(stderr, "Error: Cannot allocate memory for AAD\n");
            goto cleanup;
        }
        if (hex_to_bytes(aad_hex, aad, aad_len) != 0) {
            fprintf(stderr, "Error: Invalid AAD format (must be hex string with even length)\n");
            goto cleanup;
        }
    }
    
    // Read ciphertext from input file
    ciphertext = read_file(input_file, &ciphertext_len);
    if (!ciphertext) {
        goto cleanup;
    }
    
    // Read tag from tag file
    tag_data = read_file(tag_file, &tag_size);
    if (!tag_data) {
        goto cleanup;
    }
    
    // Verify tag size
    if (tag_size != 16) {
        fprintf(stderr, "Error: Tag file must be exactly 16 bytes (got %zu bytes)\n", 
                tag_size);
        goto cleanup;
    }
    
    memcpy(tag, tag_data, 16);
    
    // Allocate plaintext buffer (same size as ciphertext)
    plaintext = (uint8_t*)malloc(ciphertext_len);
    if (!plaintext) {
        fprintf(stderr, "Error: Cannot allocate memory for plaintext\n");
        goto cleanup;
    }
    
    // Perform decryption with authentication
    int decrypt_result = chacha20poly1305_decrypt(
        key, nonce,
        aad, aad_len,
        ciphertext, ciphertext_len,
        tag, plaintext
    );
    
    if (decrypt_result == CHACHA20POLY1305_ERROR_AUTH_FAILED) {
        fprintf(stderr, "Error: Authentication failed - tag verification failed\n");
        fprintf(stderr, "The ciphertext may have been tampered with or the key/nonce is incorrect\n");
        goto cleanup;
    } else if (decrypt_result != CHACHA20POLY1305_OK) {
        fprintf(stderr, "Error: Decryption failed with code %d\n", decrypt_result);
        goto cleanup;
    }
    
    // Write plaintext to output file (only if authentication succeeded)
    if (write_file(output_file, plaintext, ciphertext_len) != 0) {
        goto cleanup;
    }
    
    printf("Decryption successful:\n");
    printf("  Input:  %s (%zu bytes)\n", input_file, ciphertext_len);
    printf("  Tag:    %s (verified)\n", tag_file);
    printf("  Output: %s (%zu bytes)\n", output_file, ciphertext_len);
    
    result = 0;
    
cleanup:
    if (aad) free(aad);
    if (ciphertext) free(ciphertext);
    if (tag_data) free(tag_data);
    if (plaintext) free(plaintext);
    
    return result;
}


// ============================================================================
// Help Information (Task 12.6)
// ============================================================================

/**
 * @brief Display help information
 * 
 * Shows usage instructions, parameter formats, and RISC-V platform information.
 * 
 * Requirements: 10.5
 */
void print_help(const char *program_name) {
    printf("ChaCha20-Poly1305 AEAD - RISC-V Implementation\n");
    printf("==============================================\n\n");
    
    printf("USAGE:\n");
    printf("  %s encrypt <key> <nonce> <input> <output> <tag> [aad]\n", program_name);
    printf("  %s decrypt <key> <nonce> <input> <tag> <output> [aad]\n", program_name);
    printf("  %s help\n\n", program_name);
    
    printf("COMMANDS:\n");
    printf("  encrypt    Encrypt a file using ChaCha20-Poly1305\n");
    printf("  decrypt    Decrypt a file using ChaCha20-Poly1305\n");
    printf("  help       Display this help message\n\n");
    
    printf("PARAMETERS:\n");
    printf("  key        256-bit key as 64 hexadecimal characters\n");
    printf("  nonce      96-bit nonce as 24 hexadecimal characters\n");
    printf("  input      Path to input file (plaintext for encrypt, ciphertext for decrypt)\n");
    printf("  output     Path to output file (ciphertext for encrypt, plaintext for decrypt)\n");
    printf("  tag        Path to tag file (output for encrypt, input for decrypt)\n");
    printf("  aad        Optional: Additional Authenticated Data as hex string\n\n");
    
    printf("EXAMPLES:\n");
    printf("  # Encrypt a file\n");
    printf("  %s encrypt \\\n", program_name);
    printf("    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\\n");
    printf("    0123456789abcdef01234567 \\\n");
    printf("    plaintext.txt ciphertext.bin tag.bin\n\n");
    
    printf("  # Decrypt a file\n");
    printf("  %s decrypt \\\n", program_name);
    printf("    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\\n");
    printf("    0123456789abcdef01234567 \\\n");
    printf("    ciphertext.bin tag.bin plaintext.txt\n\n");
    
    printf("  # Encrypt with AAD\n");
    printf("  %s encrypt \\\n", program_name);
    printf("    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\\n");
    printf("    0123456789abcdef01234567 \\\n");
    printf("    plaintext.txt ciphertext.bin tag.bin \\\n");
    printf("    48656c6c6f\n\n");
    
    printf("RISC-V PLATFORM INFORMATION:\n");
    printf("  Target Architecture: ");
#if defined(__riscv)
    #if __riscv_xlen == 64
    printf("RV64I (64-bit RISC-V)\n");
    #else
    printf("RV32I (32-bit RISC-V)\n");
    #endif
#else
    printf("Native (non-RISC-V)\n");
#endif
    
    printf("  B Extension:         ");
#ifdef __riscv_bitmanip
    printf("Enabled\n");
#else
    printf("Disabled\n");
#endif
    
    printf("  Assembly Optimized:  ");
#ifdef USE_ASM
    printf("Yes\n");
#else
    printf("No\n");
#endif
    
    printf("\nSECURITY NOTES:\n");
    printf("  - Never reuse the same key and nonce combination\n");
    printf("  - Use a cryptographically secure random number generator for keys and nonces\n");
    printf("  - Keep keys secret and secure\n");
    printf("  - Authentication tag verification failure indicates tampering or incorrect key\n\n");
    
    printf("ALGORITHM:\n");
    printf("  ChaCha20-Poly1305 is an AEAD (Authenticated Encryption with Associated Data)\n");
    printf("  cipher that provides both confidentiality and authenticity. It combines:\n");
    printf("    - ChaCha20: Stream cipher for encryption (RFC 8439)\n");
    printf("    - Poly1305: Message authentication code for integrity (RFC 8439)\n\n");
}


// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * @brief Main entry point for CLI
 * 
 * Parses command-line arguments and dispatches to appropriate command handler.
 */
int main(int argc, char *argv[]) {
    // Check minimum arguments
    if (argc < 2) {
        fprintf(stderr, "Error: No command specified\n\n");
        print_help(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    // Help command
    if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 || 
        strcmp(command, "--help") == 0) {
        print_help(argv[0]);
        return 0;
    }
    
    // Encrypt command
    if (strcmp(command, "encrypt") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: Insufficient arguments for encrypt command\n");
            fprintf(stderr, "Usage: %s encrypt <key> <nonce> <input> <output> <tag> [aad]\n", 
                    argv[0]);
            return 1;
        }
        
        const char *key_hex = argv[2];
        const char *nonce_hex = argv[3];
        const char *input_file = argv[4];
        const char *output_file = argv[5];
        const char *tag_file = argv[6];
        const char *aad_hex = (argc >= 8) ? argv[7] : NULL;
        
        return cmd_encrypt(key_hex, nonce_hex, input_file, output_file, 
                          tag_file, aad_hex);
    }
    
    // Decrypt command
    if (strcmp(command, "decrypt") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: Insufficient arguments for decrypt command\n");
            fprintf(stderr, "Usage: %s decrypt <key> <nonce> <input> <tag> <output> [aad]\n", 
                    argv[0]);
            return 1;
        }
        
        const char *key_hex = argv[2];
        const char *nonce_hex = argv[3];
        const char *input_file = argv[4];
        const char *tag_file = argv[5];
        const char *output_file = argv[6];
        const char *aad_hex = (argc >= 8) ? argv[7] : NULL;
        
        return cmd_decrypt(key_hex, nonce_hex, input_file, tag_file, 
                          output_file, aad_hex);
    }
    
    // Unknown command
    fprintf(stderr, "Error: Unknown command '%s'\n\n", command);
    print_help(argv[0]);
    return 1;
}
