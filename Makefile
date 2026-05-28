# ChaCha20-Poly1305 RISC-V Implementation Makefile
# Supports RV32I and RV64I with optional B extension

# ============================================================================
# Configuration
# ============================================================================

# RISC-V toolchain prefix
# Set to empty string for native compilation
CROSS_COMPILE ?= riscv32-unknown-elf-

# Tools
CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)as
AR = $(CROSS_COMPILE)ar
LD = $(CROSS_COMPILE)ld
OBJDUMP = $(CROSS_COMPILE)objdump
SIZE = $(CROSS_COMPILE)size

# Architecture selection (rv32i or rv64i)
ARCH ?= rv32i
ABI ?= ilp32

# Detect RV64I and adjust ABI
ifeq ($(ARCH),rv64i)
    ABI = lp64
endif

# Base compiler flags
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2
# Only add RISC-V flags if using RISC-V toolchain
ifneq ($(CROSS_COMPILE),)
CFLAGS += -march=$(ARCH) -mabi=$(ABI)
endif
CFLAGS += -Iinclude

# Optional B extension support
ifdef ENABLE_B_EXT
    CFLAGS += -march=$(ARCH)_zba_zbb_zbc_zbs
    CFLAGS += -DUSE_B_EXTENSION
endif

# Optional assembly optimization
ifdef USE_ASM
    CFLAGS += -DUSE_ASM
endif

# Debug build
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Linker flags
ifneq ($(CROSS_COMPILE),)
LDFLAGS = -march=$(ARCH) -mabi=$(ABI)
endif

# QEMU for testing
QEMU_RV32 = qemu-riscv32
QEMU_RV64 = qemu-riscv64
ifeq ($(ARCH),rv64i)
    QEMU = $(QEMU_RV64)
else
    QEMU = $(QEMU_RV32)
endif

# ============================================================================
# Source Files
# ============================================================================

# Library sources
LIB_SOURCES = src/chacha20.c \
              src/poly1305.c \
              src/aead.c \
              src/utils.c

# Assembly sources (if enabled)
ifdef USE_ASM
    LIB_SOURCES += src/riscv_asm.S
endif

# CLI source
CLI_SOURCE = src/cli.c

# Test sources
TEST_UNIT_SOURCES = $(wildcard tests/unit/*.c)
TEST_PROPERTY_SOURCES = $(wildcard tests/property/*.c)
TEST_BENCHMARK_SOURCES = $(wildcard tests/benchmark/*.c)

# Object files
LIB_OBJECTS = $(LIB_SOURCES:.c=.o)
LIB_OBJECTS := $(LIB_OBJECTS:.S=.o)
CLI_OBJECT = $(CLI_SOURCE:.c=.o)
TEST_UNIT_OBJECTS = $(TEST_UNIT_SOURCES:.c=.o)
TEST_PROPERTY_OBJECTS = $(TEST_PROPERTY_SOURCES:.c=.o)
TEST_BENCHMARK_OBJECTS = $(TEST_BENCHMARK_SOURCES:.c=.o)

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean lib cli test test-unit test-property benchmark help

# Default target
all: lib cli

# Help target
help:
	@echo "ChaCha20-Poly1305 RISC-V Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build library and CLI (default)"
	@echo "  lib              - Build static library"
	@echo "  cli              - Build command-line tool"
	@echo "  test             - Build and run all tests"
	@echo "  test-unit        - Build and run unit tests"
	@echo "  test-property    - Build and run property-based tests"
	@echo "  benchmark        - Build and run benchmarks"
	@echo "  clean            - Remove all build artifacts"
	@echo ""
	@echo "Configuration:"
	@echo "  ARCH=rv32i|rv64i       - Select architecture (default: rv32i)"
	@echo "  ENABLE_B_EXT=1         - Enable RISC-V B extension"
	@echo "  USE_ASM=1              - Enable assembly optimizations"
	@echo "  DEBUG=1                - Build with debug symbols"
	@echo "  CROSS_COMPILE=prefix   - Set toolchain prefix"
	@echo ""
	@echo "Examples:"
	@echo "  make                                    # Build for RV32I"
	@echo "  make ARCH=rv64i                         # Build for RV64I"
	@echo "  make ENABLE_B_EXT=1                     # Build with B extension"
	@echo "  make USE_ASM=1                          # Build with assembly"
	@echo "  make ARCH=rv64i ENABLE_B_EXT=1 USE_ASM=1  # All optimizations"
	@echo "  make test                               # Run tests in QEMU"

# ============================================================================
# Library
# ============================================================================

lib: libchacha20poly1305.a

libchacha20poly1305.a: $(LIB_OBJECTS)
	@echo "AR  $@"
	@$(AR) rcs $@ $^
	@$(SIZE) $@

# ============================================================================
# CLI Tool
# ============================================================================

cli: chacha20poly1305_cli

chacha20poly1305_cli: $(CLI_OBJECT) libchacha20poly1305.a
	@echo "LD  $@"
	@$(CC) $(LDFLAGS) -o $@ $^
	@$(SIZE) $@

# ============================================================================
# Tests
# ============================================================================

test: test-unit test-property

test-unit: test_runner_unit
	@echo "Running unit tests..."
	@$(QEMU) ./test_runner_unit

test_runner_unit: tests/unit/test_runner.o $(TEST_UNIT_OBJECTS) libchacha20poly1305.a
	@echo "LD  $@"
	@$(CC) $(LDFLAGS) -o $@ $^

test-property: test_runner_property
	@echo "Running property-based tests..."
	@$(QEMU) ./test_runner_property

test_runner_property: $(TEST_PROPERTY_OBJECTS) libchacha20poly1305.a
	@echo "LD  $@"
	@$(CC) $(LDFLAGS) -o $@ $^

# ============================================================================
# Benchmarks
# ============================================================================

benchmark: benchmark_runner
	@echo "Running benchmarks..."
	@$(QEMU) ./benchmark_runner

benchmark_runner: $(TEST_BENCHMARK_OBJECTS) libchacha20poly1305.a
	@echo "LD  $@"
	@$(CC) $(LDFLAGS) -o $@ $^

# ============================================================================
# Compilation Rules
# ============================================================================

%.o: %.c
	@echo "CC  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	@echo "AS  $<"
	@$(AS) $(CFLAGS) -c $< -o $@

# ============================================================================
# Clean
# ============================================================================

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(LIB_OBJECTS) $(CLI_OBJECT)
	@rm -f $(TEST_UNIT_OBJECTS) $(TEST_PROPERTY_OBJECTS) $(TEST_BENCHMARK_OBJECTS)
	@rm -f libchacha20poly1305.a
	@rm -f chacha20poly1305_cli
	@rm -f test_runner_unit test_runner_property benchmark_runner
	@rm -f *.o src/*.o tests/unit/*.o tests/property/*.o tests/benchmark/*.o
	@echo "Clean complete."

# ============================================================================
# Dependencies
# ============================================================================

# Header dependencies
$(LIB_OBJECTS): $(wildcard include/*.h)
$(CLI_OBJECT): $(wildcard include/*.h)
$(TEST_UNIT_OBJECTS): $(wildcard include/*.h)
$(TEST_PROPERTY_OBJECTS): $(wildcard include/*.h)
$(TEST_BENCHMARK_OBJECTS): $(wildcard include/*.h)

# ============================================================================
# Info Target
# ============================================================================

.PHONY: info
info:
	@echo "Build Configuration:"
	@echo "  Architecture: $(ARCH)"
	@echo "  ABI: $(ABI)"
	@echo "  Cross Compile: $(CROSS_COMPILE)"
	@echo "  B Extension: $(if $(ENABLE_B_EXT),enabled,disabled)"
	@echo "  Assembly: $(if $(USE_ASM),enabled,disabled)"
	@echo "  Debug: $(if $(DEBUG),enabled,disabled)"
	@echo "  QEMU: $(QEMU)"
