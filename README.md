# ChaCha20-Poly1305 RISC-V 实现

> 基于RISC-V架构的ChaCha20-Poly1305认证加密算法（AEAD）C语言实现

## 📖 项目简介

本项目实现了符合 **RFC 8439** 标准的 ChaCha20-Poly1305 认证加密算法，专门针对 RISC-V 指令集架构优化。该算法被广泛应用于 TLS 1.3、WireGuard VPN 等现代安全协议。

### 核心特性

- ✅ **RFC 8439 标准合规**：通过官方测试向量验证
- ✅ **RISC-V 架构优化**：支持 RV32I 和 RV64I
- ✅ **完整功能实现**：ChaCha20 流密码 + Poly1305 MAC + AEAD 组合
- ✅ **单元测试验证**：包含完整的测试套件
- ✅ **命令行工具**：提供文件加密/解密功能
- ✅ **安全实现**：防时序攻击、安全内存管理

## 🏗️ 项目结构

```
chacha20-poly1305/
├── include/              # 头文件（4个）
│   ├── chacha20.h       # ChaCha20 流密码接口
│   ├── poly1305.h       # Poly1305 MAC 接口
│   ├── chacha20poly1305.h  # AEAD 接口
│   └── utils.h          # 工具函数
├── src/                 # 源代码（5个）
│   ├── chacha20.c       # ChaCha20 实现（Quarter Round、状态初始化、块生成）
│   ├── poly1305.c       # Poly1305 实现（130位运算、MAC计算）
│   ├── aead.c           # AEAD 实现（加密、解密、认证）
│   ├── utils.c          # 工具函数（循环移位、字节序转换、安全函数）
│   └── cli.c            # 命令行工具
├── tests/unit/          # 单元测试（4个）
│   ├── test_runner.c    # 测试运行器
│   ├── test_chacha20_basic.c  # ChaCha20 测试
│   ├── test_poly1305_basic.c  # Poly1305 测试（含RFC测试向量）
│   ├── test_aead_basic.c      # AEAD 测试
│   └── test_utils_basic.c     # 工具函数测试
├── Makefile             # 构建系统
└── README.md            # 本文件
```

## 🚀 快速开始

### 1. 环境准备

**RISC-V 工具链**（二选一）：
```bash
# 方案1：使用包管理器安装
sudo apt-get install gcc-riscv64-unknown-elf  # Ubuntu/Debian

# 方案2：从源码构建
git clone https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
./configure --prefix=/opt/riscv --with-arch=rv32i
make
export PATH=/opt/riscv/bin:$PATH
```

**QEMU 模拟器**（用于测试）：
```bash
sudo apt-get install qemu-user  # Ubuntu/Debian
```

### 2. 编译项目

```bash
# 基础编译（RV32I）
make

# 编译 RV64I 版本
make ARCH=rv64i

# 启用 RISC-V B 扩展（硬件循环移位）
make ENABLE_B_EXT=1

# 查看编译配置
make info

# 清理编译产物
make clean
```

编译成功后会生成：
- `libchacha20poly1305.a` - 静态库
- `chacha20poly1305_cli` - 命令行工具

### 3. 运行测试

```bash
# 运行所有单元测试
make test

# 仅运行单元测试
make test-unit
```

测试输出示例：
```
==============================================
ChaCha20-Poly1305 Unit Test Suite
==============================================

Running AEAD tests...
✓ AEAD tests PASSED

Running Poly1305 tests...
✓ Poly1305 tests PASSED

Running Utils tests...
✓ Utils tests PASSED

==============================================
✓ ALL TESTS PASSED!
==============================================
```

## 💻 使用方法

### 命令行工具

#### 加密文件

```bash
./chacha20poly1305_cli encrypt \
  --key 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f \
  --nonce 070000004041424344454647 \
  --input plaintext.txt \
  --output ciphertext.bin \
  --tag tag.bin
```

**参数说明**：
- `--key`：256位密钥（64个十六进制字符）
- `--nonce`：96位nonce（24个十六进制字符）
- `--input`：输入明文文件
- `--output`：输出密文文件
- `--tag`：输出认证标签文件（16字节）

#### 解密文件

```bash
./chacha20poly1305_cli decrypt \
  --key 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f \
  --nonce 070000004041424344454647 \
  --input ciphertext.bin \
  --tag tag.bin \
  --output decrypted.txt
```

**注意**：
- 解密时会先验证标签，验证失败则拒绝解密
- 密钥和nonce必须与加密时完全相同

### 库 API 使用

```c
#include "chacha20poly1305.h"

int main() {
    // 1. 准备密钥和nonce
    uint8_t key[32] = { /* 256位密钥 */ };
    uint8_t nonce[12] = { /* 96位nonce，每次加密必须不同 */ };
    
    // 2. 准备数据
    uint8_t plaintext[] = "Hello, RISC-V!";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];
    
    // 3. 加密
    int result = chacha20poly1305_encrypt(
        key, nonce,
        NULL, 0,  // 无附加认证数据（AAD）
        plaintext, sizeof(plaintext),
        ciphertext, tag
    );
    
    if (result != CHACHA20POLY1305_OK) {
        // 加密失败
        return -1;
    }
    
    // 4. 解密
    uint8_t decrypted[sizeof(plaintext)];
    result = chacha20poly1305_decrypt(
        key, nonce,
        NULL, 0,
        ciphertext, sizeof(ciphertext),
        tag, decrypted
    );
    
    if (result == CHACHA20POLY1305_OK) {
        // 解密成功，decrypted 包含明文
    } else if (result == CHACHA20POLY1305_ERROR_AUTH_FAILED) {
        // 认证失败，数据可能被篡改
    }
    
    return 0;
}
```

更多API详情请参阅 [API.md](API.md)

## 🎯 实现细节

### ChaCha20 流密码

- **Quarter Round**：核心运算单元，包含加法、异或、循环左移
- **20轮运算**：10次双轮（列轮+对角轮）
- **状态矩阵**：4×4的32位字矩阵
- **密钥流生成**：每个块64字节，支持任意长度消息

### Poly1305 MAC

- **130位运算**：使用5个26位limb表示
- **有限域**：GF(2^130-5)上的多项式运算
- **Horner方法**：高效计算多项式
- **RFC 8439合规**：通过官方测试向量

### AEAD 组合

- **密钥派生**：使用ChaCha20计数器0生成Poly1305密钥
- **认证数据**：支持附加认证数据（AAD）
- **输入格式**：按RFC 8439规范构造Poly1305输入
- **安全解密**：先验证后解密

### RISC-V 优化

- **小端序优化**：利用RISC-V小端序特性
- **寄存器优化**：充分利用31个通用寄存器
- **B扩展支持**：可选硬件循环移位指令
- **内存对齐**：4字节对齐以获得最佳性能

## ✅ 测试验证

### 测试覆盖范围

| 测试模块 | 测试内容 | 状态 |
|---------|---------|------|
| **Utils** | 字节序转换、循环移位、安全函数 | ✅ 通过 |
| **Poly1305** | RFC 8439测试向量、边界情况 | ✅ 通过 |
| **AEAD** | 加密/解密、AAD、标签验证 | ✅ 通过 |

### RFC 8439 合规性

- ✅ Poly1305 MAC：通过RFC 8439 Section 2.5.2测试向量
- ✅ AEAD：通过完整的加密/解密测试
- ✅ 边界情况：空消息、单字节、大消息

## 📊 代码统计

- **总代码行数**：约 2000+ 行（不含注释和空行）
- **核心实现**：5个源文件
- **头文件**：4个
- **测试代码**：4个测试文件

## 🔧 高级编译选项

```bash
# 启用所有优化
make ARCH=rv64i ENABLE_B_EXT=1 USE_ASM=1

# 调试构建
make DEBUG=1

# 查看构建配置
make info

# 查看帮助
make help
```


## 📖 参考资料

- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [RISC-V Instruction Set Manual](https://riscv.org/technical/specifications/)
- [RISC-V Bit Manipulation Extension](https://github.com/riscv/riscv-bitmanip)

**注意**：本实现仅用于教育和学习目的。在生产环境中使用密码学软件前，请进行专业的安全审计。
