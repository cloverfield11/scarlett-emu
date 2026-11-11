#pragma once

#include "common/types.h"
#include <string>

namespace Scarlett {

// Standard x86-64 registers used by AMD Zen 2 (GameOS ABI)
struct alignas(16) CpuContext {
    u64 rax{0};
    u64 rbx{0};
    u64 rcx{0}; // 1st arg in Microsoft x64 fastcall ABI
    u64 rdx{0}; // 2nd arg in Microsoft x64 fastcall ABI
    u64 rsi{0};
    u64 rdi{0};
    u64 rbp{0};
    u64 rsp{0}; // Stack Pointer
    u64 r8{0};  // 3rd arg in Microsoft x64 fastcall ABI
    u64 r9{0};  // 4th arg in Microsoft x64 fastcall ABI
    u64 r10{0};
    u64 r11{0};
    u64 r12{0};
    u64 r13{0};
    u64 r14{0};
    u64 r15{0};

    u64 rip{0};    // Instruction Pointer
    u64 rflags{0}; // Processor Flags
    u64 gsBase{0}; // GS Segment Base (Points to TEB in Windows x64)

    // AVX2 / YMM registers (256-bit SIMD registers)
    struct YmmReg {
        u64 qwords[4];
    } ymm[16];

    void DumpState() const;
};

} // namespace Scarlett
