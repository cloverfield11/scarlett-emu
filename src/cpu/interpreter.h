#pragma once

#include "common/types.h"
#include "cpu/cpu_context.h"
#include "cpu/memory_manager.h"
#include <string>

namespace Scarlett {

// Magic trap opcode used to intercept guest execution and transfer control to C++ HLE
constexpr u16 HLE_TRAP_OPCODE = 0x0B0F; // UD2 opcode (0x0F, 0x0B)

enum class OpcodeType {
    Unknown,
    Mov,
    Add,
    Sub,
    Xor,
    Cmp,
    Jmp,
    Jcc,
    Call,
    Ret,
    Push,
    Pop,
    HleTrap,
    Halt
};

struct DecodedInstruction {
    OpcodeType type{OpcodeType::Unknown};
    u8 length{0};
    u8 regDest{0};
    u8 regSrc{0};
    u64 immediate{0};
    s32 displacement{0};
    bool hasImmediate{false};
    bool isRipRelative{false};
};

class X86Decoder {
public:
    static DecodedInstruction Decode(const u8* code, u64 rip);
};

class Interpreter {
public:
    Interpreter(CpuContext& ctx, MemoryManager& memory);

    // Execute a single x86_64 instruction at RIP
    bool Step();

    // Run execution loop until halt, breakpoint, or max instructions
    bool Run(u64 maxInstructions = 1000000);

    bool IsHalted() const { return m_halted; }
    void Halt() { m_halted = true; }

private:
    CpuContext& m_ctx;
    MemoryManager& m_memory;
    bool m_halted{false};
    u64 m_instructionsExecuted{0};
};

} // namespace Scarlett
