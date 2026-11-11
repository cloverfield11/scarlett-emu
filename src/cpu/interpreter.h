#pragma once

#include "common/types.h"
#include "cpu/cpu_context.h"
#include "cpu/memory_manager.h"
#include <string>
#include <vector>

namespace Scarlett {

constexpr u16 HLE_TRAP_OPCODE = 0x0B0F; // UD2 opcode (0x0F, 0x0B)

enum class OpcodeType {
    Unknown,
    Nop,
    Halt,
    HleTrap,
    Mov,
    Movzx,
    Movsxd,
    Lea,
    Push,
    Pop,
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
    Test,
    Not,
    Neg,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Mul,
    Imul,
    Div,
    Idiv,
    Xchg,
    Xadd,
    Inc,
    Dec,
    Bt,
    Cpuid,
    Xgetbv,
    Cmpxchg,
    Cmov,
    Setcc,
    Jmp,
    Jcc,
    Call,
    Ret,
    Stos,
    Movs,
    Movdqa,
    Movdqu,
    Movq,
    Movsd,
    Punpcklbw,
    Xorps,
    Andps,
    Orps,
    Addsd,
    Subsd,
    Mulsd,
    Divsd,
    Comisd,
    Cvtsi2sd,
    Cvtsd2si,
    Bswap,
    Cdq,
    Cdqe,
    Movsx,
    Bts,
    Btr,
    Btc,
    Psrlq,
    Psubq,
    Psubd
};

struct Operand {
    enum class Kind : u8 {
        None,
        Register,
        Memory,
        Immediate
    } kind{Kind::None};

    u8 size{8}; // 1, 2, 4, 8, 16 bytes
    u8 reg{0};  // Register index 0-15
    u64 imm{0};

    // Memory addressing: [base + index*scale + displacement]
    bool isRipRelative{false};
    bool isGsRelative{false};
    u8 baseReg{0xFF};  // 0xFF means no base
    u8 indexReg{0xFF}; // 0xFF means no index
    u8 scale{1};
    s64 displacement{0};

    u64 GetAddress(const CpuContext& ctx, u64 nextRip) const;
};

struct DecodedInstruction {
    OpcodeType type{OpcodeType::Unknown};
    u8 length{0};
    u8 opSize{8}; // default 64-bit operand size
    u8 conditionCode{0};
    bool hasRex{false};
    bool hasLockPrefix{false};
    bool hasRepPrefix{false};

    Operand op1; // Typically destination
    Operand op2; // Typically source
};

class X86Decoder {
public:
    static DecodedInstruction Decode(const u8* code, u64 rip);
};

class HleKernel;
struct ImportedFunction;

class Interpreter {
public:
    Interpreter(CpuContext& ctx, MemoryManager& memory, HleKernel* kernel = nullptr, const std::vector<ImportedFunction>* imports = nullptr);

    // Execute a single x86_64 instruction at RIP
    bool Step();

    // Run execution loop until halt, breakpoint, or max instructions
    bool Run(u64 maxInstructions = 1000000);

    bool IsHalted() const { return m_halted; }
    void Halt() { m_halted = true; }
    u64 GetInstructionsExecuted() const { return m_instructionsExecuted; }

private:
    CpuContext& m_ctx;
    MemoryManager& m_memory;
    HleKernel* m_kernel{nullptr};
    const std::vector<ImportedFunction>* m_imports{nullptr};
    bool m_halted{false};
    u64 m_instructionsExecuted{0};

    u64 ReadOperand(const Operand& op, u8 instLen) const;
    void WriteOperand(const Operand& op, u64 val, u8 instLen, bool hasRex);
    void UpdateFlagsArithmetic(u64 result, u64 op1, u64 op2, u8 opSize, bool isSub);
    void UpdateFlagsLogic(u64 result, u8 opSize);
};

} // namespace Scarlett
