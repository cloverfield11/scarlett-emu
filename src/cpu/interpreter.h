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
    Int,
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
    Rcl,
    Rcr,
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
    Clzero,
    Cmpxchg,
    Cmpxchg16b,
    Cmpxchg8b,
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
    MovqFromGp,
    MovqToGp,
    MovqXmm,
    Movsd,
    Movss,
    Punpcklbw,
    Xorps,
    Andps,
    Orps,
    Addsd,
    Subsd,
    Mulsd,
    Divsd,
    Minsd,
    Maxsd,
    Addss,
    Subss,
    Mulss,
    Divss,
    Minss,
    Maxss,
    Rsqrtss,
    Rcpss,
    Addps,
    Subps,
    Mulps,
    Divps,
    Minps,
    Maxps,
    Sqrtps,
    Rsqrtps,
    Rcpps,
    Addpd,
    Subpd,
    Mulpd,
    Divpd,
    Minpd,
    Maxpd,
    Andnps,
    Movmskps,
    Cvtsd2ss,
    Cvtss2sd,
    Cvtps2pd,
    Cvtpd2ps,
    Cvtdq2ps,
    Cvtps2dq,
    Cvttps2dq,
    Cvttpd2dq,
    Cvtpd2dq,
    Cvtdq2pd,
    Cmpps,
    Cmppd,
    Cmpss,
    Cmpsd,
    Sqrtss,
    Sqrtsd,
    Comiss,
    Comisd,
    Cvtsi2sd,
    Cvtsi2ss,
    Cvtsd2si,
    Cvtss2si,
    Cvttsd2si,
    Cvttss2si,
    Bswap,
    Cdq,
    Cdqe,
    Movsx,
    Bts,
    Btr,
    Btc,
    Psrlw,
    Psllw,
    Psraw,
    Psrlq,
    Psrldq,
    Psllq,
    Pslldq,
    Psrld,
    Pslld,
    Psrad,
    Psubb,
    Psubw,
    Psubd,
    Psubq,
    Paddb,
    Paddw,
    Paddd,
    Paddq,
    Pshuflw,
    Pshufhw,
    Pshufd,
    Pcmpeqb,
    Pcmpeqw,
    Pcmpeqd,
    Pmovmskb,
    Bsf,
    Bsr,
    Tzcnt,
    Lzcnt,
    Popcnt,
    Punpcklqdq,
    Punpckhqdq,
    Punpcklwd,
    Punpckldq,
    Punpckhbw,
    Punpckhwd,
    Punpckhdq,
    Vzeroupper,
    Vpxor,
    Vpcmpeqb,
    Vpcmpeqw,
    Vpcmpeqd,
    Vmovdqa,
    Vmovdqu,
    Vmovss,
    Vmovsd,
    Vcvtss2sd,
    Vcvtsd2ss,
    Vcvtps2pd,
    Vcvtpd2ps,
    Vcvtpd2dq,
    Vcvtsi2ss,
    Vcvtsi2sd,
    Vcvtss2si,
    Vcvtsd2si,
    Vcvttss2si,
    Vcvttsd2si,
    Vcvtdq2ps,
    Vcvtps2dq,
    Vcvttps2dq,
    Vcvttpd2dq,
    Vcvtdq2pd,
    Vpsrlw,
    Vpsllw,
    Vpsraw,
    Vpsrld,
    Vpslld,
    Vpsrad,
    Vpsrlq,
    Vpsllq,
    Vpsrldq,
    Vpslldq,
    Vpsllvd,
    Vpsllvq,
    Vpsrlvd,
    Vpsrlvq,
    Vpsravd,
    Vpcmpgtb,
    Vpcmpgtw,
    Vpcmpgtd,
    Vpcmpgtq,
    Pcmpgtb,
    Pcmpgtw,
    Pcmpgtd,
    Pcmpgtq,
    Vpaddb,
    Vpaddw,
    Vpaddd,
    Vpaddq,
    Vpsubb,
    Vpsubw,
    Vpsubd,
    Vpsubq,
    Vpshufd,
    Vpshuflw,
    Vpshufhw,
    Vextract128,
    Vinsert128,
    Ptest,
    Vptest,
    Vpunpckldq,
    Vpunpck,
    Vunpcklps,
    Vunpcklpd,
    Vunpckhps,
    Vunpckhpd,
    Vandps,
    Vandnps,
    Vorps,
    Vaddps,
    Vaddpd,
    Vaddss,
    Vaddsd,
    Vsubps,
    Vsubpd,
    Vsubss,
    Vsubsd,
    Vmulps,
    Vmulpd,
    Vmulss,
    Vmulsd,
    Vdivps,
    Vdivpd,
    Vdivss,
    Vdivsd,
    Vminps,
    Vminpd,
    Vminss,
    Vminsd,
    Vmaxps,
    Vmaxpd,
    Vmaxss,
    Vmaxsd,
    Vshufps,
    Vshufpd,
    Vcmpps,
    Vcmppd,
    Vcmpss,
    Vcmpsd,
    Vpmovsxdq,
    Vpmovsx,
    Vpmovzx,
    Pmovsx,
    Pmovzx,
    Vpcmpeqq,
    Vfma,
    Pcmpistri,
    Unpcklps,
    Unpcklpd,
    Shufps,
    Shufpd,
    Fnstcw,
    Stmxcsr,
    Blsi,
    Blsr,
    Blsmsk,
    Andn,
    Bzhi,
    Bextr,
    Shlx,
    Shrx,
    Sarx,
    Rorx,
    Vpbroadcast,
    Vpermq,
    Vpermilps,
    Mulx,
    Pdep,
    Pext,
    Vmovhps,
    Vmovlps,
    Vmovddup,
    Movddup,
    Vmovsldup,
    Movsldup,
    Vmovshdup,
    Movshdup,
    Vhaddps,
    Vsqrtps,
    Vsqrtpd,
    Vsqrtss,
    Vsqrtsd,
    Vrsqrtps,
    Vrsqrtss,
    Vrcpps,
    Vrcpss,
    Vblendps,
    Vblendpd,
    Vpblendw,
    Vpblendd,
    Vblendv,
    Vroundps,
    Vroundpd,
    Vroundss,
    Vroundsd,
    Vpackssdw,
    Packssdw,
    Vpacksswb,
    Packsswb,
    Vpackuswb,
    Packuswb,
    Vpackusdw,
    Packusdw,
    Vinsertps,
    Vpextr,
    Vpinsr,
    Vpsignb,
    Vpsignw,
    Vpsignd,
    Psignb,
    Psignw,
    Psignd,
    Vpshufb,
    Pshufb,
    Vpabsb,
    Vpabsw,
    Vpabsd,
    Pabsb,
    Pabsw,
    Pabsd,
    Vpmulld,
    Pmulld,
    Vpmuldq,
    Vpalignr,
    Palignr,
    Vpclmulqdq,
    Pclmulqdq,
    Vpminsb,
    Vpminsd,
    Vpminuw,
    Vpminud,
    Vpmaxsb,
    Vpmaxsd,
    Vpmaxuw,
    Vpmaxud,
    VpmaskmovLoad,
    VpmaskmovStore,
    Vcvtps2ph,
    Vcvtph2ps
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
    u8 conditionCode2{0};
    bool hasRex{false};
    bool hasLockPrefix{false};
    bool hasRepPrefix{false};

    Operand op1; // Typically destination
    Operand op2; // Typically source
    Operand op3; // Extra source (AVX vvvv)
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
    struct TraceEntry {
        u64 rip{0};
        u64 rsp{0};
        u8 bytes[8]{};
        u8 len{0};
    };
    struct DecodeCacheEntry {
        u64 rip{0};
        u64 code0{0};
        u64 code1{0};
        DecodedInstruction inst{};
    };
    static constexpr size_t DECODE_CACHE_SIZE = 16384;
    static constexpr size_t TRACE_SIZE = 64;

    CpuContext& m_ctx;
    MemoryManager& m_memory;
    HleKernel* m_kernel{nullptr};
    const std::vector<ImportedFunction>* m_imports{nullptr};
    bool m_halted{false};
    u64 m_instructionsExecuted{0};
    std::vector<DecodeCacheEntry> m_decodeCache;
    TraceEntry m_trace[TRACE_SIZE]{};
    size_t m_traceIdx{0};

    void DumpRecentTrace() const;
    u64 ReadOperand(const Operand& op, u8 instLen) const;
    void WriteOperand(const Operand& op, u64 val, u8 instLen, bool hasRex);
    void UpdateFlagsArithmetic(u64 result, u64 op1, u64 op2, u8 opSize, bool isSub, bool updateCarry = true);
    void UpdateFlagsLogic(u64 result, u8 opSize);
};

} // namespace Scarlett
