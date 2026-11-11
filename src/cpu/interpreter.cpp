#include "cpu/interpreter.h"
#include "kernel/hle_kernel.h"
#include "loader/pe_loader.h"
#include "common/logging.h"
#include <iomanip>
#include <sstream>

namespace Scarlett {

static u64* GetRegisterPtr(CpuContext& ctx, u8 regIdx) {
    switch (regIdx) {
        case 0: return &ctx.rax;
        case 1: return &ctx.rcx;
        case 2: return &ctx.rdx;
        case 3: return &ctx.rbx;
        case 4: return &ctx.rsp;
        case 5: return &ctx.rbp;
        case 6: return &ctx.rsi;
        case 7: return &ctx.rdi;
        case 8: return &ctx.r8;
        case 9: return &ctx.r9;
        case 10: return &ctx.r10;
        case 11: return &ctx.r11;
        case 12: return &ctx.r12;
        case 13: return &ctx.r13;
        case 14: return &ctx.r14;
        case 15: return &ctx.r15;
        default: return nullptr;
    }
}

DecodedInstruction X86Decoder::Decode(const u8* code, u64 rip) {
    DecodedInstruction inst{};
    u8 offset = 0;
    bool rexW = false;
    u8 rexR = 0, rexB = 0;

    bool isGs = false;
    // Skip prefixes: 0x65 (GS segment), 0x66 (operand size), 0x2E (CS override / branch hint), 0xF0 (LOCK), 0xF2/0xF3 (REP)
    while (offset < 15) {
        u8 p = code[offset];
        if (p == 0x65) {
            isGs = true;
            offset++;
        } else if (p == 0x66 || p == 0x2E || p == 0xF0 || p == 0xF2 || p == 0xF3) {
            offset++;
        } else {
            break;
        }
    }
    inst.isGsRelative = isGs;

    // Check for REX prefix (0x40 - 0x4F)
    if ((code[offset] & 0xF0) == 0x40) {
        u8 rex = code[offset++];
        rexW = (rex & 0x08) != 0;
        rexR = (rex & 0x04) ? 8 : 0;
        rexB = (rex & 0x01) ? 8 : 0;
    }

    u8 opcode = code[offset++];

    // 0x90: NOP
    if (opcode == 0x90) {
        inst.type = OpcodeType::Unknown;
        inst.length = offset;
        return inst;
    }

    // 0x0F 0x1F: Multi-byte NOP (NOP r/m)
    if (opcode == 0x0F && code[offset] == 0x1F) {
        offset++;
        u8 modrm = code[offset++];
        u8 mod = (modrm >> 6) & 0x03;
        u8 rm = modrm & 0x07;
        if (rm == 4) offset++; // SIB byte
        if (mod == 1) offset += 1;
        else if (mod == 2) offset += 4;
        inst.type = OpcodeType::Unknown; // treat as NOP
        inst.length = offset;
        return inst;
    }

    // 0xF4: HLT
    if (opcode == 0xF4) {
        inst.type = OpcodeType::Halt;
        inst.length = offset;
        return inst;
    }

    // 0x0F 0x0B: HLE Trap (UD2) followed by 32-bit hook ID
    if (opcode == 0x0F && code[offset] == 0x0B) {
        offset++;
        inst.type = OpcodeType::HleTrap;
        inst.immediate = *reinterpret_cast<const u32*>(code + offset);
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // 0xB8 - 0xBF: MOV r32/r64, imm32/imm64
    if (opcode >= 0xB8 && opcode <= 0xBF) {
        inst.type = OpcodeType::Mov;
        inst.regDest = (opcode - 0xB8) | rexB;
        if (rexW) {
            inst.immediate = *reinterpret_cast<const u64*>(code + offset);
            offset += 8;
        } else {
            inst.immediate = static_cast<u64>(*reinterpret_cast<const u32*>(code + offset));
            offset += 4;
        }
        inst.hasImmediate = true;
        inst.length = offset;
        return inst;
    }

    // 0x31: XOR r/m32 or r/m64
    if (opcode == 0x31) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Xor;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        inst.length = offset;
        return inst;
    }

    // 0x74: JE rel8
    if (opcode == 0x74) {
        inst.type = OpcodeType::Je;
        inst.displacement = static_cast<s8>(code[offset++]);
        inst.length = offset;
        return inst;
    }

    // 0x75: JNE rel8
    if (opcode == 0x75) {
        inst.type = OpcodeType::Jne;
        inst.displacement = static_cast<s8>(code[offset++]);
        inst.length = offset;
        return inst;
    }

    // 0xC7 /0: MOV r/m32, imm32 (e.g. movl $imm, disp(%rax))
    if (opcode == 0xC7) {
        u8 modrm = code[offset++];
        u8 subop = (modrm >> 3) & 0x07;
        if (subop == 0) {
            inst.type = OpcodeType::Mov;
            inst.regDest = (modrm & 0x07) | rexB; // base register
            u8 mod = (modrm >> 6) & 0x03;
            if (mod == 0) {
                inst.displacement = 0;
                inst.isMemoryStore = true;
            } else if (mod == 1) {
                inst.displacement = static_cast<s8>(code[offset++]);
                inst.isMemoryStore = true;
            } else if (mod == 2) {
                inst.displacement = *reinterpret_cast<const s32*>(code + offset);
                offset += 4;
                inst.isMemoryStore = true;
            }
            inst.immediate = static_cast<u64>(*reinterpret_cast<const u32*>(code + offset));
            offset += 4;
            inst.hasImmediate = true;
            inst.length = offset;
            return inst;
        }
    }
    if (opcode == 0x85) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Test;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        inst.length = offset;
        return inst;
    }

    // 0x0F 0x84: JE rel32
    if (opcode == 0x0F && code[offset] == 0x84) {
        offset++;
        inst.type = OpcodeType::Je;
        inst.displacement = *reinterpret_cast<const s32*>(code + offset);
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // 0x0F 0x85: JNE rel32
    if (opcode == 0x0F && code[offset] == 0x85) {
        offset++;
        inst.type = OpcodeType::Jne;
        inst.displacement = *reinterpret_cast<const s32*>(code + offset);
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // 0xFF /2: CALL near absolute indirect (e.g. call *disp(%rip))
    if (opcode == 0xFF) {
        u8 modrm = code[offset++];
        u8 subop = (modrm >> 3) & 0x07;
        if (subop == 2) { // CALL near indirect
            inst.type = OpcodeType::CallIndirect;
            if ((modrm & 0xC7) == 0x05) { // [rip + disp32]
                inst.isRipRelative = true;
                inst.displacement = *reinterpret_cast<const s32*>(code + offset);
                offset += 4;
            }
            inst.length = offset;
            return inst;
        }
    }

    // 0x01: ADD r/m64, r64
    if (rexW && opcode == 0x01) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Add;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        inst.length = offset;
        return inst;
    }

    // 0x89: MOV r/m64, r64
    if (rexW && opcode == 0x89) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Mov;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        inst.length = offset;
        return inst;
    }

    // 0x8B: MOV r64, r/m64
    if (opcode == 0x8B) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Mov;
        inst.regDest = ((modrm >> 3) & 0x07) | rexR;
        inst.regSrc = (modrm & 0x07) | rexB;

        // Check for GS:[disp32] (e.g. mov rax, gs:[0x30])
        if (inst.isGsRelative && (modrm & 0xC7) == 0x04 && code[offset] == 0x25) {
            offset++; // skip SIB 0x25
            inst.displacement = *reinterpret_cast<const s32*>(code + offset);
            offset += 4;
        } else if ((modrm & 0xC0) == 0x40) { // [reg + disp8]
            inst.displacement = static_cast<s8>(code[offset++]);
        } else if ((modrm & 0xC0) == 0x80) { // [reg + disp32]
            inst.displacement = *reinterpret_cast<const s32*>(code + offset);
            offset += 4;
        }
        inst.length = offset;
        return inst;
    }

    // 0x88: MOV r/m8, r8
    if (opcode == 0x88) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Mov;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        inst.isMemoryStore = true;
        if ((modrm & 0xC7) == 0x05) { // [rip + disp32]
            inst.isRipRelative = true;
            inst.displacement = *reinterpret_cast<const s32*>(code + offset);
            offset += 4;
        }
        inst.length = offset;
        return inst;
    }

    // 0x0F 0xB6: MOVZX r32/r64, r/m8
    if (opcode == 0x0F && code[offset] == 0xB6) {
        offset++;
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Movzx;
        inst.regDest = ((modrm >> 3) & 0x07) | rexR;
        inst.regSrc = (modrm & 0x07) | rexB;
        if ((modrm & 0xC7) == 0x05) { // [rip + disp32]
            inst.isRipRelative = true;
            inst.displacement = *reinterpret_cast<const s32*>(code + offset);
            offset += 4;
        }
        inst.length = offset;
        return inst;
    }

    // 0x0F 0x40 - 0x4F: CMOVcc
    if (opcode == 0x0F && (code[offset] >= 0x40 && code[offset] <= 0x4F)) {
        u8 cc = code[offset++] & 0x0F;
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Cmov;
        inst.conditionCode = cc;
        inst.regDest = ((modrm >> 3) & 0x07) | rexR;
        inst.regSrc = (modrm & 0x07) | rexB;
        inst.length = offset;
        return inst;
    }

    // 0x0F 0xB1: CMPXCHG r/m64, r64
    if (opcode == 0x0F && code[offset] == 0xB1) {
        offset++;
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Cmpxchg;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        if ((modrm & 0xC7) == 0x05) { // [rip + disp32]
            inst.isRipRelative = true;
            inst.displacement = *reinterpret_cast<const s32*>(code + offset);
            offset += 4;
        }
        inst.length = offset;
        return inst;
    }

    // 0x38 / 0x39 / 0x3B: CMP
    if (opcode == 0x38 || opcode == 0x39 || opcode == 0x3B) {
        u8 modrm = code[offset++];
        inst.type = OpcodeType::Cmp;
        inst.regDest = (modrm & 0x07) | rexB;
        inst.regSrc = ((modrm >> 3) & 0x07) | rexR;
        inst.length = offset;
        return inst;
    }

    // 0x83 / 0x81: ADD/SUB r64, imm
    if (rexW && (opcode == 0x83 || opcode == 0x81)) {
        u8 modrm = code[offset++];
        u8 subop = (modrm >> 3) & 0x07;
        inst.regDest = (modrm & 0x07) | rexB;

        if (subop == 0) inst.type = OpcodeType::Add;
        else if (subop == 5) inst.type = OpcodeType::Sub;

        if (opcode == 0x83) {
            inst.immediate = static_cast<s64>(static_cast<s8>(code[offset++]));
        } else {
            inst.immediate = static_cast<s64>(*reinterpret_cast<const s32*>(code + offset));
            offset += 4;
        }
        inst.hasImmediate = true;
        inst.length = offset;
        return inst;
    }

    // 0xE8: CALL rel32
    if (opcode == 0xE8) {
        inst.type = OpcodeType::Call;
        inst.displacement = *reinterpret_cast<const s32*>(code + offset);
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // 0xC3: RET
    if (opcode == 0xC3) {
        inst.type = OpcodeType::Ret;
        inst.length = offset;
        return inst;
    }

    // 0xEB: JMP rel8
    if (opcode == 0xEB) {
        inst.type = OpcodeType::Jmp;
        inst.displacement = static_cast<s8>(code[offset++]);
        inst.length = offset;
        return inst;
    }

    // 0xE9: JMP rel32
    if (opcode == 0xE9) {
        inst.type = OpcodeType::Jmp;
        inst.displacement = *reinterpret_cast<const s32*>(code + offset);
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // Unknown opcode
    inst.type = OpcodeType::Unknown;
    inst.length = 1;
    return inst;
}

Interpreter::Interpreter(CpuContext& ctx, MemoryManager& memory, HleKernel* kernel, const std::vector<ImportedFunction>* imports)
    : m_ctx(ctx), m_memory(memory), m_kernel(kernel), m_imports(imports) {}

bool Interpreter::Step() {
    if (m_halted) return false;

    void* hostPtr = m_memory.Translate(m_ctx.rip);
    if (!hostPtr) {
        LOG_FATAL("Interpreter", "Access violation at RIP: 0x" + std::to_string(m_ctx.rip));
        m_halted = true;
        return false;
    }

    const u8* code = reinterpret_cast<const u8*>(hostPtr);
    DecodedInstruction inst = X86Decoder::Decode(code, m_ctx.rip);

    u64 currentRip = m_ctx.rip;
    m_ctx.rip += inst.length;
    m_instructionsExecuted++;

    switch (inst.type) {
        case OpcodeType::Halt:
            LOG_INFO("Interpreter", "HLT instruction executed. Execution finished.");
            m_halted = true;
            return false;

        case OpcodeType::Mov: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            if (inst.isGsRelative) {
                GuestAddr srcAddr = m_ctx.gsBase + inst.displacement;
                if (dst) *dst = m_memory.Read<u64>(srcAddr);
            } else if (inst.isMemoryStore) {
                if (inst.isRipRelative) {
                    GuestAddr targetAddr = currentRip + inst.length + inst.displacement;
                    m_memory.Write<u8>(targetAddr, static_cast<u8>(m_ctx.rax & 0xFF));
                } else if (dst) {
                    GuestAddr targetAddr = *dst + inst.displacement;
                    m_memory.Write<u32>(targetAddr, static_cast<u32>(inst.immediate));
                }
            } else if (inst.displacement != 0) {
                u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
                if (src && dst) {
                    GuestAddr srcAddr = *src + inst.displacement;
                    *dst = m_memory.Read<u64>(srcAddr);
                }
            } else if (inst.hasImmediate) {
                if (dst) *dst = inst.immediate;
            } else {
                u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
                if (dst && src) *dst = *src;
            }
            break;
        }

        case OpcodeType::Movzx: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            GuestAddr srcAddr = inst.isRipRelative ? (currentRip + inst.length + inst.displacement) : 0;
            u8 val = m_memory.Read<u8>(srcAddr);
            if (dst) *dst = static_cast<u64>(val);
            break;
        }

        case OpcodeType::Cmov: {
            bool condMet = false;
            if (inst.conditionCode == 4) condMet = (m_ctx.rflags & 0x40) != 0; // CMOVE (ZF == 1)
            else if (inst.conditionCode == 5) condMet = (m_ctx.rflags & 0x40) == 0; // CMOVNE (ZF == 0)
            if (condMet) {
                u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
                u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
                if (dst && src) *dst = *src;
            }
            break;
        }

        case OpcodeType::Cmpxchg: {
            GuestAddr memAddr = inst.isRipRelative ? (currentRip + inst.length + inst.displacement) : 0;
            u64 val = m_memory.Read<u64>(memAddr);
            u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
            if (m_ctx.rax == val) {
                m_ctx.rflags |= 0x40; // ZF = 1
                if (src) m_memory.Write<u64>(memAddr, *src);
            } else {
                m_ctx.rflags &= ~0x40; // ZF = 0
                m_ctx.rax = val;
            }
            break;
        }

        case OpcodeType::Cmp: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
            if (dst && src) {
                if (*dst == *src) m_ctx.rflags |= 0x40;
                else m_ctx.rflags &= ~0x40;
            }
            break;
        }

        case OpcodeType::Xor: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
            if (dst && src) {
                *dst ^= *src;
                // Update basic zero flag in RFLAGS
                if (*dst == 0) m_ctx.rflags |= 0x40; // ZF = 1
                else m_ctx.rflags &= ~0x40;
            }
            break;
        }

        case OpcodeType::Add: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            if (inst.hasImmediate) {
                if (dst) *dst += inst.immediate;
            } else {
                u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
                if (dst && src) *dst += *src;
            }
            break;
        }

        case OpcodeType::Sub: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            if (dst) *dst -= inst.immediate;
            break;
        }

        case OpcodeType::Push: {
            u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
            m_ctx.rsp -= 8;
            if (src) m_memory.Write<u64>(m_ctx.rsp, *src);
            break;
        }

        case OpcodeType::Pop: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            if (dst) *dst = m_memory.Read<u64>(m_ctx.rsp);
            m_ctx.rsp += 8;
            break;
        }

        case OpcodeType::Call: {
            // Push return address
            m_ctx.rsp -= 8;
            m_memory.Write<u64>(m_ctx.rsp, m_ctx.rip);
            m_ctx.rip = m_ctx.rip + inst.displacement;
            break;
        }

        case OpcodeType::CallIndirect: {
            GuestAddr targetPtrAddr = currentRip + inst.length + inst.displacement;
            GuestAddr targetAddr = m_memory.Read<GuestAddr>(targetPtrAddr);
            std::stringstream ss;
            ss << "CallIndirect: reading IAT from 0x" << std::hex << targetPtrAddr << " -> target: 0x" << targetAddr;
            LOG_DEBUG("Interpreter", ss.str());
            m_ctx.rsp -= 8;
            m_memory.Write<u64>(m_ctx.rsp, m_ctx.rip);
            m_ctx.rip = targetAddr;
            break;
        }

        case OpcodeType::Test: {
            u64* dst = GetRegisterPtr(m_ctx, inst.regDest);
            u64* src = GetRegisterPtr(m_ctx, inst.regSrc);
            if (dst && src) {
                u64 res = *dst & *src;
                if (res == 0) m_ctx.rflags |= 0x40; // ZF = 1
                else m_ctx.rflags &= ~0x40;
            }
            break;
        }

        case OpcodeType::Je: {
            if (m_ctx.rflags & 0x40) {
                m_ctx.rip = m_ctx.rip + inst.displacement;
            }
            break;
        }

        case OpcodeType::Jne: {
            if (!(m_ctx.rflags & 0x40)) {
                m_ctx.rip = m_ctx.rip + inst.displacement;
            }
            break;
        }

        case OpcodeType::Ret: {
            m_ctx.rip = m_memory.Read<u64>(m_ctx.rsp);
            m_ctx.rsp += 8;
            break;
        }

        case OpcodeType::Jmp: {
            m_ctx.rip = m_ctx.rip + inst.displacement;
            break;
        }

        case OpcodeType::HleTrap: {
            u32 hookId = static_cast<u32>(inst.immediate);
            std::stringstream ss;
            ss << "HLE Trap triggered! HookID = " << hookId;
            LOG_DEBUG("Interpreter", ss.str());

            if (m_kernel && m_imports && hookId > 0 && hookId <= m_imports->size()) {
                const auto& imp = (*m_imports)[hookId - 1];
                LOG_INFO("HLE", "Dispatching GameOS Call: " + imp.moduleName + "!" + imp.functionName);
                m_kernel->ExecuteHook(imp.moduleName, imp.functionName, m_ctx);

                if (imp.functionName == "ExitProcess") {
                    m_halted = true;
                    return false;
                }
            }

            // Check if called via CALL (valid stack return address)
            u64 retAddr = m_memory.Read<u64>(m_ctx.rsp);
            if (retAddr >= GUEST_MEMORY_BASE) {
                m_ctx.rip = retAddr;
                m_ctx.rsp += 8;
            }
            break;
        }

        case OpcodeType::Unknown:
        default:
            LOG_WARN("Interpreter", "Skipping unhandled opcode at 0x" + std::to_string(currentRip));
            break;
    }

    return true;
}

bool Interpreter::Run(u64 maxInstructions) {
    LOG_INFO("Interpreter", "Entering x86-64 Zen 2 execution loop...");
    while (!m_halted && m_instructionsExecuted < maxInstructions) {
        if (!Step()) break;
    }

    std::stringstream ss;
    ss << "Execution halted after " << m_instructionsExecuted << " instructions.";
    LOG_INFO("Interpreter", ss.str());
    return true;
}

} // namespace Scarlett
