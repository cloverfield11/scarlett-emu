#include "cpu/interpreter.h"
#include "kernel/hle_kernel.h"
#include "kernel/modules/kernel32.h"
#include "loader/pe_loader.h"
#include "common/logging.h"
#include <iomanip>
#include <sstream>
#include <cmath>

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

u64 Operand::GetAddress(const CpuContext& ctx, u64 nextRip) const {
    if (isRipRelative) {
        return nextRip + displacement;
    }
    u64 addr = 0;
    if (isGsRelative) {
        addr = ctx.gsBase;
    }
    if (baseReg != 0xFF) {
        u64* b = GetRegisterPtr(const_cast<CpuContext&>(ctx), baseReg);
        if (b) addr += *b;
    }
    if (indexReg != 0xFF) {
        u64* idx = GetRegisterPtr(const_cast<CpuContext&>(ctx), indexReg);
        if (idx) addr += (*idx) * scale;
    }
    addr += displacement;
    return addr;
}

static void DecodeModRM(const u8* code, u8& offset, u8 rex, bool isGs, u8 opSize, Operand& opReg, Operand& opMem) {
    u8 rexR = (rex & 0x04) ? 8 : 0;
    u8 rexX = (rex & 0x02) ? 8 : 0;
    u8 rexB = (rex & 0x01) ? 8 : 0;

    u8 modrm = code[offset++];
    u8 mod = (modrm >> 6) & 3;
    u8 reg = ((modrm >> 3) & 7) | rexR;
    u8 rm = modrm & 7;

    opReg.kind = Operand::Kind::Register;
    opReg.reg = reg;
    opReg.size = opSize;

    if (mod == 3) {
        opMem.kind = Operand::Kind::Register;
        opMem.reg = rm | rexB;
        opMem.size = opSize;
        return;
    }

    opMem.kind = Operand::Kind::Memory;
    opMem.size = opSize;
    opMem.isGsRelative = isGs;

    u8 base = rm | rexB;
    if (rm == 4) { // SIB byte present
        u8 sib = code[offset++];
        u8 sibScale = (sib >> 6) & 3;
        u8 sibIndex = ((sib >> 3) & 7) | rexX;
        u8 sibBase = (sib & 7) | rexB;

        opMem.scale = 1 << sibScale;
        if (sibIndex != 4) {
            opMem.indexReg = sibIndex;
        }
        if (mod == 0 && (sib & 7) == 5) {
            opMem.baseReg = 0xFF;
            opMem.displacement = *reinterpret_cast<const s32*>(code + offset);
            offset += 4;
        } else {
            opMem.baseReg = sibBase;
        }
    } else if (mod == 0 && rm == 5) {
        opMem.isRipRelative = true;
        opMem.displacement = *reinterpret_cast<const s32*>(code + offset);
        offset += 4;
    } else {
        opMem.baseReg = base;
    }

    if (mod == 1) {
        opMem.displacement = static_cast<s8>(code[offset++]);
    } else if (mod == 2) {
        opMem.displacement = *reinterpret_cast<const s32*>(code + offset);
        offset += 4;
    }
}

static bool CheckCondition(u8 cond, u64 rflags) {
    bool cf = (rflags & 0x001) != 0;
    bool pf = (rflags & 0x004) != 0;
    bool zf = (rflags & 0x040) != 0;
    bool sf = (rflags & 0x080) != 0;
    bool of = (rflags & 0x800) != 0;

    switch (cond & 0x0F) {
        case 0:  return of;
        case 1:  return !of;
        case 2:  return cf;
        case 3:  return !cf;
        case 4:  return zf;
        case 5:  return !zf;
        case 6:  return cf || zf;
        case 7:  return !cf && !zf;
        case 8:  return sf;
        case 9:  return !sf;
        case 10: return pf;
        case 11: return !pf;
        case 12: return sf != of;
        case 13: return sf == of;
        case 14: return zf || (sf != of);
        case 15: return !zf && (sf == of);
        default: return false;
    }
}

DecodedInstruction X86Decoder::Decode(const u8* code, u64 rip) {
    DecodedInstruction inst{};
    u8 offset = 0;
    u8 rex = 0;
    bool isGs = false;
    bool is16Bit = false;
    bool has66 = false;
    bool hasF2 = false;
    bool hasF3 = false;

    // 1. Decode prefixes
    while (offset < 15) {
        u8 p = code[offset];
        if (p == 0x65) {
            isGs = true;
            offset++;
        } else if (p == 0x66) {
            has66 = true;
            is16Bit = true;
            offset++;
        } else if (p == 0xF0) {
            inst.hasLockPrefix = true;
            offset++;
        } else if (p == 0xF3) {
            hasF3 = true;
            inst.hasRepPrefix = true;
            offset++;
        } else if (p == 0xF2) {
            hasF2 = true;
            offset++;
        } else if (p == 0x2E || p == 0x3E || p == 0x67) {
            offset++;
        } else {
            break;
        }
    }

    // 2. Decode REX prefix (0x40 - 0x4F in 64-bit mode)
    while ((code[offset] & 0xF0) == 0x40) {
        rex = code[offset++];
        inst.hasRex = true;
    }

    bool rexW = (rex & 0x08) != 0;
    u8 rexR = (rex & 0x04) ? 8 : 0;
    u8 rexB = (rex & 0x01) ? 8 : 0;
    u8 defaultOpSize = rexW ? 8 : (is16Bit ? 2 : 4);
    inst.opSize = defaultOpSize;

    u8 opcode = code[offset++];

    // VEX 2-byte (0xC5) and 3-byte (0xC4) prefixes
    if (opcode == 0xC5 || opcode == 0xC4) {
        u8 m_mmmm = 1;
        bool vexW = false;
        u8 vvvv = 0;
        bool vexL = false;
        u8 pp = 0;
        u8 rexVex = 0;

        if (opcode == 0xC5) {
            u8 byte1 = code[offset++];
            u8 vexR = (byte1 & 0x80) ? 0 : 4;
            vvvv = (~byte1 >> 3) & 0x0F;
            vexL = (byte1 & 0x04) != 0;
            pp = byte1 & 0x03; // 0=none, 1=66, 2=F3, 3=F2
            rexVex = vexR;
        } else {
            u8 byte1 = code[offset++];
            u8 byte2 = code[offset++];
            u8 vexR = (byte1 & 0x80) ? 0 : 4;
            u8 vexX = (byte1 & 0x40) ? 0 : 2;
            u8 vexB = (byte1 & 0x20) ? 0 : 1;
            m_mmmm = byte1 & 0x1F; // 1 = 0F, 2 = 0F 38, 3 = 0F 3A
            vexW = (byte2 & 0x80) != 0;
            vvvv = (~byte2 >> 3) & 0x0F;
            vexL = (byte2 & 0x04) != 0;
            pp = byte2 & 0x03;
            rexVex = vexR | vexX | vexB | (vexW ? 8 : 0);
        }

        u8 opVex = code[offset++];
        u8 vecSize = vexL ? 32 : 16;
        inst.opSize = vecSize;

        auto setOp3Vvvv = [&]() {
            inst.op3.kind = Operand::Kind::Register;
            inst.op3.reg = vvvv;
            inst.op3.size = vecSize;
        };

        if (m_mmmm == 1) { // 0F map
            if (opVex == 0x77) { // VZEROUPPER
                inst.type = OpcodeType::Vzeroupper;
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x10) {
                if (pp == 2) { // VMOVSS load/merge
                    inst.type = OpcodeType::Vmovss;
                    DecodeModRM(code, offset, rexVex, isGs, 4, inst.op1, inst.op2);
                    setOp3Vvvv();
                } else if (pp == 3) { // VMOVSD load/merge
                    inst.type = OpcodeType::Vmovsd;
                    DecodeModRM(code, offset, rexVex, isGs, 8, inst.op1, inst.op2);
                    setOp3Vvvv();
                } else { // VMOVUPS / VMOVUPD load
                    inst.type = OpcodeType::Vmovdqu;
                    DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                }
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x11) {
                if (pp == 2) { // VMOVSS store/merge
                    inst.type = OpcodeType::Vmovss;
                    DecodeModRM(code, offset, rexVex, isGs, 4, inst.op2, inst.op1);
                    setOp3Vvvv();
                } else if (pp == 3) { // VMOVSD store/merge
                    inst.type = OpcodeType::Vmovsd;
                    DecodeModRM(code, offset, rexVex, isGs, 8, inst.op2, inst.op1);
                    setOp3Vvvv();
                } else { // VMOVUPS / VMOVUPD store
                    inst.type = OpcodeType::Vmovdqu;
                    DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op2, inst.op1);
                }
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x14 && (pp == 0 || pp == 1)) {
                inst.type = (pp == 1) ? OpcodeType::Vunpcklpd : OpcodeType::Vunpcklps;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x28 && (pp == 0 || pp == 1)) {
                inst.type = OpcodeType::Vmovdqa;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x29 && (pp == 0 || pp == 1)) {
                inst.type = OpcodeType::Vmovdqa;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op2, inst.op1);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x2A && (pp == 2 || pp == 3)) {
                inst.type = (pp == 2) ? OpcodeType::Vcvtsi2ss : OpcodeType::Vcvtsi2sd;
                DecodeModRM(code, offset, rexVex, isGs, vexW ? 8 : 4, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
            if ((opVex == 0x2C || opVex == 0x2D) && (pp == 2 || pp == 3)) {
                if (opVex == 0x2C) inst.type = (pp == 2) ? OpcodeType::Vcvttss2si : OpcodeType::Vcvttsd2si;
                else inst.type = (pp == 2) ? OpcodeType::Vcvtss2si : OpcodeType::Vcvtsd2si;
                DecodeModRM(code, offset, rexVex, isGs, (pp == 2) ? 4 : 8, inst.op1, inst.op2);
                inst.op1.size = vexW ? 8 : 4;
                inst.hasRex = vexW || (inst.op1.reg >= 8);
                inst.length = offset;
                return inst;
            }
            if ((opVex == 0x2E || opVex == 0x2F) && (pp == 0 || pp == 1)) {
                inst.type = (pp == 1) ? OpcodeType::Comisd : OpcodeType::Comiss;
                DecodeModRM(code, offset, rexVex, isGs, (pp == 1) ? 8 : 4, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if ((opVex == 0x54 || opVex == 0xDB) && (pp == 0 || pp == 1)) { inst.type = OpcodeType::Vandps; }
            else if (opVex == 0x55 && (pp == 0 || pp == 1)) { inst.type = OpcodeType::Vandnps; }
            else if ((opVex == 0x56 || opVex == 0xEB) && (pp == 0 || pp == 1)) { inst.type = OpcodeType::Vorps; }
            else if (opVex == 0x57 && (pp == 0 || pp == 1)) { inst.type = OpcodeType::Vpxor; }
            else if (opVex == 0xD4 && pp == 1) { inst.type = OpcodeType::Vpaddq; }
            else if (opVex == 0xFA && pp == 1) { inst.type = OpcodeType::Vpsubd; }
            else if (opVex == 0xFB && pp == 1) { inst.type = OpcodeType::Vpsubq; }
            else if (opVex == 0xFE && pp == 1) { inst.type = OpcodeType::Vpaddd; }
            else if (opVex == 0x58) {
                inst.type = (pp == 2) ? OpcodeType::Vaddss : (pp == 3) ? OpcodeType::Vaddsd : (pp == 1) ? OpcodeType::Vaddpd : OpcodeType::Vaddps;
            } else if (opVex == 0x59) {
                inst.type = (pp == 2) ? OpcodeType::Vmulss : (pp == 3) ? OpcodeType::Vmulsd : (pp == 1) ? OpcodeType::Vmulpd : OpcodeType::Vmulps;
            } else if (opVex == 0x5C) {
                inst.type = (pp == 2) ? OpcodeType::Vsubss : (pp == 3) ? OpcodeType::Vsubsd : (pp == 1) ? OpcodeType::Vsubpd : OpcodeType::Vsubps;
            } else if (opVex == 0x5E) {
                inst.type = (pp == 2) ? OpcodeType::Vdivss : (pp == 3) ? OpcodeType::Vdivsd : (pp == 1) ? OpcodeType::Vdivpd : OpcodeType::Vdivps;
            }
            if (inst.type != OpcodeType::Unknown) {
                u8 memSz = (pp == 2) ? 4 : (pp == 3) ? 8 : vecSize;
                DecodeModRM(code, offset, rexVex, isGs, memSz, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x5A) {
                if (pp == 0) {
                    inst.type = OpcodeType::Vcvtps2pd;
                    DecodeModRM(code, offset, rexVex, isGs, vecSize / 2, inst.op1, inst.op2);
                } else if (pp == 1) {
                    inst.type = OpcodeType::Vcvtpd2ps;
                    DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                } else {
                    inst.type = (pp == 2) ? OpcodeType::Vcvtss2sd : OpcodeType::Vcvtsd2ss;
                    DecodeModRM(code, offset, rexVex, isGs, (pp == 2) ? 4 : 8, inst.op1, inst.op2);
                    setOp3Vvvv();
                }
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x62 && pp == 1) {
                inst.type = OpcodeType::Vpunpckldq;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x5B && (pp == 0 || pp == 1 || pp == 2)) {
                inst.type = (pp == 0) ? OpcodeType::Vcvtdq2ps : (pp == 1) ? OpcodeType::Vcvtps2dq : OpcodeType::Vcvttps2dq;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x6E && pp == 1) {
                inst.type = OpcodeType::MovqFromGp;
                DecodeModRM(code, offset, rexVex, isGs, vexW ? 8 : 4, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x6F) {
                inst.type = OpcodeType::Vmovdqu;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x70 && pp == 1) { // VPSHUFD
                inst.type = OpcodeType::Vpshufd;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                inst.op3.kind = Operand::Kind::Immediate;
                inst.op3.imm = code[offset++];
                inst.length = offset;
                return inst;
            }
            if ((opVex == 0x72 || opVex == 0x73) && pp == 1) {
                u8 modrm = code[offset];
                u8 subop = (modrm >> 3) & 7;
                Operand unused;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, unused, inst.op2);
                inst.op1.kind = Operand::Kind::Register;
                inst.op1.reg = vvvv;
                inst.op1.size = vecSize;
                inst.op3.kind = Operand::Kind::Immediate;
                inst.op3.imm = code[offset++];
                if (opVex == 0x72) {
                    if (subop == 2) inst.type = OpcodeType::Vpsrld;
                    else if (subop == 4) inst.type = OpcodeType::Vpsrad;
                    else if (subop == 6) inst.type = OpcodeType::Vpslld;
                } else {
                    if (subop == 2) inst.type = OpcodeType::Vpsrlq;
                    else if (subop == 3) inst.type = OpcodeType::Vpsrldq;
                    else if (subop == 6) inst.type = OpcodeType::Vpsllq;
                    else if (subop == 7) inst.type = OpcodeType::Vpslldq;
                }
                inst.length = offset;
                return inst;
            }
            if ((opVex == 0x74 || opVex == 0x75 || opVex == 0x76) && pp == 1) {
                inst.type = (opVex == 0x74) ? OpcodeType::Vpcmpeqb : (opVex == 0x75) ? OpcodeType::Vpcmpeqw : OpcodeType::Vpcmpeqd;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x7E && pp == 1) {
                inst.type = OpcodeType::MovqToGp;
                DecodeModRM(code, offset, rexVex, isGs, vexW ? 8 : 4, inst.op2, inst.op1);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x7E && pp == 2) {
                inst.type = OpcodeType::MovqXmm;
                DecodeModRM(code, offset, rexVex, isGs, 8, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x7F || opVex == 0xE7) {
                inst.type = OpcodeType::Vmovdqu;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op2, inst.op1);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0xAE && pp == 0) { // VLDMXCSR / VSTMXCSR / VZERO...
                u8 modrm = code[offset];
                u8 mod = (modrm >> 6) & 3;
                u8 subop = (modrm >> 3) & 7;
                if (mod != 3 && (subop == 2 || subop == 3)) {
                    Operand unused;
                    DecodeModRM(code, offset, rexVex, isGs, 4, unused, inst.op1);
                    inst.type = (subop == 3) ? OpcodeType::Stmxcsr : OpcodeType::Nop;
                    inst.length = offset;
                    return inst;
                }
            }
            if (opVex == 0xC6 && pp == 0) { // VSHUFPS
                inst.type = OpcodeType::Vshufps;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                inst.conditionCode = vvvv;
                inst.op3.kind = Operand::Kind::Immediate;
                inst.op3.imm = code[offset++];
                inst.length = offset;
                return inst;
            }
            if (opVex == 0xD6 && pp == 1) {
                inst.type = OpcodeType::MovqXmm;
                DecodeModRM(code, offset, rexVex, isGs, 8, inst.op2, inst.op1);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0xD7 && pp == 1) {
                inst.type = OpcodeType::Pmovmskb;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                inst.op1.size = 4;
                inst.op2.size = vecSize;
                inst.length = offset;
                return inst;
            }
            if (opVex == 0xE6 && (pp == 1 || pp == 2 || pp == 3)) {
                inst.type = (pp == 1) ? OpcodeType::Vcvttpd2dq : (pp == 2) ? OpcodeType::Vcvtdq2pd : OpcodeType::Vcvtpd2dq;
                DecodeModRM(code, offset, rexVex, isGs, (pp == 2) ? (vecSize / 2) : vecSize, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0xEF && pp == 1) {
                inst.type = OpcodeType::Vpxor;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
        } else if (m_mmmm == 2 && pp == 1) { // 0F 38 map with 66 prefix
            if (opVex == 0x25) { // VPMOVSXDQ
                inst.type = OpcodeType::Vpmovsxdq;
                DecodeModRM(code, offset, rexVex, isGs, vecSize == 32 ? 16 : 8, inst.op1, inst.op2);
                inst.length = offset;
                return inst;
            }
            if (opVex == 0x29) { // VPCMPEQQ
                inst.type = OpcodeType::Vpcmpeqq;
                DecodeModRM(code, offset, rexVex, isGs, vecSize, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
            // FMA3 instructions: 0x98..0x9F, 0xA8..0xAF, 0xB8..0xBF
            if (opVex >= 0x98 && opVex <= 0xBF && (opVex & 0x08) != 0) {
                u8 lo = opVex & 0x0F;
                bool isScalar = (opVex & 1) != 0;
                u8 order = (opVex >> 4) - 9; // 0=132, 1=213, 2=231
                bool isSub = (lo == 0x0A || lo == 0x0B || lo == 0x0E || lo == 0x0F);
                bool isNeg = (lo >= 0x0C);
                inst.type = OpcodeType::Vfma;
                inst.conditionCode = (order & 3) | (isSub ? 4 : 0) | (isNeg ? 8 : 0) | (isScalar ? 16 : 0) | (vexW ? 32 : 0);
                u8 memSz = isScalar ? (vexW ? 8 : 4) : vecSize;
                DecodeModRM(code, offset, rexVex, isGs, memSz, inst.op1, inst.op2);
                setOp3Vvvv();
                inst.length = offset;
                return inst;
            }
        }
    }

    // 0x90: NOP
    if (opcode == 0x90 || opcode == 0x9B) { // NOP / FWAIT
        inst.type = OpcodeType::Nop;
        inst.length = offset;
        return inst;
    }

    // 0xD9: x87 FPU (FNSTCW / FLDCW)
    if (opcode == 0xD9) {
        u8 modrm = code[offset];
        u8 mod = (modrm >> 6) & 3;
        u8 subop = (modrm >> 3) & 7;
        if (mod != 3) {
            Operand unused;
            DecodeModRM(code, offset, rex, isGs, 2, unused, inst.op1);
            if (subop == 7) {
                inst.type = OpcodeType::Fnstcw;
            } else {
                inst.type = OpcodeType::Nop; // e.g., FLDCW (subop 5)
            }
            inst.length = offset;
            return inst;
        }
    }

    // 0x98: CDQE / CWDE
    if (opcode == 0x98) {
        inst.type = OpcodeType::Cdqe;
        inst.length = offset;
        return inst;
    }

    // 0x99: CQO / CDQ
    if (opcode == 0x99) {
        inst.type = OpcodeType::Cdq;
        inst.length = offset;
        return inst;
    }

    // 0xF4: HLT
    if (opcode == 0xF4) {
        inst.type = OpcodeType::Halt;
        inst.length = offset;
        return inst;
    }

    // 0xCC: INT3 (treat as Nop / Trap)
    if (opcode == 0xCC) {
        inst.type = OpcodeType::Nop;
        inst.length = offset;
        return inst;
    }

    // 0xCD: INT imm8
    if (opcode == 0xCD) {
        inst.type = OpcodeType::Int;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = code[offset++];
        inst.op1.size = 1;
        inst.length = offset;
        return inst;
    }

    // 0x50 - 0x57: PUSH r64
    if (opcode >= 0x50 && opcode <= 0x57) {
        inst.type = OpcodeType::Push;
        inst.op1.kind = Operand::Kind::Register;
        inst.op1.reg = (opcode - 0x50) | rexB;
        inst.op1.size = 8;
        inst.length = offset;
        return inst;
    }

    // 0x58 - 0x5F: POP r64
    if (opcode >= 0x58 && opcode <= 0x5F) {
        inst.type = OpcodeType::Pop;
        inst.op1.kind = Operand::Kind::Register;
        inst.op1.reg = (opcode - 0x58) | rexB;
        inst.op1.size = 8;
        inst.length = offset;
        return inst;
    }

    // 0x68: PUSH imm32
    if (opcode == 0x68) {
        inst.type = OpcodeType::Push;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = static_cast<u64>(*reinterpret_cast<const s32*>(code + offset));
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // 0x6A: PUSH imm8
    if (opcode == 0x6A) {
        inst.type = OpcodeType::Push;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = static_cast<u64>(static_cast<s64>(static_cast<s8>(code[offset++])));
        inst.length = offset;
        return inst;
    }

    // 0x63: MOVSXD r64, r/m32
    if (opcode == 0x63) {
        inst.type = OpcodeType::Movsxd;
        DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
        inst.op1.size = 8;
        inst.op2.size = 4;
        inst.length = offset;
        return inst;
    }

    // 0x86: XCHG r/m8, r8
    if (opcode == 0x86) {
        inst.type = OpcodeType::Xchg;
        DecodeModRM(code, offset, rex, isGs, 1, inst.op2, inst.op1);
        inst.length = offset;
        return inst;
    }

    // 0x87: XCHG r/m, r
    if (opcode == 0x87) {
        inst.type = OpcodeType::Xchg;
        DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op2, inst.op1);
        inst.length = offset;
        return inst;
    }

    // 0x88: MOV r/m8, r8
    if (opcode == 0x88) {
        inst.type = OpcodeType::Mov;
        DecodeModRM(code, offset, rex, isGs, 1, inst.op2, inst.op1);
        inst.length = offset;
        return inst;
    }

    // 0x89: MOV r/m, r
    if (opcode == 0x89) {
        inst.type = OpcodeType::Mov;
        DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op2, inst.op1);
        inst.length = offset;
        return inst;
    }

    // 0x8A: MOV r8, r/m8
    if (opcode == 0x8A) {
        inst.type = OpcodeType::Mov;
        DecodeModRM(code, offset, rex, isGs, 1, inst.op1, inst.op2);
        inst.length = offset;
        return inst;
    }

    // 0x8B: MOV r, r/m
    if (opcode == 0x8B) {
        inst.type = OpcodeType::Mov;
        DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
        inst.length = offset;
        return inst;
    }

    // 0x8D: LEA r, m
    if (opcode == 0x8D) {
        inst.type = OpcodeType::Lea;
        DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
        inst.length = offset;
        return inst;
    }

    // 0x69: IMUL reg, r/m, imm32
    // 0x6B: IMUL reg, r/m, imm8
    if (opcode == 0x69 || opcode == 0x6B) {
        inst.type = OpcodeType::Imul;
        inst.opSize = defaultOpSize;
        DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
        inst.op3.kind = Operand::Kind::Immediate;
        if (opcode == 0x6B) {
            inst.op3.imm = static_cast<u64>(static_cast<s64>(static_cast<s8>(code[offset++])));
            inst.op3.size = defaultOpSize;
        } else {
            if (defaultOpSize == 2) {
                inst.op3.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s16*>(code + offset)));
                offset += 2;
            } else {
                inst.op3.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s32*>(code + offset)));
                offset += 4;
            }
            inst.op3.size = defaultOpSize;
        }
        inst.length = offset;
        return inst;
    }

    // 0xB0 - 0xB7: MOV r8, imm8
    if (opcode >= 0xB0 && opcode <= 0xB7) {
        inst.type = OpcodeType::Mov;
        inst.op1.kind = Operand::Kind::Register;
        inst.op1.reg = (opcode - 0xB0) | rexB;
        inst.op1.size = 1;
        inst.op2.kind = Operand::Kind::Immediate;
        inst.op2.imm = code[offset++];
        inst.op2.size = 1;
        inst.length = offset;
        return inst;
    }

    // 0xB8 - 0xBF: MOV r32/r64, imm32/imm64
    if (opcode >= 0xB8 && opcode <= 0xBF) {
        inst.type = OpcodeType::Mov;
        inst.op1.kind = Operand::Kind::Register;
        inst.op1.reg = (opcode - 0xB8) | rexB;
        inst.op1.size = defaultOpSize;
        inst.op2.kind = Operand::Kind::Immediate;
        if (rexW) {
            inst.op2.imm = *reinterpret_cast<const u64*>(code + offset);
            offset += 8;
            inst.op2.size = 8;
        } else {
            inst.op2.imm = *reinterpret_cast<const u32*>(code + offset);
            offset += 4;
            inst.op2.size = 4;
        }
        inst.length = offset;
        return inst;
    }

    // 0xC6: MOV r/m8, imm8
    if (opcode == 0xC6) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        if (subop == 0) {
            inst.type = OpcodeType::Mov;
            Operand unused;
            DecodeModRM(code, offset, rex, isGs, 1, unused, inst.op1);
            inst.op2.kind = Operand::Kind::Immediate;
            inst.op2.imm = code[offset++];
            inst.op2.size = 1;
            inst.length = offset;
            return inst;
        }
    }

    // 0xC7: MOV r/m, imm32
    if (opcode == 0xC7) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        if (subop == 0) {
            inst.type = OpcodeType::Mov;
            Operand unused;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, unused, inst.op1);
            inst.op2.kind = Operand::Kind::Immediate;
            if (defaultOpSize == 2) {
                inst.op2.imm = *reinterpret_cast<const u16*>(code + offset);
                offset += 2;
            } else {
                inst.op2.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s32*>(code + offset)));
                offset += 4;
            }
            inst.op2.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }
    }

    // 0x00 - 0x3D: ALU operations (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP)
    if (opcode <= 0x3D && (opcode & 7) <= 5) {
        static const OpcodeType aluOps[8] = {
            OpcodeType::Add, OpcodeType::Or, OpcodeType::Adc, OpcodeType::Sbb,
            OpcodeType::And, OpcodeType::Sub, OpcodeType::Xor, OpcodeType::Cmp
        };
        inst.type = aluOps[(opcode >> 3) & 7];
        u8 sub = opcode & 7;
        if (sub <= 3) {
            u8 sz = (sub & 1) ? defaultOpSize : 1;
            if ((sub & 2) == 0) DecodeModRM(code, offset, rex, isGs, sz, inst.op2, inst.op1);
            else DecodeModRM(code, offset, rex, isGs, sz, inst.op1, inst.op2);
        } else if (sub == 4) { // AL, imm8
            inst.op1.kind = Operand::Kind::Register;
            inst.op1.reg = 0; // AL
            inst.op1.size = 1;
            inst.op2.kind = Operand::Kind::Immediate;
            inst.op2.imm = code[offset++];
            inst.op2.size = 1;
        } else if (sub == 5) { // (E)AX, imm16/imm32
            inst.op1.kind = Operand::Kind::Register;
            inst.op1.reg = 0; // RAX / EAX
            inst.op1.size = defaultOpSize;
            inst.op2.kind = Operand::Kind::Immediate;
            if (defaultOpSize == 2) {
                inst.op2.imm = *reinterpret_cast<const u16*>(code + offset);
                offset += 2;
            } else {
                s32 imm32 = *reinterpret_cast<const s32*>(code + offset);
                offset += 4;
                inst.op2.imm = (defaultOpSize == 8) ? static_cast<u64>(static_cast<s64>(imm32)) : static_cast<u32>(imm32);
            }
            inst.op2.size = defaultOpSize;
        }
        inst.length = offset;
        return inst;
    }

    // 0x84, 0x85: TEST r/m, r
    if (opcode == 0x84 || opcode == 0x85) {
        inst.type = OpcodeType::Test;
        u8 sz = (opcode == 0x85) ? defaultOpSize : 1;
        DecodeModRM(code, offset, rex, isGs, sz, inst.op2, inst.op1);
        inst.length = offset;
        return inst;
    }

    // 0xA8: TEST al, imm8
    if (opcode == 0xA8) {
        inst.type = OpcodeType::Test;
        inst.op1.kind = Operand::Kind::Register;
        inst.op1.reg = 0; // RAX (AL)
        inst.op1.size = 1;
        inst.op2.kind = Operand::Kind::Immediate;
        inst.op2.imm = code[offset++];
        inst.op2.size = 1;
        inst.length = offset;
        return inst;
    }

    // 0xA9: TEST eax/rax, imm32
    if (opcode == 0xA9) {
        inst.type = OpcodeType::Test;
        inst.op1.kind = Operand::Kind::Register;
        inst.op1.reg = 0; // RAX
        inst.op1.size = defaultOpSize;
        inst.op2.kind = Operand::Kind::Immediate;
        if (defaultOpSize == 2) {
            inst.op2.imm = *reinterpret_cast<const u16*>(code + offset);
            offset += 2;
        } else {
            inst.op2.imm = static_cast<u64>(*reinterpret_cast<const u32*>(code + offset));
            offset += 4;
        }
        inst.op2.size = defaultOpSize;
        inst.length = offset;
        return inst;
    }

    // 0x80 - 0x83: Group 1 (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP) r/m, imm
    if (opcode >= 0x80 && opcode <= 0x83) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        switch (subop) {
            case 0: inst.type = OpcodeType::Add; break;
            case 1: inst.type = OpcodeType::Or; break;
            case 2: inst.type = OpcodeType::Adc; break;
            case 3: inst.type = OpcodeType::Sbb; break;
            case 4: inst.type = OpcodeType::And; break;
            case 5: inst.type = OpcodeType::Sub; break;
            case 6: inst.type = OpcodeType::Xor; break;
            case 7: inst.type = OpcodeType::Cmp; break;
        }

        u8 sz = (opcode == 0x80) ? 1 : defaultOpSize;
        Operand unused;
        DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);

        inst.op2.kind = Operand::Kind::Immediate;
        if (opcode == 0x80 || opcode == 0x83) {
            // Sign-extended 8-bit immediate
            inst.op2.imm = static_cast<u64>(static_cast<s64>(static_cast<s8>(code[offset++])));
        } else if (opcode == 0x81) {
            if (defaultOpSize == 2) {
                inst.op2.imm = *reinterpret_cast<const u16*>(code + offset);
                offset += 2;
            } else {
                inst.op2.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s32*>(code + offset)));
                offset += 4;
            }
        }
        inst.op2.size = sz;
        inst.length = offset;
        return inst;
    }

    // 0xC0, 0xC1: Shift / Rotate r/m, imm8
    if (opcode == 0xC0 || opcode == 0xC1) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        if (subop == 0) inst.type = OpcodeType::Rol;
        else if (subop == 1) inst.type = OpcodeType::Ror;
        else if (subop == 2) inst.type = OpcodeType::Rcl;
        else if (subop == 3) inst.type = OpcodeType::Rcr;
        else if (subop == 4) inst.type = OpcodeType::Shl;
        else if (subop == 5) inst.type = OpcodeType::Shr;
        else if (subop == 7) inst.type = OpcodeType::Sar;

        u8 sz = (opcode == 0xC1) ? defaultOpSize : 1;
        Operand unused;
        DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
        inst.op2.kind = Operand::Kind::Immediate;
        inst.op2.imm = code[offset++];
        inst.op2.size = 1;
        inst.length = offset;
        return inst;
    }

    // 0xD0, 0xD1: Shift / Rotate r/m, 1
    if (opcode == 0xD0 || opcode == 0xD1) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        if (subop == 0) inst.type = OpcodeType::Rol;
        else if (subop == 1) inst.type = OpcodeType::Ror;
        else if (subop == 2) inst.type = OpcodeType::Rcl;
        else if (subop == 3) inst.type = OpcodeType::Rcr;
        else if (subop == 4) inst.type = OpcodeType::Shl;
        else if (subop == 5) inst.type = OpcodeType::Shr;
        else if (subop == 7) inst.type = OpcodeType::Sar;

        u8 sz = (opcode == 0xD1) ? defaultOpSize : 1;
        Operand unused;
        DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
        inst.op2.kind = Operand::Kind::Immediate;
        inst.op2.imm = 1;
        inst.op2.size = 1;
        inst.length = offset;
        return inst;
    }

    // 0xD2, 0xD3: Shift / Rotate r/m, CL
    if (opcode == 0xD2 || opcode == 0xD3) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        if (subop == 0) inst.type = OpcodeType::Rol;
        else if (subop == 1) inst.type = OpcodeType::Ror;
        else if (subop == 2) inst.type = OpcodeType::Rcl;
        else if (subop == 3) inst.type = OpcodeType::Rcr;
        else if (subop == 4) inst.type = OpcodeType::Shl;
        else if (subop == 5) inst.type = OpcodeType::Shr;
        else if (subop == 7) inst.type = OpcodeType::Sar;

        u8 sz = (opcode == 0xD3) ? defaultOpSize : 1;
        Operand unused;
        DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
        inst.op2.kind = Operand::Kind::Register;
        inst.op2.reg = 1; // RCX (CL)
        inst.op2.size = 1;
        inst.length = offset;
        return inst;
    }

    // 0xF6, 0xF7: Group 3 (TEST, NOT, NEG)
    if (opcode == 0xF6 || opcode == 0xF7) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        u8 sz = (opcode == 0xF7) ? defaultOpSize : 1;
        Operand unused;

        if (subop == 0) { // TEST r/m, imm
            inst.type = OpcodeType::Test;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.op2.kind = Operand::Kind::Immediate;
            if (opcode == 0xF6) {
                inst.op2.imm = code[offset++];
            } else {
                inst.op2.imm = *reinterpret_cast<const u32*>(code + offset);
                offset += 4;
            }
            inst.length = offset;
            return inst;
        } else if (subop == 2) { // NOT
            inst.type = OpcodeType::Not;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.length = offset;
            return inst;
        } else if (subop == 3) { // NEG
            inst.type = OpcodeType::Neg;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.length = offset;
            return inst;
        } else if (subop == 4) { // MUL
            inst.type = OpcodeType::Mul;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.length = offset;
            return inst;
        } else if (subop == 5) { // IMUL (1-op)
            inst.type = OpcodeType::Imul;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.length = offset;
            return inst;
        } else if (subop == 6) { // DIV
            inst.type = OpcodeType::Div;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.length = offset;
            return inst;
        } else if (subop == 7) { // IDIV
            inst.type = OpcodeType::Idiv;
            DecodeModRM(code, offset, rex, isGs, sz, unused, inst.op1);
            inst.length = offset;
            return inst;
        }
    }

    // 0xEB: JMP rel8
    if (opcode == 0xEB) {
        inst.type = OpcodeType::Jmp;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = static_cast<u64>(static_cast<s64>(static_cast<s8>(code[offset++])));
        inst.length = offset;
        return inst;
    }

    // 0xE9: JMP rel32
    if (opcode == 0xE9) {
        inst.type = OpcodeType::Jmp;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s32*>(code + offset)));
        offset += 4;
        inst.length = offset;
        return inst;
    }

    // 0x70 - 0x7F: Jcc rel8
    if (opcode >= 0x70 && opcode <= 0x7F) {
        inst.type = OpcodeType::Jcc;
        inst.conditionCode = opcode & 0x0F;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = static_cast<u64>(static_cast<s64>(static_cast<s8>(code[offset++])));
        inst.length = offset;
        return inst;
    }

    // 0xE8: CALL rel32
    if (opcode == 0xE8) {
        inst.type = OpcodeType::Call;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s32*>(code + offset)));
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

    // 0xC2: RET imm16
    if (opcode == 0xC2) {
        inst.type = OpcodeType::Ret;
        inst.op1.kind = Operand::Kind::Immediate;
        inst.op1.imm = *reinterpret_cast<const u16*>(code + offset);
        offset += 2;
        inst.length = offset;
        return inst;
    }

    // 0xAA: STOSB
    if (opcode == 0xAA) {
        inst.type = OpcodeType::Stos;
        inst.opSize = 1;
        inst.length = offset;
        return inst;
    }

    // 0xAB: STOSD / STOSQ
    if (opcode == 0xAB) {
        inst.type = OpcodeType::Stos;
        inst.opSize = defaultOpSize;
        inst.length = offset;
        return inst;
    }

    // 0xFE: Group 4 (INC r/m8, DEC r/m8)
    if (opcode == 0xFE) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        Operand unused;
        DecodeModRM(code, offset, rex, isGs, 1, unused, inst.op1);

        if (subop == 0) inst.type = OpcodeType::Inc;
        else if (subop == 1) inst.type = OpcodeType::Dec;
        inst.length = offset;
        return inst;
    }

    // 0xFF: Group 5 (INC, DEC, CALL, CALLF, JMP, JMPF, PUSH)
    if (opcode == 0xFF) {
        u8 modrm = code[offset];
        u8 subop = (modrm >> 3) & 7;
        Operand unused;
        DecodeModRM(code, offset, rex, isGs, 8, unused, inst.op1);

        if (subop == 0) inst.type = OpcodeType::Inc;
        else if (subop == 1) inst.type = OpcodeType::Dec;
        else if (subop == 2) inst.type = OpcodeType::Call;
        else if (subop == 4) inst.type = OpcodeType::Jmp;
        else if (subop == 6) inst.type = OpcodeType::Push;

        inst.length = offset;
        return inst;
    }

    // Two-byte opcodes: 0x0F ...
    if (opcode == 0x0F) {
        u8 op2 = code[offset++];

        // 0x0F 0x14: UNPCKLPS (none) / UNPCKLPD (66)
        if (op2 == 0x14) {
            inst.type = has66 ? OpcodeType::Unpcklpd : OpcodeType::Unpcklps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x3A: 3-byte SSE4 opcode prefix
        if (op2 == 0x3A) {
            u8 op3 = code[offset++];
            if (op3 == 0x63) { // PCMPISTRI
                inst.type = OpcodeType::Pcmpistri;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
                inst.op3.kind = Operand::Kind::Immediate;
                inst.op3.imm = code[offset++];
                inst.op3.size = 1;
                inst.length = offset;
                return inst;
            }
        }

        // 0x0F 0x01: XGETBV (0x0F 0x01 0xD0)
        if (op2 == 0x01 && code[offset] == 0xD0) {
            offset++;
            inst.type = OpcodeType::Xgetbv;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x0B: HLE Trap (UD2)
        if (op2 == 0x0B) {
            inst.type = OpcodeType::HleTrap;
            inst.op1.kind = Operand::Kind::Immediate;
            inst.op1.imm = *reinterpret_cast<const u32*>(code + offset);
            offset += 4;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x10: MOVUPS, MOVSD (with F2), or MOVSS (with F3)
        if (op2 == 0x10) {
            if (hasF2) {
                inst.type = OpcodeType::Movsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (hasF3) {
                inst.type = OpcodeType::Movss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Movdqu;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x11: MOVUPS, MOVSD (with F2), or MOVSS (with F3)
        if (op2 == 0x11) {
            if (hasF2) {
                inst.type = OpcodeType::Movsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op2, inst.op1);
            } else if (hasF3) {
                inst.type = OpcodeType::Movss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op2, inst.op1);
            } else {
                inst.type = OpcodeType::Movdqu;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op2, inst.op1);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x12 / 0x16: MOVLPS/MOVHPS
        if (op2 == 0x12 || op2 == 0x16) {
            inst.type = OpcodeType::Movdqu;
            DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x0D / 0x0F 0x18: PREFETCHW / PREFETCH
        if (op2 == 0x0D || op2 == 0x18) {
            Operand unused1, unused2;
            DecodeModRM(code, offset, rex, isGs, 1, unused1, unused2);
            inst.type = OpcodeType::Nop;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x1F: Multi-byte NOP
        if (op2 == 0x1F) {
            Operand unused1, unused2;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, unused1, unused2);
            inst.type = OpcodeType::Nop;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x28: MOVAPS / MOVAPD
        if (op2 == 0x28) {
            inst.type = OpcodeType::Movdqa;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x29: MOVAPS / MOVAPD
        if (op2 == 0x29) {
            inst.type = OpcodeType::Movdqa;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x2A: CVTSI2SD (with F2) / CVTSI2SS (with F3)
        if (op2 == 0x2A) {
            if (hasF3) {
                inst.type = OpcodeType::Cvtsi2ss;
            } else {
                inst.type = OpcodeType::Cvtsi2sd;
            }
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x2B: MOVNTPS
        if (op2 == 0x2B) {
            inst.type = OpcodeType::Movdqa;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x2C: CVTTSS2SI (with F3) / CVTTSD2SI (with F2)
        if (op2 == 0x2C) {
            if (hasF3) {
                inst.type = OpcodeType::Cvttss2si;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Cvttsd2si;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            }
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x2D: CVTSS2SI (with F3) / CVTSD2SI (with F2)
        if (op2 == 0x2D) {
            if (hasF3) {
                inst.type = OpcodeType::Cvtss2si;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Cvtsd2si;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            }
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x2E / 0x2F: UCOMISS / COMISS (none) or UCOMISD / COMISD (66)
        if (op2 == 0x2E || op2 == 0x2F) {
            inst.type = has66 ? OpcodeType::Comisd : OpcodeType::Comiss;
            DecodeModRM(code, offset, rex, isGs, has66 ? 8 : 4, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x40 - 0x4F: CMOVcc
        if (op2 >= 0x40 && op2 <= 0x4F) {
            inst.type = OpcodeType::Cmov;
            inst.conditionCode = op2 & 0x0F;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x50: MOVMSKPS / MOVMSKPD
        if (op2 == 0x50) {
            inst.type = OpcodeType::Movmskps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x51: SQRTSS (F3) / SQRTSD (F2) / SQRTPS
        if (op2 == 0x51) {
            if (hasF3) {
                inst.type = OpcodeType::Sqrtss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Sqrtsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Sqrtps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x52: RSQRTSS (F3) / RSQRTPS
        if (op2 == 0x52) {
            if (hasF3) {
                inst.type = OpcodeType::Rsqrtss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Rsqrtps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x53: RCPSS (F3) / RCPPS
        if (op2 == 0x53) {
            if (hasF3) {
                inst.type = OpcodeType::Rcpss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Rcpps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x54: ANDPS / ANDPD
        if (op2 == 0x54 || op2 == 0xDB) {
            inst.type = OpcodeType::Andps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x55: ANDNPS / ANDNPD
        if (op2 == 0x55 || op2 == 0xDF) {
            inst.type = OpcodeType::Andnps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x56: ORPS / ORPD
        if (op2 == 0x56 || op2 == 0xEB) {
            inst.type = OpcodeType::Orps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x57: XORPS / XORPD / PXOR
        if (op2 == 0x57 || op2 == 0xEF) {
            inst.type = OpcodeType::Xorps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x58: ADDSS (F3) / ADDSD (F2) / ADDPD (66) / ADDPS
        if (op2 == 0x58) {
            if (hasF3) {
                inst.type = OpcodeType::Addss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Addsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Addpd;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Addps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x59: MULSS (F3) / MULSD (F2) / MULPD (66) / MULPS
        if (op2 == 0x59) {
            if (hasF3) {
                inst.type = OpcodeType::Mulss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Mulsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Mulpd;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Mulps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x5A: CVTSS2SD (F3) / CVTSD2SS (F2) / CVTPD2PS (66) / CVTPS2PD (none)
        if (op2 == 0x5A) {
            if (hasF3) {
                inst.type = OpcodeType::Cvtss2sd;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Cvtsd2ss;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Cvtpd2ps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Cvtps2pd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x5B: CVTDQ2PS (none) / CVTPS2DQ (66) / CVTTPS2DQ (F3)
        if (op2 == 0x5B) {
            if (hasF3) {
                inst.type = OpcodeType::Cvttps2dq;
            } else if (has66) {
                inst.type = OpcodeType::Cvtps2dq;
            } else {
                inst.type = OpcodeType::Cvtdq2ps;
            }
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x5C: SUBSS (F3) / SUBSD (F2) / SUBPD (66) / SUBPS
        if (op2 == 0x5C) {
            if (hasF3) {
                inst.type = OpcodeType::Subss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Subsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Subpd;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Subps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x5D: MINSS (F3) / MINSD (F2) / MINPD (66) / MINPS
        if (op2 == 0x5D) {
            if (hasF3) {
                inst.type = OpcodeType::Minss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Minsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Minpd;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Minps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x5E: DIVSS (F3) / DIVSD (F2) / DIVPD (66) / DIVPS
        if (op2 == 0x5E) {
            if (hasF3) {
                inst.type = OpcodeType::Divss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Divsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Divpd;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Divps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x5F: MAXSS (F3) / MAXSD (F2) / MAXPD (66) / MAXPS
        if (op2 == 0x5F) {
            if (hasF3) {
                inst.type = OpcodeType::Maxss;
                DecodeModRM(code, offset, rex, isGs, 4, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Maxsd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (has66) {
                inst.type = OpcodeType::Maxpd;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Maxps;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x60..0x62, 0x68..0x6D: PUNPCK*
        if (op2 == 0x60 || op2 == 0x61 || op2 == 0x62 ||
            op2 == 0x68 || op2 == 0x69 || op2 == 0x6A || op2 == 0x6C || op2 == 0x6D) {
            switch (op2) {
                case 0x60: inst.type = OpcodeType::Punpcklbw; break;
                case 0x61: inst.type = OpcodeType::Punpcklwd; break;
                case 0x62: inst.type = OpcodeType::Punpckldq; break;
                case 0x68: inst.type = OpcodeType::Punpckhbw; break;
                case 0x69: inst.type = OpcodeType::Punpckhwd; break;
                case 0x6A: inst.type = OpcodeType::Punpckhdq; break;
                case 0x6C: inst.type = OpcodeType::Punpcklqdq; break;
                case 0x6D: inst.type = OpcodeType::Punpckhqdq; break;
            }
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x6E: MOVD/MOVQ xmm, r/m32 or r/m64
        if (op2 == 0x6E) {
            inst.type = OpcodeType::MovqFromGp;
            u8 sz = rexW ? 8 : 4;
            DecodeModRM(code, offset, rex, isGs, sz, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x6F: MOVDQA / MOVDQU
        if (op2 == 0x6F) {
            inst.type = OpcodeType::Movdqa;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x70: PSHUFD (66) / PSHUFLW (F2) / PSHUFHW (F3)
        if (op2 == 0x70) {
            if (hasF2) inst.type = OpcodeType::Pshuflw;
            else if (hasF3) inst.type = OpcodeType::Pshufhw;
            else inst.type = OpcodeType::Pshufd;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.op3.kind = Operand::Kind::Immediate;
            inst.op3.imm = code[offset++];
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x71 / 0x72: PSRL{W,D} / PSRA{W,D} / PSLL{W,D} xmm, imm8
        if (op2 == 0x71 || op2 == 0x72) {
            u8 modrm = code[offset];
            u8 subop = (modrm >> 3) & 7;
            if (subop == 2) inst.type = (op2 == 0x71) ? OpcodeType::Psrlw : OpcodeType::Psrld;
            else if (subop == 4) inst.type = (op2 == 0x71) ? OpcodeType::Psraw : OpcodeType::Psrad;
            else if (subop == 6) inst.type = (op2 == 0x71) ? OpcodeType::Psllw : OpcodeType::Pslld;
            if (inst.type != OpcodeType::Unknown) {
                Operand unused;
                DecodeModRM(code, offset, rex, isGs, 16, unused, inst.op1);
                inst.op2.kind = Operand::Kind::Immediate;
                inst.op2.imm = code[offset++];
                inst.length = offset;
                return inst;
            }
        }

        // 0x0F 0x73: PSRLQ / PSRLDQ / PSLLQ / PSLLDQ xmm, imm8
        if (op2 == 0x73) {
            u8 modrm = code[offset];
            u8 subop = (modrm >> 3) & 7;
            Operand unused;
            DecodeModRM(code, offset, rex, isGs, 16, unused, inst.op1);
            inst.op2.kind = Operand::Kind::Immediate;
            inst.op2.imm = code[offset++];
            if (subop == 3) inst.type = OpcodeType::Psrldq;
            else if (subop == 6) inst.type = OpcodeType::Psllq;
            else if (subop == 7) inst.type = OpcodeType::Pslldq;
            else inst.type = OpcodeType::Psrlq;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x74 / 0x75 / 0x76: PCMPEQB / PCMPEQW / PCMPEQD
        if (op2 == 0x74 || op2 == 0x75 || op2 == 0x76) {
            if (op2 == 0x74) inst.type = OpcodeType::Pcmpeqb;
            else if (op2 == 0x75) inst.type = OpcodeType::Pcmpeqw;
            else inst.type = OpcodeType::Pcmpeqd;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x7E: MOVQ xmm, xmm/m64 (F3) or MOVD/MOVQ r/m32 or r/m64, xmm
        if (op2 == 0x7E) {
            if (hasF3) {
                inst.type = OpcodeType::MovqXmm;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::MovqToGp;
                u8 sz = rexW ? 8 : 4;
                DecodeModRM(code, offset, rex, isGs, sz, inst.op2, inst.op1);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x7F: MOVDQA / MOVDQU
        if (op2 == 0x7F) {
            inst.type = OpcodeType::Movdqu;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x80 - 0x8F: Jcc rel32
        if (op2 >= 0x80 && op2 <= 0x8F) {
            inst.type = OpcodeType::Jcc;
            inst.conditionCode = op2 & 0x0F;
            inst.op1.kind = Operand::Kind::Immediate;
            inst.op1.imm = static_cast<u64>(static_cast<s64>(*reinterpret_cast<const s32*>(code + offset)));
            offset += 4;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0x90 - 0x9F: SETcc
        if (op2 >= 0x90 && op2 <= 0x9F) {
            inst.type = OpcodeType::Setcc;
            inst.conditionCode = op2 & 0x0F;
            Operand unused;
            DecodeModRM(code, offset, rex, isGs, 1, unused, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xA2: CPUID
        if (op2 == 0xA2) {
            inst.type = OpcodeType::Cpuid;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xA3: BT r/m, r
        if (op2 == 0xA3) {
            inst.type = OpcodeType::Bt;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xAB: BTS r/m, r
        if (op2 == 0xAB) {
            inst.type = OpcodeType::Bts;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xAE: Group 15 (SFENCE, LFENCE, MFENCE, LDMXCSR, STMXCSR)
        if (op2 == 0xAE) {
            u8 modrm = code[offset];
            u8 mod = (modrm >> 6) & 3;
            u8 subop = (modrm >> 3) & 7;
            if (mod == 3) {
                offset++;
                inst.type = OpcodeType::Nop;
                inst.length = offset;
                return inst;
            } else if (subop == 2 || subop == 3) {
                Operand unused;
                DecodeModRM(code, offset, rex, isGs, 4, unused, inst.op1);
                inst.type = (subop == 3) ? OpcodeType::Stmxcsr : OpcodeType::Nop;
                inst.length = offset;
                return inst;
            }
        }

        // 0x0F 0xAF: IMUL r, r/m
        if (op2 == 0xAF) {
            inst.type = OpcodeType::Imul;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xB0, 0x0F 0xB1: CMPXCHG
        if (op2 == 0xB0 || op2 == 0xB1) {
            inst.type = OpcodeType::Cmpxchg;
            u8 sz = (op2 == 0xB1) ? defaultOpSize : 1;
            DecodeModRM(code, offset, rex, isGs, sz, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xB3: BTR r/m, r
        if (op2 == 0xB3) {
            inst.type = OpcodeType::Btr;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xB6: MOVZX r, r/m8
        if (op2 == 0xB6) {
            inst.type = OpcodeType::Movzx;
            DecodeModRM(code, offset, rex, isGs, 1, inst.op1, inst.op2);
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xB7: MOVZX r, r/m16
        if (op2 == 0xB7) {
            inst.type = OpcodeType::Movzx;
            DecodeModRM(code, offset, rex, isGs, 2, inst.op1, inst.op2);
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xBA: Group 8 (BT, BTS, BTR, BTC r/m, imm8)
        if (op2 == 0xBA) {
            u8 modrm = code[offset];
            u8 subop = (modrm >> 3) & 7;
            if (subop == 4) inst.type = OpcodeType::Bt;
            else if (subop == 5) inst.type = OpcodeType::Bts;
            else if (subop == 6) inst.type = OpcodeType::Btr;
            else if (subop == 7) inst.type = OpcodeType::Btc;
            if (inst.type != OpcodeType::Unknown) {
                Operand unused;
                DecodeModRM(code, offset, rex, isGs, defaultOpSize, unused, inst.op1);
                inst.op2.kind = Operand::Kind::Immediate;
                inst.op2.imm = code[offset++];
                inst.length = offset;
                return inst;
            }
        }


        // 0x0F 0xB8: POPCNT r, r/m
        if (op2 == 0xB8) {
            inst.type = OpcodeType::Popcnt;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xBC: BSF / TZCNT
        if (op2 == 0xBC) {
            inst.type = OpcodeType::Bsf;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xBD: BSR / LZCNT
        if (op2 == 0xBD) {
            inst.type = OpcodeType::Bsr;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xBB: BTC r/m, r
        if (op2 == 0xBB) {
            inst.type = OpcodeType::Btc;
            DecodeModRM(code, offset, rex, isGs, defaultOpSize, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xBE: MOVSX r, r/m8
        if (op2 == 0xBE) {
            inst.type = OpcodeType::Movsx;
            DecodeModRM(code, offset, rex, isGs, 1, inst.op1, inst.op2);
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xBF: MOVSX r, r/m16
        if (op2 == 0xBF) {
            inst.type = OpcodeType::Movsx;
            DecodeModRM(code, offset, rex, isGs, 2, inst.op1, inst.op2);
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xC0, 0x0F 0xC1: XADD
        if (op2 == 0xC0 || op2 == 0xC1) {
            inst.type = OpcodeType::Xadd;
            u8 sz = (op2 == 0xC1) ? defaultOpSize : 1;
            DecodeModRM(code, offset, rex, isGs, sz, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xC2: CMPPS / CMPPD (66) / CMPSS (F3) / CMPSD (F2)
        if (op2 == 0xC2) {
            u8 sz = 16;
            if (hasF3) { inst.type = OpcodeType::Cmpss; sz = 4; }
            else if (hasF2) { inst.type = OpcodeType::Cmpsd; sz = 8; }
            else if (has66) { inst.type = OpcodeType::Cmppd; sz = 16; }
            else { inst.type = OpcodeType::Cmpps; sz = 16; }
            DecodeModRM(code, offset, rex, isGs, sz, inst.op1, inst.op2);
            inst.op3.kind = Operand::Kind::Immediate;
            inst.op3.imm = code[offset++];
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xC6: SHUFPS / SHUFPD (with 66 prefix)
        if (op2 == 0xC6) {
            inst.type = has66 ? OpcodeType::Shufpd : OpcodeType::Shufps;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.op3.kind = Operand::Kind::Immediate;
            inst.op3.imm = code[offset++];
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xC7: Group 9 (CMPXCHG8B / CMPXCHG16B)
        if (op2 == 0xC7) {
            u8 modrm = code[offset];
            u8 subop = (modrm >> 3) & 7;
            Operand unused;
            if (subop == 1) {
                if (inst.hasRex && (rex & 0x08)) {
                    inst.type = OpcodeType::Cmpxchg16b;
                    DecodeModRM(code, offset, rex, isGs, 16, unused, inst.op1);
                } else {
                    inst.type = OpcodeType::Cmpxchg8b;
                    DecodeModRM(code, offset, rex, isGs, 8, unused, inst.op1);
                }
                inst.length = offset;
                return inst;
            }
        }

        // 0x0F 0xC8 - 0x0F 0xCF: BSWAP r32/r64
        if (op2 >= 0xC8 && op2 <= 0xCF) {
            inst.type = OpcodeType::Bswap;
            inst.op1.kind = Operand::Kind::Register;
            inst.op1.reg = (op2 - 0xC8) | rexB;
            inst.op1.size = defaultOpSize;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xD1..0xD3, 0xE1..0xE2, 0xF1..0xF3: PSRL{W,D,Q} / PSRA{W,D} / PSLL{W,D,Q} xmm, xmm/m128
        if (op2 == 0xD1 || op2 == 0xD2 || op2 == 0xD3 ||
            op2 == 0xE1 || op2 == 0xE2 ||
            op2 == 0xF1 || op2 == 0xF2 || op2 == 0xF3) {
            switch (op2) {
                case 0xD1: inst.type = OpcodeType::Psrlw; break;
                case 0xD2: inst.type = OpcodeType::Psrld; break;
                case 0xD3: inst.type = OpcodeType::Psrlq; break;
                case 0xE1: inst.type = OpcodeType::Psraw; break;
                case 0xE2: inst.type = OpcodeType::Psrad; break;
                case 0xF1: inst.type = OpcodeType::Psllw; break;
                case 0xF2: inst.type = OpcodeType::Pslld; break;
                case 0xF3: inst.type = OpcodeType::Psllq; break;
            }
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xD4: PADDQ
        if (op2 == 0xD4) {
            inst.type = OpcodeType::Paddq;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xD6: MOVQ xmm/m64, xmm
        if (op2 == 0xD6) {
            inst.type = OpcodeType::MovqXmm;
            DecodeModRM(code, offset, rex, isGs, 8, inst.op2, inst.op1);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xD7: PMOVMSKB r32/r64, xmm
        if (op2 == 0xD7) {
            inst.type = OpcodeType::Pmovmskb;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.op1.size = defaultOpSize;
            inst.op2.size = 16;
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xE6: CVTTPD2DQ (66) / CVTPD2DQ (F2) / CVTDQ2PD (F3)
        if (op2 == 0xE6) {
            if (hasF3) {
                inst.type = OpcodeType::Cvtdq2pd;
                DecodeModRM(code, offset, rex, isGs, 8, inst.op1, inst.op2);
            } else if (hasF2) {
                inst.type = OpcodeType::Cvtpd2dq;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            } else {
                inst.type = OpcodeType::Cvttpd2dq;
                DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            }
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xF8: PSUBB
        if (op2 == 0xF8) {
            inst.type = OpcodeType::Psubb;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xF9: PSUBW
        if (op2 == 0xF9) {
            inst.type = OpcodeType::Psubw;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xFA: PSUBD
        if (op2 == 0xFA) {
            inst.type = OpcodeType::Psubd;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xFB: PSUBQ
        if (op2 == 0xFB) {
            inst.type = OpcodeType::Psubq;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xFC: PADDB
        if (op2 == 0xFC) {
            inst.type = OpcodeType::Paddb;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xFD: PADDW
        if (op2 == 0xFD) {
            inst.type = OpcodeType::Paddw;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }

        // 0x0F 0xFE: PADDD
        if (op2 == 0xFE) {
            inst.type = OpcodeType::Paddd;
            DecodeModRM(code, offset, rex, isGs, 16, inst.op1, inst.op2);
            inst.length = offset;
            return inst;
        }
    }

    inst.type = OpcodeType::Unknown;
    inst.length = 1; // Fallback advance
    return inst;
}

Interpreter::Interpreter(CpuContext& ctx, MemoryManager& memory, HleKernel* kernel, const std::vector<ImportedFunction>* imports)
    : m_ctx(ctx), m_memory(memory), m_kernel(kernel), m_imports(imports), m_decodeCache(DECODE_CACHE_SIZE) {}

u64 Interpreter::ReadOperand(const Operand& op, u8 instLen) const {
    if (op.kind == Operand::Kind::Immediate) {
        return op.imm;
    }
    if (op.kind == Operand::Kind::Register) {
        u64 val = *GetRegisterPtr(const_cast<CpuContext&>(m_ctx), op.reg);
        if (op.size == 4) return static_cast<u32>(val);
        if (op.size == 2) return static_cast<u16>(val);
        if (op.size == 1) {
            if (op.reg >= 4 && op.reg <= 7 && !m_ctx.gsBase) {
                // AH, CH, DH, BH if no REX
                return (val >> 8) & 0xFF;
            }
            return val & 0xFF;
        }
        return val;
    }
    if (op.kind == Operand::Kind::Memory) {
        u64 addr = op.GetAddress(m_ctx, m_ctx.rip);
        if (op.size == 8) return m_memory.Read<u64>(addr);
        if (op.size == 4) return m_memory.Read<u32>(addr);
        if (op.size == 2) return m_memory.Read<u16>(addr);
        if (op.size == 1) return m_memory.Read<u8>(addr);
    }
    return 0;
}

void Interpreter::WriteOperand(const Operand& op, u64 val, u8 instLen, bool hasRex) {
    if (op.kind == Operand::Kind::Register) {
        u64* regPtr = GetRegisterPtr(m_ctx, op.reg);
        if (!regPtr) return;

        if (op.size == 8) {
            *regPtr = val;
        } else if (op.size == 4) {
            // 32-bit writes clear the upper 32 bits in x86-64
            *regPtr = static_cast<u32>(val);
        } else if (op.size == 2) {
            *regPtr = (*regPtr & ~0xFFFFULL) | (val & 0xFFFFULL);
        } else if (op.size == 1) {
            if (!hasRex && op.reg >= 4 && op.reg <= 7) {
                // AH, CH, DH, BH
                *GetRegisterPtr(m_ctx, op.reg - 4) = (*GetRegisterPtr(m_ctx, op.reg - 4) & ~0xFF00ULL) | ((val & 0xFFULL) << 8);
            } else {
                *regPtr = (*regPtr & ~0xFFULL) | (val & 0xFFULL);
            }
        }
    } else if (op.kind == Operand::Kind::Memory) {
        u64 addr = op.GetAddress(m_ctx, m_ctx.rip);
        if (op.size == 8) m_memory.Write<u64>(addr, val);
        else if (op.size == 4) m_memory.Write<u32>(addr, static_cast<u32>(val));
        else if (op.size == 2) m_memory.Write<u16>(addr, static_cast<u16>(val));
        else if (op.size == 1) m_memory.Write<u8>(addr, static_cast<u8>(val));
    }
}

void Interpreter::UpdateFlagsArithmetic(u64 result, u64 op1, u64 op2, u8 opSize, bool isSub, bool updateCarry) {
    u64 mask = (opSize == 8) ? ~0ULL : ((1ULL << (opSize * 8)) - 1);
    u64 signBit = 1ULL << (opSize * 8 - 1);

    result &= mask;
    op1 &= mask;
    op2 &= mask;

    // ZF, SF
    if (result == 0) m_ctx.rflags |= 0x040;
    else m_ctx.rflags &= ~0x040;

    if (result & signBit) m_ctx.rflags |= 0x080;
    else m_ctx.rflags &= ~0x080;

    // CF
    if (updateCarry) {
        if (isSub) {
            if (op1 < op2) m_ctx.rflags |= 0x001;
            else m_ctx.rflags &= ~0x001;
        } else {
            if (result < op1) m_ctx.rflags |= 0x001;
            else m_ctx.rflags &= ~0x001;
        }
    }

    // OF
    if (isSub) {
        if (((op1 ^ op2) & (op1 ^ result)) & signBit) m_ctx.rflags |= 0x800;
        else m_ctx.rflags &= ~0x800;
    } else {
        if ((~(op1 ^ op2) & (op1 ^ result)) & signBit) m_ctx.rflags |= 0x800;
        else m_ctx.rflags &= ~0x800;
    }
}

void Interpreter::UpdateFlagsLogic(u64 result, u8 opSize) {
    u64 mask = (opSize == 8) ? ~0ULL : ((1ULL << (opSize * 8)) - 1);
    u64 signBit = 1ULL << (opSize * 8 - 1);
    result &= mask;

    if (result == 0) m_ctx.rflags |= 0x040;
    else m_ctx.rflags &= ~0x040;

    if (result & signBit) m_ctx.rflags |= 0x080;
    else m_ctx.rflags &= ~0x080;

    // Logic clears CF and OF
    m_ctx.rflags &= ~0x001;
    m_ctx.rflags &= ~0x800;
}

void Interpreter::DumpRecentTrace() const {
    std::stringstream ts;
    ts << "Recent instruction trace before fault:\n";
    for (size_t i = 0; i < TRACE_SIZE; ++i) {
        const auto& e = m_trace[(m_traceIdx + i) % TRACE_SIZE];
        if (e.rip == 0) continue;
        ts << "  [" << std::dec << i << "] RIP=0x" << std::hex << e.rip
           << " RSP=0x" << e.rsp << " len=" << std::dec << static_cast<int>(e.len) << " bytes=";
        for (int b = 0; b < 8; ++b) {
            ts << std::hex << std::setw(2) << std::setfill('0') << static_cast<u32>(e.bytes[b]) << " ";
        }
        ts << "\n";
    }
    ts << "Stack return candidates at fault RSP=0x" << std::hex << m_ctx.rsp << ":";
    for (u64 off = 0; off < 0x800; off += 8) {
        u64 v = m_memory.Read<u64>(m_ctx.rsp + off);
        if (v >= 0x140000000ULL && v < 0x240000000ULL) {
            ts << " [+" << std::hex << off << "]=0x" << v;
        }
    }
    ts << "\n";
    LOG_ERROR("Interpreter", ts.str());
}

bool Interpreter::Step() {
    if (m_halted) return false;

    u64 currentRip = m_ctx.rip;
    if (currentRip < 0x140000000ULL) {
        std::stringstream ss;
        ss << "Non-executable/low-address execution fault at RIP=0x" << std::hex << currentRip
           << " (caller ret=[RSP]=0x" << m_memory.Read<u64>(m_ctx.rsp) << ")";
        LOG_ERROR("Interpreter", ss.str());
        DumpRecentTrace();
        m_halted = true;
        return false;
    }
    const u8* code = static_cast<const u8*>(m_memory.Translate(currentRip));
    if (!code) {
        LOG_ERROR("Interpreter", "Access violation executing at 0x" + std::to_string(currentRip));
        DumpRecentTrace();
        m_halted = true;
        return false;
    }

    u64 c0 = 0, c1 = 0;
    std::memcpy(&c0, code, 8);
    std::memcpy(&c1, code + 8, 8);
    DecodeCacheEntry& slot = m_decodeCache[(currentRip ^ (currentRip >> 12)) & (DECODE_CACHE_SIZE - 1)];
    if (slot.rip != currentRip || slot.code0 != c0 || slot.code1 != c1) {
        slot.inst = X86Decoder::Decode(code, currentRip);
        slot.rip = currentRip;
        slot.code0 = c0;
        slot.code1 = c1;
    }
    const DecodedInstruction& inst = slot.inst;

    if (inst.type == OpcodeType::Unknown) {
        std::stringstream ss;
        ss << "Unhandled instruction at 0x" << std::hex << currentRip << ": ";
        for (int i = 0; i < 8; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<u32>(code[i]) << " ";
        }
        LOG_ERROR("Interpreter", ss.str());
        DumpRecentTrace();
        m_halted = true;
        return false;
    }

    TraceEntry& tr = m_trace[m_traceIdx % TRACE_SIZE];
    tr.rip = currentRip;
    tr.rsp = m_ctx.rsp;
    tr.len = inst.length;
    std::memcpy(tr.bytes, &c0, 8);
    m_traceIdx++;

    m_ctx.rip += inst.length;
    m_instructionsExecuted++;

    switch (inst.type) {
        case OpcodeType::Nop:
            break;

        case OpcodeType::Halt:
            m_halted = true;
            break;

        case OpcodeType::Int: {
            u8 vec = static_cast<u8>(inst.op1.imm);
            if (vec == 0x29) {
                u64 fastFailCode = m_ctx.rcx;
                LOG_ERROR("Interpreter", "__fastfail(0x" + std::to_string(fastFailCode) + ") invoked at RIP=0x" + std::to_string(currentRip));
                m_halted = true;
            } else if (vec == 3) {
                LOG_INFO("Interpreter", "INT 3 breakpoint hit at RIP=0x" + std::to_string(currentRip));
            } else {
                LOG_WARN("Interpreter", "INT " + std::to_string(vec) + " invoked at RIP=0x" + std::to_string(currentRip));
            }
            break;
        }

        case OpcodeType::HleTrap: {
            if (m_kernel) m_kernel->ClearYieldRequest();
            if (m_kernel && m_kernel->ExecuteHookByTrampoline(currentRip, m_ctx)) {
                // Handled by dynamic HleKernel trampoline
            } else if (m_imports && m_kernel) {
                for (size_t i = 0; i < m_imports->size(); ++i) {
                    if ((*m_imports)[i].trampolineAddress == currentRip) {
                        std::string modName = (*m_imports)[i].moduleName;
                        std::string funcName = (*m_imports)[i].functionName;
                        m_kernel->ExecuteHook(modName, funcName, m_ctx);
                        break;
                    }
                }
            }
            if (Modules::HasProcessExited()) {
                m_halted = true;
                break;
            }
            if (m_kernel && m_kernel->ShouldYield()) {
                if (m_kernel->ShouldRetryOnWake()) {
                    m_ctx.rip = currentRip;
                } else {
                    u64 retAddr = m_memory.Read<u64>(m_ctx.rsp);
                    if (retAddr >= GUEST_MEMORY_BASE) {
                        m_ctx.rip = retAddr;
                        m_ctx.rsp += 8;
                    }
                }
                break;
            }
            // Return from HLE hook (pop caller return address)
            u64 retAddr = m_memory.Read<u64>(m_ctx.rsp);
            if (retAddr >= GUEST_MEMORY_BASE) {
                m_ctx.rip = retAddr;
                m_ctx.rsp += 8;
            }
            break;
        }

        case OpcodeType::Mov: {
            u64 val = ReadOperand(inst.op2, inst.length);
            WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Movzx: {
            u64 val = ReadOperand(inst.op2, inst.length);
            WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Movsxd: {
            s64 val = static_cast<s64>(static_cast<s32>(ReadOperand(inst.op2, inst.length)));
            WriteOperand(inst.op1, static_cast<u64>(val), inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Lea: {
            u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
            WriteOperand(inst.op1, addr, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Push: {
            u64 val = ReadOperand(inst.op1, inst.length);
            m_ctx.rsp -= 8;
            m_memory.Write<u64>(m_ctx.rsp, val);
            break;
        }

        case OpcodeType::Pop: {
            u64 val = m_memory.Read<u64>(m_ctx.rsp);
            m_ctx.rsp += 8;
            WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Add: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst + src;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, src, inst.op1.size, false);
            break;
        }

        case OpcodeType::Adc: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 cf = (m_ctx.rflags & 0x001) ? 1 : 0;
            u64 res = dst + src + cf;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, src + cf, inst.op1.size, false);
            break;
        }

        case OpcodeType::Sub: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst - src;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, src, inst.op1.size, true);
            break;
        }

        case OpcodeType::Sbb: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 cf = (m_ctx.rflags & 0x001) ? 1 : 0;
            u64 res = dst - (src + cf);
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, src + cf, inst.op1.size, true);
            break;
        }

        case OpcodeType::And: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst & src;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsLogic(res, inst.op1.size);
            break;
        }

        case OpcodeType::Or: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst | src;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsLogic(res, inst.op1.size);
            break;
        }

        case OpcodeType::Xor: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst ^ src;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsLogic(res, inst.op1.size);
            break;
        }

        case OpcodeType::Cmp: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst - src;
            UpdateFlagsArithmetic(res, dst, src, inst.op1.size, true);
            break;
        }

        case OpcodeType::Test: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst & src;
            UpdateFlagsLogic(res, inst.op1.size);
            break;
        }

        case OpcodeType::Not: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            WriteOperand(inst.op1, ~dst, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Neg: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 res = -dst;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, 0, dst, inst.op1.size, true);
            break;
        }

        case OpcodeType::Shl: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 count = ReadOperand(inst.op2, inst.length) & 0x3F;
            u64 res = dst << count;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsLogic(res, inst.op1.size);
            break;
        }

        case OpcodeType::Shr: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 count = ReadOperand(inst.op2, inst.length) & 0x3F;
            u64 res = dst >> count;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsLogic(res, inst.op1.size);
            break;
        }

        case OpcodeType::Sar: {
            s64 dst = static_cast<s64>(ReadOperand(inst.op1, inst.length));
            u64 count = ReadOperand(inst.op2, inst.length) & 0x3F;
            s64 res = dst >> count;
            WriteOperand(inst.op1, static_cast<u64>(res), inst.length, inst.hasRex);
            UpdateFlagsLogic(static_cast<u64>(res), inst.op1.size);
            break;
        }

        case OpcodeType::Rol: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u32 bits = inst.op1.size * 8;
            u32 count = static_cast<u32>(ReadOperand(inst.op2, inst.length) & (bits - 1));
            u64 mask = (inst.op1.size == 8) ? ~0ULL : ((1ULL << bits) - 1);
            dst &= mask;
            u64 res = count ? (((dst << count) | (dst >> (bits - count))) & mask) : dst;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Ror: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u32 bits = inst.op1.size * 8;
            u32 count = static_cast<u32>(ReadOperand(inst.op2, inst.length) & (bits - 1));
            u64 mask = (inst.op1.size == 8) ? ~0ULL : ((1ULL << bits) - 1);
            dst &= mask;
            u64 res = count ? (((dst >> count) | (dst << (bits - count))) & mask) : dst;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Rcl:
        case OpcodeType::Rcr: {
            u64 val = ReadOperand(inst.op1, inst.length);
            u32 bits = inst.op1.size * 8;
            u32 rawCount = static_cast<u32>(ReadOperand(inst.op2, inst.length) & 0x3F);
            u32 count = rawCount % (bits + 1);
            u64 mask = (inst.op1.size == 8) ? ~0ULL : ((1ULL << bits) - 1);
            val &= mask;
            u64 cf = (m_ctx.rflags & 0x001) ? 1 : 0;
            for (u32 i = 0; i < count; i++) {
                if (inst.type == OpcodeType::Rcl) {
                    u64 nextCf = (val >> (bits - 1)) & 1;
                    val = ((val << 1) | cf) & mask;
                    cf = nextCf;
                } else {
                    u64 nextCf = val & 1;
                    val = ((val >> 1) | (cf << (bits - 1))) & mask;
                    cf = nextCf;
                }
            }
            if (count > 0) {
                if (cf) m_ctx.rflags |= 0x001; else m_ctx.rflags &= ~0x001;
            }
            WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Mul: {
            u64 src = ReadOperand(inst.op1, inst.length);
            if (inst.op1.size == 8) {
                __uint128_t prod = static_cast<__uint128_t>(m_ctx.rax) * src;
                m_ctx.rax = static_cast<u64>(prod);
                m_ctx.rdx = static_cast<u64>(prod >> 64);
            } else if (inst.op1.size == 4) {
                u64 prod = static_cast<u64>(static_cast<u32>(m_ctx.rax)) * static_cast<u32>(src);
                m_ctx.rax = static_cast<u32>(prod);
                m_ctx.rdx = static_cast<u32>(prod >> 32);
            }
            break;
        }

        case OpcodeType::Imul: {
            if (inst.op3.kind != Operand::Kind::None) {
                // 3-operand IMUL reg, r/m, imm
                s64 src = static_cast<s64>(ReadOperand(inst.op2, inst.length));
                s64 imm = static_cast<s64>(inst.op3.imm);
                s64 res = src * imm;
                WriteOperand(inst.op1, static_cast<u64>(res), inst.length, inst.hasRex);
            } else if (inst.op2.kind != Operand::Kind::None) {
                // 2-operand IMUL reg, r/m
                s64 dst = static_cast<s64>(ReadOperand(inst.op1, inst.length));
                s64 src = static_cast<s64>(ReadOperand(inst.op2, inst.length));
                s64 res = dst * src;
                WriteOperand(inst.op1, static_cast<u64>(res), inst.length, inst.hasRex);
            } else {
                // 1-operand IMUL r/m
                s64 src = static_cast<s64>(ReadOperand(inst.op1, inst.length));
                if (inst.op1.size == 8) {
                    __int128_t prod = static_cast<__int128_t>(static_cast<s64>(m_ctx.rax)) * src;
                    m_ctx.rax = static_cast<u64>(prod);
                    m_ctx.rdx = static_cast<u64>(prod >> 64);
                } else {
                    s64 prod = static_cast<s64>(static_cast<s32>(m_ctx.rax)) * static_cast<s32>(src);
                    m_ctx.rax = static_cast<u32>(prod);
                    m_ctx.rdx = static_cast<u32>(prod >> 32);
                }
            }
            break;
        }

        case OpcodeType::Div: {
            u64 divisor = ReadOperand(inst.op1, inst.length);
            if (divisor == 0) break; // avoid division by zero
            if (inst.op1.size == 8) {
                __uint128_t dividend = (static_cast<__uint128_t>(m_ctx.rdx) << 64) | m_ctx.rax;
                m_ctx.rax = static_cast<u64>(dividend / divisor);
                m_ctx.rdx = static_cast<u64>(dividend % divisor);
            } else {
                u64 dividend = (static_cast<u64>(static_cast<u32>(m_ctx.rdx)) << 32) | static_cast<u32>(m_ctx.rax);
                m_ctx.rax = static_cast<u32>(dividend / divisor);
                m_ctx.rdx = static_cast<u32>(dividend % divisor);
            }
            break;
        }

        case OpcodeType::Idiv: {
            s64 divisor = static_cast<s64>(ReadOperand(inst.op1, inst.length));
            if (divisor == 0) break;
            if (inst.op1.size == 8) {
                __int128_t dividend = (static_cast<__int128_t>(m_ctx.rdx) << 64) | m_ctx.rax;
                m_ctx.rax = static_cast<u64>(dividend / divisor);
                m_ctx.rdx = static_cast<u64>(dividend % divisor);
            } else {
                s64 dividend = (static_cast<s64>(static_cast<s32>(m_ctx.rdx)) << 32) | static_cast<u32>(m_ctx.rax);
                m_ctx.rax = static_cast<u32>(dividend / divisor);
                m_ctx.rdx = static_cast<u32>(dividend % divisor);
            }
            break;
        }

        case OpcodeType::Inc: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 res = dst + 1;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, 1, inst.op1.size, false, false);
            break;
        }

        case OpcodeType::Dec: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 res = dst - 1;
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, 1, inst.op1.size, true, false);
            break;
        }

        case OpcodeType::Bt:
        case OpcodeType::Bts:
        case OpcodeType::Btr:
        case OpcodeType::Btc: {
            u64 base = ReadOperand(inst.op1, inst.length);
            u64 bitIdx = ReadOperand(inst.op2, inst.length);
            u64 bitMask = 1ULL << (bitIdx & (inst.op1.size * 8 - 1));
            if (base & bitMask) m_ctx.rflags |= 0x001; // CF = 1
            else m_ctx.rflags &= ~0x001;               // CF = 0

            if (inst.type == OpcodeType::Bts) {
                base |= bitMask;
                WriteOperand(inst.op1, base, inst.length, inst.hasRex);
            } else if (inst.type == OpcodeType::Btr) {
                base &= ~bitMask;
                WriteOperand(inst.op1, base, inst.length, inst.hasRex);
            } else if (inst.type == OpcodeType::Btc) {
                base ^= bitMask;
                WriteOperand(inst.op1, base, inst.length, inst.hasRex);
            }
            break;
        }

        case OpcodeType::Cpuid: {
            u32 leaf = static_cast<u32>(m_ctx.rax);
            if (leaf == 0) {
                // Return "AuthenticAMD" for Xbox Scarlett (AMD Zen 2 APU)
                m_ctx.rax = 0x17;
                m_ctx.rbx = 0x68747541; // "Auth"
                m_ctx.rdx = 0x69746e65; // "enti"
                m_ctx.rcx = 0x444d4163; // "cAMD"
            } else if (leaf == 1) {
                m_ctx.rax = 0x00870F10; // Zen 2
                m_ctx.rbx = 0x00020800;
                m_ctx.rcx = 0x7FFAFBFF; // AVX, SSE4.2, SSE4.1, SSSE3, SSE3, FMA, AES
                m_ctx.rdx = 0x178BFBFF; // SSE2, SSE, MMX, FXSR, CMOV
            } else if (leaf == 7) {
                m_ctx.rax = 0;
                m_ctx.rbx = 0x219C01AB; // AVX2, BMI1, BMI2, ERMS
                m_ctx.rcx = 0;
                m_ctx.rdx = 0;
            } else {
                m_ctx.rax = 0;
                m_ctx.rbx = 0;
                m_ctx.rcx = 0;
                m_ctx.rdx = 0;
            }
            break;
        }

        case OpcodeType::Xgetbv: {
            // XCR0 state: x87 (bit 0) | SSE (bit 1) | AVX (bit 2) = 0x7
            m_ctx.rax = 7;
            m_ctx.rdx = 0;
            break;
        }

        case OpcodeType::Xchg: {
            u64 v1 = ReadOperand(inst.op1, inst.length);
            u64 v2 = ReadOperand(inst.op2, inst.length);
            WriteOperand(inst.op1, v2, inst.length, inst.hasRex);
            WriteOperand(inst.op2, v1, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Xadd: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 res = dst + src;
            WriteOperand(inst.op2, dst, inst.length, inst.hasRex);
            WriteOperand(inst.op1, res, inst.length, inst.hasRex);
            UpdateFlagsArithmetic(res, dst, src, inst.op1.size, false);
            break;
        }

        case OpcodeType::Cmpxchg: {
            u64 dst = ReadOperand(inst.op1, inst.length);
            u64 acc = (inst.op1.size == 8) ? m_ctx.rax : ((inst.op1.size == 4) ? static_cast<u32>(m_ctx.rax) : (m_ctx.rax & 0xFF));
            if (dst == acc) {
                m_ctx.rflags |= 0x040; // ZF = 1
                u64 src = ReadOperand(inst.op2, inst.length);
                WriteOperand(inst.op1, src, inst.length, inst.hasRex);
            } else {
                m_ctx.rflags &= ~0x040; // ZF = 0
                if (inst.op1.size == 8) m_ctx.rax = dst;
                else if (inst.op1.size == 4) m_ctx.rax = static_cast<u32>(dst);
                else m_ctx.rax = (m_ctx.rax & ~0xFFULL) | (dst & 0xFFULL);
            }
            break;
        }

        case OpcodeType::Cmpxchg16b: {
            u64 addr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
            u64 memLow = m_memory.Read<u64>(addr);
            u64 memHigh = m_memory.Read<u64>(addr + 8);
            if (memLow == m_ctx.rax && memHigh == m_ctx.rdx) {
                m_ctx.rflags |= 0x040; // ZF = 1
                m_memory.Write<u64>(addr, m_ctx.rbx);
                m_memory.Write<u64>(addr + 8, m_ctx.rcx);
            } else {
                m_ctx.rflags &= ~0x040; // ZF = 0
                m_ctx.rax = memLow;
                m_ctx.rdx = memHigh;
            }
            break;
        }

        case OpcodeType::Cmpxchg8b: {
            u64 addr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
            u32 memLow = m_memory.Read<u32>(addr);
            u32 memHigh = m_memory.Read<u32>(addr + 4);
            if (memLow == static_cast<u32>(m_ctx.rax) && memHigh == static_cast<u32>(m_ctx.rdx)) {
                m_ctx.rflags |= 0x040; // ZF = 1
                m_memory.Write<u32>(addr, static_cast<u32>(m_ctx.rbx));
                m_memory.Write<u32>(addr + 4, static_cast<u32>(m_ctx.rcx));
            } else {
                m_ctx.rflags &= ~0x040; // ZF = 0
                m_ctx.rax = (m_ctx.rax & ~0xFFFFFFFFULL) | memLow;
                m_ctx.rdx = (m_ctx.rdx & ~0xFFFFFFFFULL) | memHigh;
            }
            break;
        }

        case OpcodeType::Cmov: {
            if (CheckCondition(inst.conditionCode, m_ctx.rflags)) {
                u64 val = ReadOperand(inst.op2, inst.length);
                WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            }
            break;
        }

        case OpcodeType::Setcc: {
            u64 val = CheckCondition(inst.conditionCode, m_ctx.rflags) ? 1 : 0;
            WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Bsf: {
            u64 src = ReadOperand(inst.op2, inst.length);
            if (src == 0) {
                m_ctx.rflags |= 0x040; // ZF = 1
            } else {
                m_ctx.rflags &= ~0x040; // ZF = 0
                u64 idx = __builtin_ctzll(src);
                WriteOperand(inst.op1, idx, inst.length, inst.hasRex);
            }
            break;
        }

        case OpcodeType::Bsr: {
            u64 src = ReadOperand(inst.op2, inst.length);
            if (src == 0) {
                m_ctx.rflags |= 0x040; // ZF = 1
            } else {
                m_ctx.rflags &= ~0x040; // ZF = 0
                u64 idx = (inst.op2.size == 8) ? (63 - __builtin_clzll(src)) : (31 - __builtin_clz(static_cast<u32>(src)));
                WriteOperand(inst.op1, idx, inst.length, inst.hasRex);
            }
            break;
        }

        case OpcodeType::Popcnt: {
            u64 src = ReadOperand(inst.op2, inst.length);
            u64 count = (inst.op2.size == 8) ? __builtin_popcountll(src) : __builtin_popcount(static_cast<u32>(src));
            m_ctx.rflags &= ~0x8FF;
            if (count == 0) m_ctx.rflags |= 0x040;
            WriteOperand(inst.op1, count, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Jmp: {
            if (inst.op1.kind == Operand::Kind::Immediate) {
                s64 rel = static_cast<s64>(inst.op1.imm);
                m_ctx.rip += rel;
            } else {
                u64 target = ReadOperand(inst.op1, inst.length);
                m_ctx.rip = target;
            }
            break;
        }

        case OpcodeType::Jcc: {
            if (CheckCondition(inst.conditionCode, m_ctx.rflags)) {
                s64 rel = static_cast<s64>(inst.op1.imm);
                m_ctx.rip += rel;
            }
            break;
        }

        case OpcodeType::Call: {
            u64 target = 0;
            if (inst.op1.kind == Operand::Kind::Immediate) {
                s64 rel = static_cast<s64>(inst.op1.imm);
                target = m_ctx.rip + rel;
            } else {
                target = ReadOperand(inst.op1, inst.length);
            }
            m_ctx.rsp -= 8;
            m_memory.Write<u64>(m_ctx.rsp, m_ctx.rip);
            m_ctx.rip = target;
            break;
        }

        case OpcodeType::Ret: {
            u64 retAddr = m_memory.Read<u64>(m_ctx.rsp);
            m_ctx.rsp += 8;
            if (inst.op1.kind == Operand::Kind::Immediate) {
                m_ctx.rsp += inst.op1.imm;
            }
            m_ctx.rip = retAddr;
            break;
        }

        case OpcodeType::Stos: {
            u64 count = inst.hasRepPrefix ? m_ctx.rcx : 1;
            for (u64 i = 0; i < count; i++) {
                if (inst.opSize == 8) {
                    m_memory.Write<u64>(m_ctx.rdi, m_ctx.rax);
                    m_ctx.rdi += 8;
                } else if (inst.opSize == 4) {
                    m_memory.Write<u32>(m_ctx.rdi, static_cast<u32>(m_ctx.rax));
                    m_ctx.rdi += 4;
                } else {
                    m_memory.Write<u8>(m_ctx.rdi, static_cast<u8>(m_ctx.rax));
                    m_ctx.rdi += 1;
                }
            }
            if (inst.hasRepPrefix) m_ctx.rcx = 0;
            break;
        }

        case OpcodeType::Movdqa:
        case OpcodeType::Movdqu: {
            // 128-bit SIMD move
            u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
            u64 dstAddr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
            if (inst.op2.kind == Operand::Kind::Memory && inst.op1.kind == Operand::Kind::Register) {
                u8 reg = inst.op1.reg;
                m_ctx.ymm[reg].qwords[0] = m_memory.Read<u64>(srcAddr);
                m_ctx.ymm[reg].qwords[1] = m_memory.Read<u64>(srcAddr + 8);
            } else if (inst.op2.kind == Operand::Kind::Register && inst.op1.kind == Operand::Kind::Memory) {
                u8 reg = inst.op2.reg;
                m_memory.Write<u64>(dstAddr, m_ctx.ymm[reg].qwords[0]);
                m_memory.Write<u64>(dstAddr + 8, m_ctx.ymm[reg].qwords[1]);
            } else if (inst.op2.kind == Operand::Kind::Register && inst.op1.kind == Operand::Kind::Register) {
                u8 dstReg = inst.op1.reg;
                u8 srcReg = inst.op2.reg;
                m_ctx.ymm[dstReg] = m_ctx.ymm[srcReg];
            }
            break;
        }

        case OpcodeType::MovqFromGp: {
            u8 dstReg = inst.op1.reg;
            u64 val = ReadOperand(inst.op2, inst.length);
            if (inst.op2.size == 4) val = static_cast<u32>(val);
            m_ctx.ymm[dstReg].qwords[0] = val;
            m_ctx.ymm[dstReg].qwords[1] = 0;
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::MovqToGp: {
            u8 srcReg = inst.op2.reg;
            u64 val = m_ctx.ymm[srcReg].qwords[0];
            if (inst.op1.size == 4) val = static_cast<u32>(val);
            WriteOperand(inst.op1, val, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::MovqXmm: {
            u64 val = 0;
            if (inst.op2.kind == Operand::Kind::Register) {
                val = m_ctx.ymm[inst.op2.reg].qwords[0];
            } else {
                val = m_memory.Read<u64>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
            }
            if (inst.op1.kind == Operand::Kind::Register) {
                u8 dstReg = inst.op1.reg;
                m_ctx.ymm[dstReg].qwords[0] = val;
                m_ctx.ymm[dstReg].qwords[1] = 0;
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            } else {
                m_memory.Write<u64>(inst.op1.GetAddress(m_ctx, m_ctx.rip), val);
            }
            break;
        }

        case OpcodeType::Movsd: {
            if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Memory) {
                u8 reg = inst.op1.reg;
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_ctx.ymm[reg].qwords[0] = m_memory.Read<u64>(srcAddr);
                m_ctx.ymm[reg].qwords[1] = 0;
            } else if (inst.op1.kind == Operand::Kind::Memory && inst.op2.kind == Operand::Kind::Register) {
                u8 reg = inst.op2.reg;
                u64 dstAddr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.Write<u64>(dstAddr, m_ctx.ymm[reg].qwords[0]);
            } else if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Register) {
                u8 dstReg = inst.op1.reg;
                u8 srcReg = inst.op2.reg;
                m_ctx.ymm[dstReg].qwords[0] = m_ctx.ymm[srcReg].qwords[0];
            }
            break;
        }

        case OpcodeType::Movss: {
            if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Memory) {
                u8 reg = inst.op1.reg;
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_ctx.ymm[reg].qwords[0] = m_memory.Read<u32>(srcAddr);
                m_ctx.ymm[reg].qwords[1] = 0;
            } else if (inst.op1.kind == Operand::Kind::Memory && inst.op2.kind == Operand::Kind::Register) {
                u8 reg = inst.op2.reg;
                u64 dstAddr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.Write<u32>(dstAddr, static_cast<u32>(m_ctx.ymm[reg].qwords[0] & 0xFFFFFFFFULL));
            } else if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Register) {
                u8 dstReg = inst.op1.reg;
                u8 srcReg = inst.op2.reg;
                m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[dstReg].qwords[0] & 0xFFFFFFFF00000000ULL) |
                                              (m_ctx.ymm[srcReg].qwords[0] & 0xFFFFFFFFULL);
            }
            break;
        }

        case OpcodeType::Vmovss: {
            if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Memory) {
                u8 reg = inst.op1.reg;
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_ctx.ymm[reg].qwords[0] = m_memory.Read<u32>(srcAddr);
                m_ctx.ymm[reg].qwords[1] = 0;
                m_ctx.ymm[reg].qwords[2] = 0;
                m_ctx.ymm[reg].qwords[3] = 0;
            } else if (inst.op1.kind == Operand::Kind::Memory && inst.op2.kind == Operand::Kind::Register) {
                u8 reg = inst.op2.reg;
                u64 dstAddr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.Write<u32>(dstAddr, static_cast<u32>(m_ctx.ymm[reg].qwords[0] & 0xFFFFFFFFULL));
            } else if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Register) {
                u8 dstReg = inst.op1.reg;
                u8 src1Reg = inst.op3.reg;
                u8 src2Reg = inst.op2.reg;
                u32 low32 = static_cast<u32>(m_ctx.ymm[src2Reg].qwords[0] & 0xFFFFFFFFULL);
                m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[src1Reg].qwords[0] & 0xFFFFFFFF00000000ULL) | low32;
                m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Vmovsd: {
            if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Memory) {
                u8 reg = inst.op1.reg;
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_ctx.ymm[reg].qwords[0] = m_memory.Read<u64>(srcAddr);
                m_ctx.ymm[reg].qwords[1] = 0;
                m_ctx.ymm[reg].qwords[2] = 0;
                m_ctx.ymm[reg].qwords[3] = 0;
            } else if (inst.op1.kind == Operand::Kind::Memory && inst.op2.kind == Operand::Kind::Register) {
                u8 reg = inst.op2.reg;
                u64 dstAddr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.Write<u64>(dstAddr, m_ctx.ymm[reg].qwords[0]);
            } else if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Register) {
                u8 dstReg = inst.op1.reg;
                u8 src1Reg = inst.op3.reg;
                u8 src2Reg = inst.op2.reg;
                m_ctx.ymm[dstReg].qwords[0] = m_ctx.ymm[src2Reg].qwords[0];
                m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Punpcklbw:
        case OpcodeType::Punpckhbw:
        case OpcodeType::Punpcklwd:
        case OpcodeType::Punpckhwd:
        case OpcodeType::Punpckldq:
        case OpcodeType::Punpckhdq:
        case OpcodeType::Punpcklqdq:
        case OpcodeType::Punpckhqdq: {
            u8 dstReg = inst.op1.reg;
            u8 srcBytes[16] = {0}, dstBytes[16] = {0}, resBytes[16] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), srcBytes, 16);
            } else {
                std::memcpy(srcBytes, &m_ctx.ymm[inst.op2.reg], 16);
            }
            std::memcpy(dstBytes, &m_ctx.ymm[dstReg], 16);

            const bool isHigh = (inst.type == OpcodeType::Punpckhbw ||
                                 inst.type == OpcodeType::Punpckhwd ||
                                 inst.type == OpcodeType::Punpckhdq ||
                                 inst.type == OpcodeType::Punpckhqdq);
            int elemBytes = 1;
            if (inst.type == OpcodeType::Punpcklwd || inst.type == OpcodeType::Punpckhwd) elemBytes = 2;
            else if (inst.type == OpcodeType::Punpckldq || inst.type == OpcodeType::Punpckhdq) elemBytes = 4;
            else if (inst.type == OpcodeType::Punpcklqdq || inst.type == OpcodeType::Punpckhqdq) elemBytes = 8;

            const int count = 8 / elemBytes;
            const int base = isHigh ? 8 : 0;
            for (int i = 0; i < count; ++i) {
                std::memcpy(resBytes + (2 * i) * elemBytes, dstBytes + base + i * elemBytes, elemBytes);
                std::memcpy(resBytes + (2 * i + 1) * elemBytes, srcBytes + base + i * elemBytes, elemBytes);
            }
            std::memcpy(&m_ctx.ymm[dstReg], resBytes, 16);
            break;
        }

        case OpcodeType::Xorps: {
            u8 dstReg = inst.op1.reg;
            u64 src0 = 0, src1 = 0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                src0 = m_memory.Read<u64>(srcAddr);
                src1 = m_memory.Read<u64>(srcAddr + 8);
            } else {
                u8 srcReg = inst.op2.reg;
                src0 = m_ctx.ymm[srcReg].qwords[0];
                src1 = m_ctx.ymm[srcReg].qwords[1];
            }
            m_ctx.ymm[dstReg].qwords[0] ^= src0;
            m_ctx.ymm[dstReg].qwords[1] ^= src1;
            break;
        }

        case OpcodeType::Andps: {
            u8 dstReg = inst.op1.reg;
            u64 src0 = 0, src1 = 0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                src0 = m_memory.Read<u64>(srcAddr);
                src1 = m_memory.Read<u64>(srcAddr + 8);
            } else {
                u8 srcReg = inst.op2.reg;
                src0 = m_ctx.ymm[srcReg].qwords[0];
                src1 = m_ctx.ymm[srcReg].qwords[1];
            }
            m_ctx.ymm[dstReg].qwords[0] &= src0;
            m_ctx.ymm[dstReg].qwords[1] &= src1;
            break;
        }

        case OpcodeType::Orps: {
            u8 dstReg = inst.op1.reg;
            u64 src0 = 0, src1 = 0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                src0 = m_memory.Read<u64>(srcAddr);
                src1 = m_memory.Read<u64>(srcAddr + 8);
            } else {
                u8 srcReg = inst.op2.reg;
                src0 = m_ctx.ymm[srcReg].qwords[0];
                src1 = m_ctx.ymm[srcReg].qwords[1];
            }
            m_ctx.ymm[dstReg].qwords[0] |= src0;
            m_ctx.ymm[dstReg].qwords[1] |= src1;
            break;
        }

        case OpcodeType::Addsd:
        case OpcodeType::Subsd:
        case OpcodeType::Mulsd:
        case OpcodeType::Divsd:
        case OpcodeType::Minsd:
        case OpcodeType::Maxsd: {
            u8 dstReg = inst.op1.reg;
            double v1 = *reinterpret_cast<double*>(&m_ctx.ymm[dstReg].qwords[0]);
            double v2 = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 raw = m_memory.Read<u64>(addr);
                v2 = *reinterpret_cast<double*>(&raw);
            } else {
                v2 = *reinterpret_cast<double*>(&m_ctx.ymm[inst.op2.reg].qwords[0]);
            }
            double res = 0.0;
            if (inst.type == OpcodeType::Addsd) res = v1 + v2;
            else if (inst.type == OpcodeType::Subsd) res = v1 - v2;
            else if (inst.type == OpcodeType::Mulsd) res = v1 * v2;
            else if (inst.type == OpcodeType::Divsd) res = (v2 != 0.0) ? (v1 / v2) : 0.0;
            else if (inst.type == OpcodeType::Minsd) res = (v1 < v2) ? v1 : v2;
            else if (inst.type == OpcodeType::Maxsd) res = (v1 > v2) ? v1 : v2;
            m_ctx.ymm[dstReg].qwords[0] = *reinterpret_cast<u64*>(&res);
            break;
        }

        case OpcodeType::Addss:
        case OpcodeType::Subss:
        case OpcodeType::Mulss:
        case OpcodeType::Divss:
        case OpcodeType::Minss:
        case OpcodeType::Maxss:
        case OpcodeType::Rsqrtss:
        case OpcodeType::Rcpss:
        case OpcodeType::Sqrtss: {
            u8 dstReg = inst.op1.reg;
            float v1 = 0.0f;
            std::memcpy(&v1, &m_ctx.ymm[dstReg].qwords[0], sizeof(float));
            float v2 = 0.0f;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u32 raw = m_memory.Read<u32>(addr);
                std::memcpy(&v2, &raw, sizeof(float));
            } else {
                std::memcpy(&v2, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(float));
            }
            float res = 0.0f;
            if (inst.type == OpcodeType::Addss) res = v1 + v2;
            else if (inst.type == OpcodeType::Subss) res = v1 - v2;
            else if (inst.type == OpcodeType::Mulss) res = v1 * v2;
            else if (inst.type == OpcodeType::Divss) res = (v2 != 0.0f) ? (v1 / v2) : 0.0f;
            else if (inst.type == OpcodeType::Minss) res = (v1 < v2) ? v1 : v2;
            else if (inst.type == OpcodeType::Maxss) res = (v1 > v2) ? v1 : v2;
            else if (inst.type == OpcodeType::Sqrtss) res = (v2 >= 0.0f) ? std::sqrt(v2) : 0.0f;
            else if (inst.type == OpcodeType::Rsqrtss) res = (v2 > 0.0f) ? (1.0f / std::sqrt(v2)) : 0.0f;
            else if (inst.type == OpcodeType::Rcpss) res = (v2 != 0.0f) ? (1.0f / v2) : 0.0f;
            u32 resRaw = 0;
            std::memcpy(&resRaw, &res, sizeof(float));
            m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[dstReg].qwords[0] & 0xFFFFFFFF00000000ULL) | resRaw;
            break;
        }

        case OpcodeType::Addps:
        case OpcodeType::Subps:
        case OpcodeType::Mulps:
        case OpcodeType::Divps:
        case OpcodeType::Minps:
        case OpcodeType::Maxps:
        case OpcodeType::Sqrtps:
        case OpcodeType::Rsqrtps:
        case OpcodeType::Rcpps: {
            u8 dstReg = inst.op1.reg;
            float src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 q0 = m_memory.Read<u64>(addr);
                u64 q1 = m_memory.Read<u64>(addr + 8);
                std::memcpy(&src[0], &q0, 8);
                std::memcpy(&src[2], &q1, 8);
            } else {
                std::memcpy(&src[0], &m_ctx.ymm[inst.op2.reg].qwords[0], 8);
                std::memcpy(&src[2], &m_ctx.ymm[inst.op2.reg].qwords[1], 8);
            }
            float dst[4] = {0};
            std::memcpy(&dst[0], &m_ctx.ymm[dstReg].qwords[0], 8);
            std::memcpy(&dst[2], &m_ctx.ymm[dstReg].qwords[1], 8);
            for (int i = 0; i < 4; i++) {
                if (inst.type == OpcodeType::Addps) dst[i] += src[i];
                else if (inst.type == OpcodeType::Subps) dst[i] -= src[i];
                else if (inst.type == OpcodeType::Mulps) dst[i] *= src[i];
                else if (inst.type == OpcodeType::Divps) dst[i] = (src[i] != 0.0f) ? (dst[i] / src[i]) : 0.0f;
                else if (inst.type == OpcodeType::Minps) dst[i] = (dst[i] < src[i]) ? dst[i] : src[i];
                else if (inst.type == OpcodeType::Maxps) dst[i] = (dst[i] > src[i]) ? dst[i] : src[i];
                else if (inst.type == OpcodeType::Sqrtps) dst[i] = (src[i] >= 0.0f) ? std::sqrt(src[i]) : 0.0f;
                else if (inst.type == OpcodeType::Rsqrtps) dst[i] = (src[i] > 0.0f) ? (1.0f / std::sqrt(src[i])) : 0.0f;
                else if (inst.type == OpcodeType::Rcpps) dst[i] = (src[i] != 0.0f) ? (1.0f / src[i]) : 0.0f;
            }
            std::memcpy(&m_ctx.ymm[dstReg].qwords[0], &dst[0], 8);
            std::memcpy(&m_ctx.ymm[dstReg].qwords[1], &dst[2], 8);
            break;
        }

        case OpcodeType::Addpd:
        case OpcodeType::Subpd:
        case OpcodeType::Mulpd:
        case OpcodeType::Divpd:
        case OpcodeType::Minpd:
        case OpcodeType::Maxpd: {
            u8 dstReg = inst.op1.reg;
            double src[2] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 q0 = m_memory.Read<u64>(addr);
                u64 q1 = m_memory.Read<u64>(addr + 8);
                src[0] = *reinterpret_cast<double*>(&q0);
                src[1] = *reinterpret_cast<double*>(&q1);
            } else {
                src[0] = *reinterpret_cast<double*>(&m_ctx.ymm[inst.op2.reg].qwords[0]);
                src[1] = *reinterpret_cast<double*>(&m_ctx.ymm[inst.op2.reg].qwords[1]);
            }
            double dst[2] = {
                *reinterpret_cast<double*>(&m_ctx.ymm[dstReg].qwords[0]),
                *reinterpret_cast<double*>(&m_ctx.ymm[dstReg].qwords[1])
            };
            for (int i = 0; i < 2; i++) {
                if (inst.type == OpcodeType::Addpd) dst[i] += src[i];
                else if (inst.type == OpcodeType::Subpd) dst[i] -= src[i];
                else if (inst.type == OpcodeType::Mulpd) dst[i] *= src[i];
                else if (inst.type == OpcodeType::Divpd) dst[i] = (src[i] != 0.0) ? (dst[i] / src[i]) : 0.0;
                else if (inst.type == OpcodeType::Minpd) dst[i] = (dst[i] < src[i]) ? dst[i] : src[i];
                else if (inst.type == OpcodeType::Maxpd) dst[i] = (dst[i] > src[i]) ? dst[i] : src[i];
            }
            m_ctx.ymm[dstReg].qwords[0] = *reinterpret_cast<u64*>(&dst[0]);
            m_ctx.ymm[dstReg].qwords[1] = *reinterpret_cast<u64*>(&dst[1]);
            break;
        }

        case OpcodeType::Andnps: {
            u8 dstReg = inst.op1.reg;
            u64 src0 = 0, src1 = 0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 srcAddr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                src0 = m_memory.Read<u64>(srcAddr);
                src1 = m_memory.Read<u64>(srcAddr + 8);
            } else {
                u8 srcReg = inst.op2.reg;
                src0 = m_ctx.ymm[srcReg].qwords[0];
                src1 = m_ctx.ymm[srcReg].qwords[1];
            }
            m_ctx.ymm[dstReg].qwords[0] = (~m_ctx.ymm[dstReg].qwords[0]) & src0;
            m_ctx.ymm[dstReg].qwords[1] = (~m_ctx.ymm[dstReg].qwords[1]) & src1;
            break;
        }

        case OpcodeType::Movmskps: {
            u8 srcReg = inst.op2.reg;
            u32 raw[4];
            std::memcpy(&raw[0], &m_ctx.ymm[srcReg].qwords[0], 8);
            std::memcpy(&raw[2], &m_ctx.ymm[srcReg].qwords[1], 8);
            u32 mask = 0;
            for (int i = 0; i < 4; i++) {
                if (raw[i] & 0x80000000U) {
                    mask |= (1U << i);
                }
            }
            WriteOperand(inst.op1, mask, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Cvtsd2ss: {
            u8 dstReg = inst.op1.reg;
            double dVal = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 raw = m_memory.Read<u64>(addr);
                std::memcpy(&dVal, &raw, sizeof(double));
            } else {
                std::memcpy(&dVal, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(double));
            }
            float fVal = static_cast<float>(dVal);
            u32 fRaw = 0;
            std::memcpy(&fRaw, &fVal, sizeof(float));
            m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[dstReg].qwords[0] & 0xFFFFFFFF00000000ULL) | fRaw;
            break;
        }

        case OpcodeType::Cvtss2sd: {
            u8 dstReg = inst.op1.reg;
            float fVal = 0.0f;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u32 raw = m_memory.Read<u32>(addr);
                std::memcpy(&fVal, &raw, sizeof(float));
            } else {
                std::memcpy(&fVal, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(float));
            }
            double dVal = static_cast<double>(fVal);
            u64 dRaw = 0;
            std::memcpy(&dRaw, &dVal, sizeof(double));
            m_ctx.ymm[dstReg].qwords[0] = dRaw;
            break;
        }

        case OpcodeType::Cvtps2pd: {
            u8 dstReg = inst.op1.reg;
            float src[2] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 8);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 8);
            }
            double dst[2] = { static_cast<double>(src[0]), static_cast<double>(src[1]) };
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Cvtpd2ps: {
            u8 dstReg = inst.op1.reg;
            double src[2] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            float dst[4] = { static_cast<float>(src[0]), static_cast<float>(src[1]), 0.0f, 0.0f };
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Cvtdq2ps: {
            u8 dstReg = inst.op1.reg;
            s32 src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            float dst[4];
            for (int i = 0; i < 4; i++) dst[i] = static_cast<float>(src[i]);
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Cvtps2dq:
        case OpcodeType::Cvttps2dq: {
            u8 dstReg = inst.op1.reg;
            float src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            s32 dst[4];
            for (int i = 0; i < 4; i++) {
                dst[i] = (inst.type == OpcodeType::Cvttps2dq)
                    ? static_cast<s32>(src[i])
                    : static_cast<s32>(std::round(src[i]));
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Cmpps:
        case OpcodeType::Cmpss: {
            u8 dstReg = inst.op1.reg;
            u8 pred = static_cast<u8>(inst.op3.imm) & 7;
            auto evalF = [&](float a, float b) -> bool {
                bool ord = !std::isnan(a) && !std::isnan(b);
                switch (pred) {
                    case 0: return ord && (a == b);
                    case 1: return ord && (a < b);
                    case 2: return ord && (a <= b);
                    case 3: return !ord;
                    case 4: return !ord || (a != b);
                    case 5: return !ord || !(a < b);
                    case 6: return !ord || !(a <= b);
                    case 7: return ord;
                }
                return false;
            };
            int count = (inst.type == OpcodeType::Cmpss) ? 1 : 4;
            float src1[4], src2[4] = {0};
            std::memcpy(src1, &m_ctx.ymm[dstReg], 16);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, count * 4);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u32 dst[4];
            std::memcpy(dst, &m_ctx.ymm[dstReg], 16);
            for (int i = 0; i < count; i++) {
                dst[i] = evalF(src1[i], src2[i]) ? 0xFFFFFFFFU : 0U;
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Cmppd:
        case OpcodeType::Cmpsd: {
            u8 dstReg = inst.op1.reg;
            u8 pred = static_cast<u8>(inst.op3.imm) & 7;
            auto evalD = [&](double a, double b) -> bool {
                bool ord = !std::isnan(a) && !std::isnan(b);
                switch (pred) {
                    case 0: return ord && (a == b);
                    case 1: return ord && (a < b);
                    case 2: return ord && (a <= b);
                    case 3: return !ord;
                    case 4: return !ord || (a != b);
                    case 5: return !ord || !(a < b);
                    case 6: return !ord || !(a <= b);
                    case 7: return ord;
                }
                return false;
            };
            int count = (inst.type == OpcodeType::Cmpsd) ? 1 : 2;
            double src1[2], src2[2] = {0};
            std::memcpy(src1, &m_ctx.ymm[dstReg], 16);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, count * 8);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], 16);
            }
            for (int i = 0; i < count; i++) {
                m_ctx.ymm[dstReg].qwords[i] = evalD(src1[i], src2[i]) ? ~0ULL : 0ULL;
            }
            break;
        }

        case OpcodeType::Sqrtsd: {
            u8 dstReg = inst.op1.reg;
            double val = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 raw = m_memory.Read<u64>(addr);
                val = *reinterpret_cast<double*>(&raw);
            } else {
                val = *reinterpret_cast<double*>(&m_ctx.ymm[inst.op2.reg].qwords[0]);
            }
            double res = std::sqrt(val);
            *reinterpret_cast<double*>(&m_ctx.ymm[dstReg].qwords[0]) = res;
            break;
        }

        case OpcodeType::Comiss: {
            u8 dstReg = inst.op1.reg;
            float v1 = 0.0f, v2 = 0.0f;
            std::memcpy(&v1, &m_ctx.ymm[dstReg].qwords[0], sizeof(float));
            if (inst.op2.kind == Operand::Kind::Memory) {
                u32 raw = m_memory.Read<u32>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
                std::memcpy(&v2, &raw, sizeof(float));
            } else {
                std::memcpy(&v2, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(float));
            }
            m_ctx.rflags &= ~(0x800 | 0x080 | 0x010 | 0x040 | 0x004 | 0x001);
            if (std::isnan(v1) || std::isnan(v2)) {
                m_ctx.rflags |= (0x040 | 0x004 | 0x001); // ZF=1, PF=1, CF=1
            } else if (v1 < v2) {
                m_ctx.rflags |= 0x001; // CF=1
            } else if (v1 == v2) {
                m_ctx.rflags |= 0x040; // ZF=1
            }
            break;
        }

        case OpcodeType::Comisd: {
            u8 dstReg = inst.op1.reg;
            double v1 = *reinterpret_cast<const double*>(&m_ctx.ymm[dstReg].qwords[0]);
            double v2 = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 raw = m_memory.Read<u64>(addr);
                v2 = *reinterpret_cast<const double*>(&raw);
            } else {
                v2 = *reinterpret_cast<const double*>(&m_ctx.ymm[inst.op2.reg].qwords[0]);
            }
            m_ctx.rflags &= ~(0x800 | 0x080 | 0x010 | 0x040 | 0x004 | 0x001);
            if (std::isnan(v1) || std::isnan(v2)) {
                m_ctx.rflags |= (0x040 | 0x004 | 0x001); // ZF=1, PF=1, CF=1
            } else if (v1 < v2) {
                m_ctx.rflags |= 0x001; // CF=1
            } else if (v1 == v2) {
                m_ctx.rflags |= 0x040; // ZF=1
            }
            break;
        }

        case OpcodeType::Cvtsi2sd: {
            u8 dstReg = inst.op1.reg;
            s64 intVal = 0;
            if (inst.op2.size == 8) {
                intVal = static_cast<s64>(ReadOperand(inst.op2, inst.length));
            } else {
                intVal = static_cast<s32>(ReadOperand(inst.op2, inst.length));
            }
            double dVal = static_cast<double>(intVal);
            m_ctx.ymm[dstReg].qwords[0] = *reinterpret_cast<u64*>(&dVal);
            break;
        }

        case OpcodeType::Cvtsi2ss: {
            u8 dstReg = inst.op1.reg;
            s64 intVal = 0;
            if (inst.op2.size == 8) {
                intVal = static_cast<s64>(ReadOperand(inst.op2, inst.length));
            } else {
                intVal = static_cast<s32>(ReadOperand(inst.op2, inst.length));
            }
            float fVal = static_cast<float>(intVal);
            u32 fRaw = 0;
            std::memcpy(&fRaw, &fVal, sizeof(float));
            m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[dstReg].qwords[0] & 0xFFFFFFFF00000000ULL) | fRaw;
            break;
        }

        case OpcodeType::Cvtsd2si:
        case OpcodeType::Vcvtsd2si: {
            double dVal = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 raw = m_memory.Read<u64>(addr);
                dVal = *reinterpret_cast<double*>(&raw);
            } else {
                dVal = *reinterpret_cast<double*>(&m_ctx.ymm[inst.op2.reg].qwords[0]);
            }
            if (inst.op1.size == 8) {
                s64 intVal = static_cast<s64>(std::round(dVal));
                WriteOperand(inst.op1, static_cast<u64>(intVal), inst.length, inst.hasRex);
            } else {
                s32 intVal = static_cast<s32>(std::round(dVal));
                WriteOperand(inst.op1, static_cast<u32>(intVal), inst.length, inst.hasRex);
            }
            break;
        }

        case OpcodeType::Cvttsd2si:
        case OpcodeType::Vcvttsd2si: {
            double dVal = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 raw = m_memory.Read<u64>(addr);
                dVal = *reinterpret_cast<double*>(&raw);
            } else {
                dVal = *reinterpret_cast<double*>(&m_ctx.ymm[inst.op2.reg].qwords[0]);
            }
            if (inst.op1.size == 8) {
                s64 intVal = static_cast<s64>(dVal);
                WriteOperand(inst.op1, static_cast<u64>(intVal), inst.length, inst.hasRex);
            } else {
                s32 intVal = static_cast<s32>(dVal);
                WriteOperand(inst.op1, static_cast<u32>(intVal), inst.length, inst.hasRex);
            }
            break;
        }

        case OpcodeType::Cvtss2si:
        case OpcodeType::Cvttss2si:
        case OpcodeType::Vcvtss2si:
        case OpcodeType::Vcvttss2si: {
            float fVal = 0.0f;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u32 raw = m_memory.Read<u32>(addr);
                std::memcpy(&fVal, &raw, sizeof(float));
            } else {
                std::memcpy(&fVal, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(float));
            }
            bool trunc = (inst.type == OpcodeType::Cvttss2si || inst.type == OpcodeType::Vcvttss2si);
            if (trunc) {
                if (inst.op1.size == 8) {
                    s64 intVal = static_cast<s64>(fVal);
                    WriteOperand(inst.op1, static_cast<u64>(intVal), inst.length, inst.hasRex);
                } else {
                    s32 intVal = static_cast<s32>(fVal);
                    WriteOperand(inst.op1, static_cast<u32>(intVal), inst.length, inst.hasRex);
                }
            } else {
                if (inst.op1.size == 8) {
                    s64 intVal = static_cast<s64>(std::round(fVal));
                    WriteOperand(inst.op1, static_cast<u64>(intVal), inst.length, inst.hasRex);
                } else {
                    s32 intVal = static_cast<s32>(std::round(fVal));
                    WriteOperand(inst.op1, static_cast<u32>(intVal), inst.length, inst.hasRex);
                }
            }
            break;
        }

        case OpcodeType::Bswap: {
            u8 reg = inst.op1.reg;
            u64 val = *GetRegisterPtr(m_ctx, reg);
            if (inst.op1.size == 8) {
                *GetRegisterPtr(m_ctx, reg) = __builtin_bswap64(val);
            } else {
                *GetRegisterPtr(m_ctx, reg) = __builtin_bswap32(static_cast<u32>(val));
            }
            break;
        }

        case OpcodeType::Cdqe: {
            if (inst.opSize == 8) {
                m_ctx.rax = static_cast<u64>(static_cast<s64>(static_cast<s32>(m_ctx.rax & 0xFFFFFFFF)));
            } else if (inst.opSize == 4) {
                m_ctx.rax = (m_ctx.rax & ~0xFFFFFFFFULL) | static_cast<u32>(static_cast<s32>(static_cast<s16>(m_ctx.rax & 0xFFFF)));
            }
            break;
        }

        case OpcodeType::Cdq: {
            if (inst.opSize == 8) {
                m_ctx.rdx = (static_cast<s64>(m_ctx.rax) < 0) ? ~0ULL : 0;
            } else {
                m_ctx.rdx = (static_cast<s32>(m_ctx.rax & 0xFFFFFFFF) < 0) ? 0xFFFFFFFFULL : 0;
            }
            break;
        }

        case OpcodeType::Movsx: {
            s64 val = 0;
            if (inst.op2.size == 1) {
                val = static_cast<s8>(ReadOperand(inst.op2, inst.length));
            } else if (inst.op2.size == 2) {
                val = static_cast<s16>(ReadOperand(inst.op2, inst.length));
            }
            WriteOperand(inst.op1, static_cast<u64>(val), inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Psrlw:
        case OpcodeType::Psllw:
        case OpcodeType::Psraw:
        case OpcodeType::Psrld:
        case OpcodeType::Pslld:
        case OpcodeType::Psrad:
        case OpcodeType::Psrlq:
        case OpcodeType::Psllq: {
            u8 dstReg = inst.op1.reg;
            u64 shift = 0;
            if (inst.op2.kind == Operand::Kind::Immediate) {
                shift = inst.op2.imm;
            } else if (inst.op2.kind == Operand::Kind::Memory) {
                shift = m_memory.Read<u64>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
            } else {
                shift = m_ctx.ymm[inst.op2.reg].qwords[0];
            }

            if (inst.type == OpcodeType::Psrlq || inst.type == OpcodeType::Psllq) {
                for (int i = 0; i < 2; ++i) {
                    if (shift >= 64) {
                        m_ctx.ymm[dstReg].qwords[i] = 0;
                    } else if (inst.type == OpcodeType::Psrlq) {
                        m_ctx.ymm[dstReg].qwords[i] >>= shift;
                    } else {
                        m_ctx.ymm[dstReg].qwords[i] <<= shift;
                    }
                }
            } else if (inst.type == OpcodeType::Psrlw || inst.type == OpcodeType::Psllw || inst.type == OpcodeType::Psraw) {
                u16 dst16[8];
                std::memcpy(dst16, &m_ctx.ymm[dstReg], 16);
                for (int i = 0; i < 8; ++i) {
                    if (inst.type == OpcodeType::Psraw) {
                        dst16[i] = static_cast<u16>(static_cast<s16>(dst16[i]) >> std::min<u64>(shift, 15ULL));
                    } else if (shift >= 16) {
                        dst16[i] = 0;
                    } else {
                        dst16[i] = (inst.type == OpcodeType::Psrlw) ? (dst16[i] >> shift) : (dst16[i] << shift);
                    }
                }
                std::memcpy(&m_ctx.ymm[dstReg], dst16, 16);
            } else {
                u32 dst32[4];
                std::memcpy(dst32, &m_ctx.ymm[dstReg], 16);
                for (int i = 0; i < 4; ++i) {
                    if (inst.type == OpcodeType::Psrad) {
                        dst32[i] = static_cast<u32>(static_cast<s32>(dst32[i]) >> std::min<u64>(shift, 31ULL));
                    } else if (shift >= 32) {
                        dst32[i] = 0;
                    } else {
                        dst32[i] = (inst.type == OpcodeType::Psrld) ? (dst32[i] >> shift) : (dst32[i] << shift);
                    }
                }
                std::memcpy(&m_ctx.ymm[dstReg], dst32, 16);
            }
            break;
        }

        case OpcodeType::Psrldq: {
            u8 dstReg = inst.op1.reg;
            u64 byteShift = inst.op2.imm;
            u8 bytes[16] = {0};
            std::memcpy(bytes, &m_ctx.ymm[dstReg], 16);
            u8 res[16] = {0};
            if (byteShift < 16) {
                std::memcpy(res, bytes + byteShift, 16 - byteShift);
            }
            std::memcpy(&m_ctx.ymm[dstReg], res, 16);
            break;
        }

        case OpcodeType::Pslldq: {
            u8 dstReg = inst.op1.reg;
            u64 byteShift = inst.op2.imm;
            u8 bytes[16] = {0};
            std::memcpy(bytes, &m_ctx.ymm[dstReg], 16);
            u8 res[16] = {0};
            if (byteShift < 16) {
                std::memcpy(res + byteShift, bytes, 16 - byteShift);
            }
            std::memcpy(&m_ctx.ymm[dstReg], res, 16);
            break;
        }

        case OpcodeType::Psubb: {
            u8 dstReg = inst.op1.reg;
            u8 src[16] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u8* dst = reinterpret_cast<u8*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < 16; i++) dst[i] -= src[i];
            break;
        }

        case OpcodeType::Psubw: {
            u8 dstReg = inst.op1.reg;
            u16 src[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u16 dst[8];
            std::memcpy(dst, &m_ctx.ymm[dstReg], 16);
            for (int i = 0; i < 8; i++) dst[i] -= src[i];
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Psubq: {
            u8 dstReg = inst.op1.reg;
            u64 src0 = 0, src1 = 0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                src0 = m_memory.Read<u64>(addr);
                src1 = m_memory.Read<u64>(addr + 8);
            } else {
                src0 = m_ctx.ymm[inst.op2.reg].qwords[0];
                src1 = m_ctx.ymm[inst.op2.reg].qwords[1];
            }
            m_ctx.ymm[dstReg].qwords[0] -= src0;
            m_ctx.ymm[dstReg].qwords[1] -= src1;
            break;
        }

        case OpcodeType::Psubd: {
            u8 dstReg = inst.op1.reg;
            u32 src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                u64 q0 = m_memory.Read<u64>(addr);
                u64 q1 = m_memory.Read<u64>(addr + 8);
                *reinterpret_cast<u64*>(&src[0]) = q0;
                *reinterpret_cast<u64*>(&src[2]) = q1;
            } else {
                *reinterpret_cast<u64*>(&src[0]) = m_ctx.ymm[inst.op2.reg].qwords[0];
                *reinterpret_cast<u64*>(&src[2]) = m_ctx.ymm[inst.op2.reg].qwords[1];
            }
            u32 dst[4];
            *reinterpret_cast<u64*>(&dst[0]) = m_ctx.ymm[dstReg].qwords[0];
            *reinterpret_cast<u64*>(&dst[2]) = m_ctx.ymm[dstReg].qwords[1];
            for (int i = 0; i < 4; i++) {
                dst[i] -= src[i];
            }
            m_ctx.ymm[dstReg].qwords[0] = *reinterpret_cast<u64*>(&dst[0]);
            m_ctx.ymm[dstReg].qwords[1] = *reinterpret_cast<u64*>(&dst[2]);
            break;
        }

        case OpcodeType::Paddb: {
            u8 dstReg = inst.op1.reg;
            u8 src[16] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u8* dst = reinterpret_cast<u8*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < 16; i++) dst[i] += src[i];
            break;
        }

        case OpcodeType::Paddw: {
            u8 dstReg = inst.op1.reg;
            u16 src[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u16 dst[8];
            std::memcpy(dst, &m_ctx.ymm[dstReg], 16);
            for (int i = 0; i < 8; i++) dst[i] += src[i];
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Paddd: {
            u8 dstReg = inst.op1.reg;
            u32 src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u32 dst[4];
            std::memcpy(dst, &m_ctx.ymm[dstReg], 16);
            for (int i = 0; i < 4; i++) dst[i] += src[i];
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Paddq: {
            u8 dstReg = inst.op1.reg;
            u64 src0 = 0, src1 = 0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                src0 = m_memory.Read<u64>(addr);
                src1 = m_memory.Read<u64>(addr + 8);
            } else {
                src0 = m_ctx.ymm[inst.op2.reg].qwords[0];
                src1 = m_ctx.ymm[inst.op2.reg].qwords[1];
            }
            m_ctx.ymm[dstReg].qwords[0] += src0;
            m_ctx.ymm[dstReg].qwords[1] += src1;
            break;
        }

        case OpcodeType::Unpcklps: {
            u8 dstReg = inst.op1.reg;
            u32 src32[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src32, 16);
            } else {
                std::memcpy(src32, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u32* dst32 = reinterpret_cast<u32*>(&m_ctx.ymm[dstReg]);
            u32 d0 = dst32[0];
            u32 d1 = dst32[1];
            dst32[0] = d0;
            dst32[1] = src32[0];
            dst32[2] = d1;
            dst32[3] = src32[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Unpcklpd: {
            u8 dstReg = inst.op1.reg;
            u64 src64 = (inst.op2.kind == Operand::Kind::Memory)
                ? m_memory.Read<u64>(inst.op2.GetAddress(m_ctx, m_ctx.rip))
                : m_ctx.ymm[inst.op2.reg].qwords[0];
            m_ctx.ymm[dstReg].qwords[1] = src64;
            break;
        }

        case OpcodeType::Shufps: {
            u8 dstReg = inst.op1.reg;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u32 src32[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src32, 16);
            } else {
                std::memcpy(src32, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u32 oldDst[4];
            std::memcpy(oldDst, &m_ctx.ymm[dstReg], 16);
            u32* dst32 = reinterpret_cast<u32*>(&m_ctx.ymm[dstReg]);
            dst32[0] = oldDst[(imm >> 0) & 3];
            dst32[1] = oldDst[(imm >> 2) & 3];
            dst32[2] = src32[(imm >> 4) & 3];
            dst32[3] = src32[(imm >> 6) & 3];
            break;
        }

        case OpcodeType::Shufpd: {
            u8 dstReg = inst.op1.reg;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u64 src64[2] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src64, 16);
            } else {
                src64[0] = m_ctx.ymm[inst.op2.reg].qwords[0];
                src64[1] = m_ctx.ymm[inst.op2.reg].qwords[1];
            }
            u64 d0 = m_ctx.ymm[dstReg].qwords[0];
            u64 d1 = m_ctx.ymm[dstReg].qwords[1];
            m_ctx.ymm[dstReg].qwords[0] = (imm & 1) ? d1 : d0;
            m_ctx.ymm[dstReg].qwords[1] = (imm & 2) ? src64[1] : src64[0];
            break;
        }

        case OpcodeType::Pshufd: {
            u8 dstReg = inst.op1.reg;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u32 src32[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src32, 16);
            } else {
                std::memcpy(src32, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u32* dst32 = reinterpret_cast<u32*>(&m_ctx.ymm[dstReg]);
            dst32[0] = src32[(imm >> 0) & 3];
            dst32[1] = src32[(imm >> 2) & 3];
            dst32[2] = src32[(imm >> 4) & 3];
            dst32[3] = src32[(imm >> 6) & 3];
            break;
        }

        case OpcodeType::Pshuflw: {
            u8 dstReg = inst.op1.reg;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u16 src16[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src16, 16);
            } else {
                std::memcpy(src16, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u16* dst16 = reinterpret_cast<u16*>(&m_ctx.ymm[dstReg]);
            dst16[0] = src16[(imm >> 0) & 3];
            dst16[1] = src16[(imm >> 2) & 3];
            dst16[2] = src16[(imm >> 4) & 3];
            dst16[3] = src16[(imm >> 6) & 3];
            dst16[4] = src16[4];
            dst16[5] = src16[5];
            dst16[6] = src16[6];
            dst16[7] = src16[7];
            break;
        }

        case OpcodeType::Pshufhw: {
            u8 dstReg = inst.op1.reg;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u16 src16[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src16, 16);
            } else {
                std::memcpy(src16, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u16* dst16 = reinterpret_cast<u16*>(&m_ctx.ymm[dstReg]);
            dst16[0] = src16[0];
            dst16[1] = src16[1];
            dst16[2] = src16[2];
            dst16[3] = src16[3];
            dst16[4] = src16[4 + ((imm >> 0) & 3)];
            dst16[5] = src16[4 + ((imm >> 2) & 3)];
            dst16[6] = src16[4 + ((imm >> 4) & 3)];
            dst16[7] = src16[4 + ((imm >> 6) & 3)];
            break;
        }

        case OpcodeType::Vzeroupper:
            break;

        case OpcodeType::Pcmpeqb: {
            u8 dstReg = inst.op1.reg;
            u8 src2Bytes[16] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Bytes, 16);
            } else {
                std::memcpy(src2Bytes, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u8* dstBytes = reinterpret_cast<u8*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < 16; i++) {
                dstBytes[i] = (dstBytes[i] == src2Bytes[i]) ? 0xFF : 0x00;
            }
            break;
        }

        case OpcodeType::Pcmpeqw: {
            u8 dstReg = inst.op1.reg;
            u16 src2Words[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Words, 16);
            } else {
                std::memcpy(src2Words, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u16* dstWords = reinterpret_cast<u16*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < 8; i++) {
                dstWords[i] = (dstWords[i] == src2Words[i]) ? 0xFFFF : 0x0000;
            }
            break;
        }

        case OpcodeType::Pcmpeqd: {
            u8 dstReg = inst.op1.reg;
            u32 src2Dwords[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Dwords, 16);
            } else {
                std::memcpy(src2Dwords, &m_ctx.ymm[inst.op2.reg], 16);
            }
            u32* dstDwords = reinterpret_cast<u32*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < 4; i++) {
                dstDwords[i] = (dstDwords[i] == src2Dwords[i]) ? 0xFFFFFFFF : 0x00000000;
            }
            break;
        }

        case OpcodeType::Pmovmskb: {
            u8 srcReg = inst.op2.reg;
            int vecBytes = (inst.op2.size == 32) ? 32 : 16;
            const u8* srcBytes = reinterpret_cast<const u8*>(&m_ctx.ymm[srcReg]);
            u32 mask = 0;
            for (int i = 0; i < vecBytes; i++) {
                if (srcBytes[i] & 0x80) {
                    mask |= (1U << i);
                }
            }
            WriteOperand(inst.op1, mask, inst.length, inst.hasRex);
            break;
        }

        case OpcodeType::Vpxor: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            u8 src2Bytes[32] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Bytes, vecSize);
            } else {
                std::memcpy(src2Bytes, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            const u8* src1Bytes = reinterpret_cast<const u8*>(&m_ctx.ymm[src1Reg]);
            u8* dstBytes = reinterpret_cast<u8*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < vecSize; i++) {
                dstBytes[i] = src1Bytes[i] ^ src2Bytes[i];
            }
            if (vecSize == 16) {
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Vpcmpeqb: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            u8 src2Bytes[32] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Bytes, vecSize);
            } else {
                std::memcpy(src2Bytes, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            const u8* src1Bytes = reinterpret_cast<const u8*>(&m_ctx.ymm[src1Reg]);
            u8* dstBytes = reinterpret_cast<u8*>(&m_ctx.ymm[dstReg]);
            for (int i = 0; i < vecSize; i++) {
                dstBytes[i] = (src1Bytes[i] == src2Bytes[i]) ? 0xFF : 0x00;
            }
            if (vecSize == 16) {
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Vpcmpeqw: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            u16 src2Words[16] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Words, vecSize);
            } else {
                std::memcpy(src2Words, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            const u16* src1Words = reinterpret_cast<const u16*>(&m_ctx.ymm[src1Reg]);
            u16* dstWords = reinterpret_cast<u16*>(&m_ctx.ymm[dstReg]);
            int count = vecSize / 2;
            for (int i = 0; i < count; i++) {
                dstWords[i] = (src1Words[i] == src2Words[i]) ? 0xFFFF : 0x0000;
            }
            if (vecSize == 16) {
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Vpcmpeqd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            u32 src2Dwords[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, src2Dwords, vecSize);
            } else {
                std::memcpy(src2Dwords, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            const u32* src1Dwords = reinterpret_cast<const u32*>(&m_ctx.ymm[src1Reg]);
            u32* dstDwords = reinterpret_cast<u32*>(&m_ctx.ymm[dstReg]);
            int count = vecSize / 4;
            for (int i = 0; i < count; i++) {
                dstDwords[i] = (src1Dwords[i] == src2Dwords[i]) ? 0xFFFFFFFF : 0x00000000;
            }
            if (vecSize == 16) {
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Vmovdqa:
        case OpcodeType::Vmovdqu: {
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, &m_ctx.ymm[inst.op1.reg], vecSize);
                if (vecSize == 16) {
                    m_ctx.ymm[inst.op1.reg].qwords[2] = 0;
                    m_ctx.ymm[inst.op1.reg].qwords[3] = 0;
                }
            } else if (inst.op1.kind == Operand::Kind::Memory && inst.op2.kind == Operand::Kind::Register) {
                u64 addr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.WriteBytes(addr, &m_ctx.ymm[inst.op2.reg], vecSize);
            } else if (inst.op1.kind == Operand::Kind::Register && inst.op2.kind == Operand::Kind::Register) {
                std::memcpy(&m_ctx.ymm[inst.op1.reg], &m_ctx.ymm[inst.op2.reg], vecSize);
                if (vecSize == 16) {
                    m_ctx.ymm[inst.op1.reg].qwords[2] = 0;
                    m_ctx.ymm[inst.op1.reg].qwords[3] = 0;
                }
            }
            break;
        }

        case OpcodeType::Cvttpd2dq:
        case OpcodeType::Cvtpd2dq: {
            u8 dstReg = inst.op1.reg;
            double src[2] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 16);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 16);
            }
            s32 dst[4] = {0};
            for (int i = 0; i < 2; i++) {
                dst[i] = (inst.type == OpcodeType::Cvttpd2dq)
                    ? static_cast<s32>(src[i])
                    : static_cast<s32>(std::round(src[i]));
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Cvtdq2pd: {
            u8 dstReg = inst.op1.reg;
            s32 src[2] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, 8);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], 8);
            }
            double dst[2] = { static_cast<double>(src[0]), static_cast<double>(src[1]) };
            std::memcpy(&m_ctx.ymm[dstReg], dst, 16);
            break;
        }

        case OpcodeType::Vcvtss2sd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            float fVal = 0.0f;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u32 raw = m_memory.Read<u32>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
                std::memcpy(&fVal, &raw, sizeof(float));
            } else {
                std::memcpy(&fVal, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(float));
            }
            double dVal = static_cast<double>(fVal);
            u64 dRaw = 0;
            std::memcpy(&dRaw, &dVal, sizeof(double));
            m_ctx.ymm[dstReg].qwords[0] = dRaw;
            m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Vcvtsd2ss: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            double dVal = 0.0;
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 raw = m_memory.Read<u64>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
                std::memcpy(&dVal, &raw, sizeof(double));
            } else {
                std::memcpy(&dVal, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(double));
            }
            float fVal = static_cast<float>(dVal);
            u32 fRaw = 0;
            std::memcpy(&fRaw, &fVal, sizeof(float));
            m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[src1Reg].qwords[0] & 0xFFFFFFFF00000000ULL) | fRaw;
            m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Vcvttpd2dq:
        case OpcodeType::Vcvtpd2dq: {
            u8 dstReg = inst.op1.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = (vecSize == 32) ? 4 : 2;
            double src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, vecSize);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            s32 dst[8] = {0};
            for (int i = 0; i < count; i++) {
                dst[i] = (inst.type == OpcodeType::Vcvttpd2dq)
                    ? static_cast<s32>(src[i])
                    : static_cast<s32>(std::round(src[i]));
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vcvtps2pd: {
            u8 dstReg = inst.op1.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 8;
            float src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, count * 4);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], count * 4);
            }
            double dst[4] = {0};
            for (int i = 0; i < count; i++) {
                dst[i] = static_cast<double>(src[i]);
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vcvtpd2ps: {
            u8 dstReg = inst.op1.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 8;
            double src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, vecSize);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            float dst[8] = {0};
            for (int i = 0; i < count; i++) {
                dst[i] = static_cast<float>(src[i]);
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vcvtsi2ss: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            s64 intVal = (inst.op2.size == 8)
                ? static_cast<s64>(ReadOperand(inst.op2, inst.length))
                : static_cast<s32>(ReadOperand(inst.op2, inst.length));
            float fVal = static_cast<float>(intVal);
            u32 fRaw = 0;
            std::memcpy(&fRaw, &fVal, sizeof(float));
            m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[src1Reg].qwords[0] & 0xFFFFFFFF00000000ULL) | fRaw;
            m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Vcvtsi2sd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            s64 intVal = (inst.op2.size == 8)
                ? static_cast<s64>(ReadOperand(inst.op2, inst.length))
                : static_cast<s32>(ReadOperand(inst.op2, inst.length));
            double dVal = static_cast<double>(intVal);
            u64 dRaw = 0;
            std::memcpy(&dRaw, &dVal, sizeof(double));
            m_ctx.ymm[dstReg].qwords[0] = dRaw;
            m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Vcvtdq2pd: {
            u8 dstReg = inst.op1.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = (vecSize == 32) ? 4 : 2;
            s32 src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, count * 4);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], count * 4);
            }
            double dst[4] = {0};
            for (int i = 0; i < count; i++) {
                dst[i] = static_cast<double>(src[i]);
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vandps:
        case OpcodeType::Vandnps:
        case OpcodeType::Vorps: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            u64 src2[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            u64 src1[4] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            int qwords = vecSize / 8;
            for (int i = 0; i < qwords; i++) {
                if (inst.type == OpcodeType::Vandps) m_ctx.ymm[dstReg].qwords[i] = src1[i] & src2[i];
                else if (inst.type == OpcodeType::Vandnps) m_ctx.ymm[dstReg].qwords[i] = (~src1[i]) & src2[i];
                else m_ctx.ymm[dstReg].qwords[i] = src1[i] | src2[i];
            }
            if (vecSize == 16) {
                m_ctx.ymm[dstReg].qwords[2] = 0;
                m_ctx.ymm[dstReg].qwords[3] = 0;
            }
            break;
        }

        case OpcodeType::Vaddps:
        case OpcodeType::Vsubps:
        case OpcodeType::Vmulps:
        case OpcodeType::Vdivps: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 4;
            float src1[8] = {0}, src2[8] = {0}, dst[8] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int i = 0; i < count; i++) {
                if (inst.type == OpcodeType::Vaddps) dst[i] = src1[i] + src2[i];
                else if (inst.type == OpcodeType::Vsubps) dst[i] = src1[i] - src2[i];
                else if (inst.type == OpcodeType::Vmulps) dst[i] = src1[i] * src2[i];
                else dst[i] = (src2[i] != 0.0f) ? (src1[i] / src2[i]) : 0.0f;
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vaddpd:
        case OpcodeType::Vsubpd:
        case OpcodeType::Vmulpd:
        case OpcodeType::Vdivpd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 8;
            double src1[4] = {0}, src2[4] = {0}, dst[4] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int i = 0; i < count; i++) {
                if (inst.type == OpcodeType::Vaddpd) dst[i] = src1[i] + src2[i];
                else if (inst.type == OpcodeType::Vsubpd) dst[i] = src1[i] - src2[i];
                else if (inst.type == OpcodeType::Vmulpd) dst[i] = src1[i] * src2[i];
                else dst[i] = (src2[i] != 0.0) ? (src1[i] / src2[i]) : 0.0;
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vaddss:
        case OpcodeType::Vsubss:
        case OpcodeType::Vmulss:
        case OpcodeType::Vdivss: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            float v1 = 0.0f, v2 = 0.0f;
            std::memcpy(&v1, &m_ctx.ymm[src1Reg].qwords[0], sizeof(float));
            if (inst.op2.kind == Operand::Kind::Memory) {
                u32 raw = m_memory.Read<u32>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
                std::memcpy(&v2, &raw, sizeof(float));
            } else {
                std::memcpy(&v2, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(float));
            }
            float res = 0.0f;
            if (inst.type == OpcodeType::Vaddss) res = v1 + v2;
            else if (inst.type == OpcodeType::Vsubss) res = v1 - v2;
            else if (inst.type == OpcodeType::Vmulss) res = v1 * v2;
            else res = (v2 != 0.0f) ? (v1 / v2) : 0.0f;
            u32 resRaw = 0;
            std::memcpy(&resRaw, &res, sizeof(float));
            m_ctx.ymm[dstReg].qwords[0] = (m_ctx.ymm[src1Reg].qwords[0] & 0xFFFFFFFF00000000ULL) | resRaw;
            m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Vaddsd:
        case OpcodeType::Vsubsd:
        case OpcodeType::Vmulsd:
        case OpcodeType::Vdivsd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            double v1 = 0.0, v2 = 0.0;
            std::memcpy(&v1, &m_ctx.ymm[src1Reg].qwords[0], sizeof(double));
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 raw = m_memory.Read<u64>(inst.op2.GetAddress(m_ctx, m_ctx.rip));
                std::memcpy(&v2, &raw, sizeof(double));
            } else {
                std::memcpy(&v2, &m_ctx.ymm[inst.op2.reg].qwords[0], sizeof(double));
            }
            double res = 0.0;
            if (inst.type == OpcodeType::Vaddsd) res = v1 + v2;
            else if (inst.type == OpcodeType::Vsubsd) res = v1 - v2;
            else if (inst.type == OpcodeType::Vmulsd) res = v1 * v2;
            else res = (v2 != 0.0) ? (v1 / v2) : 0.0;
            u64 resRaw = 0;
            std::memcpy(&resRaw, &res, sizeof(double));
            m_ctx.ymm[dstReg].qwords[0] = resRaw;
            m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[src1Reg].qwords[1];
            m_ctx.ymm[dstReg].qwords[2] = 0;
            m_ctx.ymm[dstReg].qwords[3] = 0;
            break;
        }

        case OpcodeType::Vshufps: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.conditionCode;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int lanes = (vecSize == 32) ? 2 : 1;
            u32 src1[8] = {0}, src2[8] = {0}, dst[8] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int lane = 0; lane < lanes; lane++) {
                int base = lane * 4;
                dst[base + 0] = src1[base + ((imm >> 0) & 3)];
                dst[base + 1] = src1[base + ((imm >> 2) & 3)];
                dst[base + 2] = src2[base + ((imm >> 4) & 3)];
                dst[base + 3] = src2[base + ((imm >> 6) & 3)];
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpmovsxdq: {
            u8 dstReg = inst.op1.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = (vecSize == 32) ? 4 : 2;
            s32 src[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, count * 4);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], count * 4);
            }
            s64 dst[4] = {0};
            for (int i = 0; i < count; i++) {
                dst[i] = static_cast<s64>(src[i]);
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpcmpeqq: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 8;
            u64 src2[4] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            u64 src1[4] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            u64 dst[4] = {0};
            for (int i = 0; i < count; i++) {
                dst[i] = (src1[i] == src2[i]) ? ~0ULL : 0ULL;
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vcvtdq2ps:
        case OpcodeType::Vcvtps2dq:
        case OpcodeType::Vcvttps2dq: {
            u8 dstReg = inst.op1.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 4;
            if (inst.type == OpcodeType::Vcvtdq2ps) {
                s32 src[8] = {0};
                if (inst.op2.kind == Operand::Kind::Memory) {
                    m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, vecSize);
                } else {
                    std::memcpy(src, &m_ctx.ymm[inst.op2.reg], vecSize);
                }
                float dst[8] = {0};
                for (int i = 0; i < count; i++) dst[i] = static_cast<float>(src[i]);
                std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            } else {
                float src[8] = {0};
                if (inst.op2.kind == Operand::Kind::Memory) {
                    m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, vecSize);
                } else {
                    std::memcpy(src, &m_ctx.ymm[inst.op2.reg], vecSize);
                }
                s32 dst[8] = {0};
                for (int i = 0; i < count; i++) {
                    dst[i] = (inst.type == OpcodeType::Vcvttps2dq)
                        ? static_cast<s32>(src[i])
                        : static_cast<s32>(std::round(src[i]));
                }
                std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            }
            break;
        }

        case OpcodeType::Vpsrld:
        case OpcodeType::Vpslld:
        case OpcodeType::Vpsrad: {
            u8 dstReg = inst.op1.reg;
            u8 srcReg = inst.op2.reg;
            u64 shift = inst.op3.imm;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 4;
            u32 src[8] = {0}, dst[8] = {0};
            std::memcpy(src, &m_ctx.ymm[srcReg], vecSize);
            if (inst.type == OpcodeType::Vpsrad) {
                u64 clamped = std::min<u64>(shift, 31ULL);
                for (int i = 0; i < count; i++) {
                    dst[i] = static_cast<u32>(static_cast<s32>(src[i]) >> clamped);
                }
            } else if (shift < 32) {
                for (int i = 0; i < count; i++) {
                    dst[i] = (inst.type == OpcodeType::Vpsrld) ? (src[i] >> shift) : (src[i] << shift);
                }
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpsrlq:
        case OpcodeType::Vpsllq: {
            u8 dstReg = inst.op1.reg;
            u8 srcReg = inst.op2.reg;
            u64 shift = inst.op3.imm;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 8;
            u64 src[4] = {0}, dst[4] = {0};
            std::memcpy(src, &m_ctx.ymm[srcReg], vecSize);
            if (shift < 64) {
                for (int i = 0; i < count; i++) {
                    dst[i] = (inst.type == OpcodeType::Vpsrlq) ? (src[i] >> shift) : (src[i] << shift);
                }
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpsrldq:
        case OpcodeType::Vpslldq: {
            u8 dstReg = inst.op1.reg;
            u8 srcReg = inst.op2.reg;
            u64 byteShift = inst.op3.imm;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int lanes = vecSize / 16;
            u8 dst[32] = {0};
            if (byteShift < 16) {
                for (int l = 0; l < lanes; l++) {
                    const u8* sLane = reinterpret_cast<const u8*>(&m_ctx.ymm[srcReg]) + l * 16;
                    u8* dLane = dst + l * 16;
                    if (inst.type == OpcodeType::Vpsrldq) {
                        std::memcpy(dLane, sLane + byteShift, 16 - byteShift);
                    } else {
                        std::memcpy(dLane + byteShift, sLane, 16 - byteShift);
                    }
                }
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpaddd:
        case OpcodeType::Vpsubd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 4;
            u32 src1[8] = {0}, src2[8] = {0}, dst[8] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int i = 0; i < count; i++) {
                dst[i] = (inst.type == OpcodeType::Vpaddd) ? (src1[i] + src2[i]) : (src1[i] - src2[i]);
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpaddq:
        case OpcodeType::Vpsubq: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int count = vecSize / 8;
            u64 src1[4] = {0}, src2[4] = {0}, dst[4] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int i = 0; i < count; i++) {
                dst[i] = (inst.type == OpcodeType::Vpaddq) ? (src1[i] + src2[i]) : (src1[i] - src2[i]);
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpshufd: {
            u8 dstReg = inst.op1.reg;
            u8 imm = static_cast<u8>(inst.op3.imm);
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int lanes = vecSize / 16;
            u32 src[8] = {0}, dst[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src, vecSize);
            } else {
                std::memcpy(src, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int l = 0; l < lanes; l++) {
                int b = l * 4;
                dst[b + 0] = src[b + ((imm >> 0) & 3)];
                dst[b + 1] = src[b + ((imm >> 2) & 3)];
                dst[b + 2] = src[b + ((imm >> 4) & 3)];
                dst[b + 3] = src[b + ((imm >> 6) & 3)];
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vpunpckldq:
        case OpcodeType::Vunpcklps: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int lanes = vecSize / 16;
            u32 src1[8] = {0}, src2[8] = {0}, dst[8] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int l = 0; l < lanes; l++) {
                int b = l * 4;
                dst[b + 0] = src1[b + 0];
                dst[b + 1] = src2[b + 0];
                dst[b + 2] = src1[b + 1];
                dst[b + 3] = src2[b + 1];
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vunpcklpd: {
            u8 dstReg = inst.op1.reg;
            u8 src1Reg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            int lanes = vecSize / 16;
            u64 src1[4] = {0}, src2[4] = {0}, dst[4] = {0};
            std::memcpy(src1, &m_ctx.ymm[src1Reg], vecSize);
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), src2, vecSize);
            } else {
                std::memcpy(src2, &m_ctx.ymm[inst.op2.reg], vecSize);
            }
            for (int l = 0; l < lanes; l++) {
                int b = l * 2;
                dst[b + 0] = src1[b + 0];
                dst[b + 1] = src2[b + 0];
            }
            std::memcpy(&m_ctx.ymm[dstReg], dst, 32);
            break;
        }

        case OpcodeType::Vfma: {
            u8 dstReg = inst.op1.reg;
            u8 vvvvReg = inst.op3.reg;
            u8 vecSize = (inst.opSize == 32) ? 32 : 16;
            u8 cc = inst.conditionCode;
            u8 order = cc & 3;
            bool isSub = (cc & 4) != 0;
            bool isNeg = (cc & 8) != 0;
            bool isScalar = (cc & 16) != 0;
            bool isDouble = (cc & 32) != 0;

            u8 op1Bytes[32] = {0}, op2Bytes[32] = {0}, op3Bytes[32] = {0};
            std::memcpy(op1Bytes, &m_ctx.ymm[dstReg], 32);
            std::memcpy(op3Bytes, &m_ctx.ymm[vvvvReg], 32);
            u8 readSz = isScalar ? (isDouble ? 8 : 4) : vecSize;
            if (inst.op2.kind == Operand::Kind::Memory) {
                m_memory.ReadBytes(inst.op2.GetAddress(m_ctx, m_ctx.rip), op2Bytes, readSz);
            } else {
                std::memcpy(op2Bytes, &m_ctx.ymm[inst.op2.reg], readSz);
            }

            if (isDouble) {
                int count = isScalar ? 1 : (vecSize / 8);
                double a[4], b[4], c[4];
                double d1[4], d2[4], d3[4];
                std::memcpy(d1, op1Bytes, 32);
                std::memcpy(d2, op2Bytes, 32);
                std::memcpy(d3, op3Bytes, 32);
                for (int i = 0; i < count; i++) {
                    if (order == 0) { a[i] = d1[i]; b[i] = d2[i]; c[i] = d3[i]; }
                    else if (order == 1) { a[i] = d3[i]; b[i] = d1[i]; c[i] = d2[i]; }
                    else { a[i] = d3[i]; b[i] = d2[i]; c[i] = d1[i]; }
                    double res = std::fma(isNeg ? -a[i] : a[i], b[i], isSub ? -c[i] : c[i]);
                    std::memcpy(&m_ctx.ymm[dstReg].qwords[i], &res, sizeof(double));
                }
                if (isScalar) {
                    m_ctx.ymm[dstReg].qwords[1] = m_ctx.ymm[dstReg].qwords[1]; // preserved in op1
                }
                if (isScalar || vecSize == 16) {
                    m_ctx.ymm[dstReg].qwords[2] = 0;
                    m_ctx.ymm[dstReg].qwords[3] = 0;
                }
            } else {
                int count = isScalar ? 1 : (vecSize / 4);
                float f1[8], f2[8], f3[8], resArr[8] = {0};
                std::memcpy(f1, op1Bytes, 32);
                std::memcpy(f2, op2Bytes, 32);
                std::memcpy(f3, op3Bytes, 32);
                if (isScalar) {
                    std::memcpy(resArr, op1Bytes, 16);
                }
                for (int i = 0; i < count; i++) {
                    float a, b, c;
                    if (order == 0) { a = f1[i]; b = f2[i]; c = f3[i]; }
                    else if (order == 1) { a = f3[i]; b = f1[i]; c = f2[i]; }
                    else { a = f3[i]; b = f2[i]; c = f1[i]; }
                    resArr[i] = std::fma(isNeg ? -a : a, b, isSub ? -c : c);
                }
                std::memcpy(&m_ctx.ymm[dstReg], resArr, 32);
            }
            break;
        }

        case OpcodeType::Pcmpistri: {
            u8 imm = static_cast<u8>(inst.op3.imm);
            u16 srcWords[8] = {0};
            u16 dstWords[8] = {0};
            if (inst.op2.kind == Operand::Kind::Memory) {
                u64 addr = inst.op2.GetAddress(m_ctx, m_ctx.rip);
                m_memory.ReadBytes(addr, srcWords, 16);
            } else {
                std::memcpy(srcWords, &m_ctx.ymm[inst.op2.reg], 16);
            }
            std::memcpy(dstWords, &m_ctx.ymm[inst.op1.reg], 16);

            int lenSrc = 8;
            for (int i = 0; i < 8; i++) {
                if (srcWords[i] == 0) { lenSrc = i; break; }
            }
            int lenDst = 8;
            for (int i = 0; i < 8; i++) {
                if (dstWords[i] == 0) { lenDst = i; break; }
            }

            u8 mode = (imm >> 2) & 3;
            u8 intRes1 = 0;

            if (mode == 0) { // Equal any
                for (int i = 0; i < lenSrc; i++) {
                    for (int j = 0; j < lenDst; j++) {
                        if (srcWords[i] == dstWords[j]) {
                            intRes1 |= (1 << i);
                            break;
                        }
                    }
                }
            } else if (mode == 2) { // Equal each
                for (int i = 0; i < 8; i++) {
                    if (i < lenSrc && i < lenDst && srcWords[i] == dstWords[i]) {
                        intRes1 |= (1 << i);
                    }
                }
            } else if (mode == 3) { // Equal ordered / Substring search
                for (int i = 0; i < 8; i++) {
                    bool match = true;
                    for (int k = 0; k < lenDst; k++) {
                        if (i + k >= 8) {
                            if (i + k >= lenSrc) match = false;
                            break;
                        }
                        if (i + k >= lenSrc || srcWords[i + k] != dstWords[k]) {
                            match = false;
                            break;
                        }
                    }
                    if (match && lenDst > 0) intRes1 |= (1 << i);
                }
            }

            // Polarity
            u8 intRes2 = intRes1;
            if (((imm >> 4) & 3) == 1) {
                intRes2 = ~intRes1 & ((1 << lenSrc) - 1);
            }

            // Index in ECX
            int index = 8;
            if ((imm & 0x40) == 0) {
                for (int i = 0; i < 8; i++) {
                    if (intRes2 & (1 << i)) { index = i; break; }
                }
            } else {
                for (int i = 7; i >= 0; i--) {
                    if (intRes2 & (1 << i)) { index = i; break; }
                }
            }
            m_ctx.rcx = static_cast<u64>(index);

            // Flags
            if (intRes2 != 0) m_ctx.rflags |= 0x001; else m_ctx.rflags &= ~0x001; // CF
            if (lenSrc < 8) m_ctx.rflags |= 0x040; else m_ctx.rflags &= ~0x040;   // ZF
            if (lenDst < 8) m_ctx.rflags |= 0x080; else m_ctx.rflags &= ~0x080;   // SF
            if (intRes2 & 1) m_ctx.rflags |= 0x800; else m_ctx.rflags &= ~0x800;  // OF
            m_ctx.rflags &= ~0x014; // AF, PF
            break;
        }

        case OpcodeType::Fnstcw: {
            if (inst.op1.kind == Operand::Kind::Memory) {
                u64 addr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.Write<u16>(addr, 0x037F); // Standard x87 control word
            }
            break;
        }

        case OpcodeType::Stmxcsr: {
            if (inst.op1.kind == Operand::Kind::Memory) {
                u64 addr = inst.op1.GetAddress(m_ctx, m_ctx.rip);
                m_memory.Write<u32>(addr, 0x1F80); // Standard MXCSR default
            }
            break;
        }

        default:
            break;
    }

    return true;
}

bool Interpreter::Run(u64 maxInstructions) {
    if (m_kernel) m_kernel->ClearYieldRequest();
    u64 sliceCount = 0;
    while (!m_halted && sliceCount < maxInstructions) {
        if (!Step()) break;
        sliceCount++;
        if (m_kernel && m_kernel->ShouldYield()) break;
    }

    if (m_halted && m_ctx.rip != 0x1500f0001ULL) {
        std::stringstream ss;
        ss << "Execution halted: " << sliceCount << " instructions executed (Total: " << m_instructionsExecuted << ", RIP=0x"
           << std::hex << m_ctx.rip << ")";
        LOG_ERROR("Interpreter", ss.str());
    }
    return true;
}

} // namespace Scarlett
