#include "cpu/cpu_context.h"
#include "common/logging.h"
#include <iomanip>
#include <sstream>

namespace Scarlett {

void CpuContext::DumpState() const {
    std::stringstream ss;
    ss << "\n--- CPU State (Zen 2 x86_64) ---\n"
       << std::hex << std::setfill('0')
       << "RIP: 0x" << std::setw(16) << rip << "  RFLAGS: 0x" << std::setw(8) << rflags << "\n"
       << "RAX: 0x" << std::setw(16) << rax << "  RBX: 0x" << std::setw(16) << rbx << "\n"
       << "RCX: 0x" << std::setw(16) << rcx << "  RDX: 0x" << std::setw(16) << rdx << "\n"
       << "RSI: 0x" << std::setw(16) << rsi << "  RDI: 0x" << std::setw(16) << rdi << "\n"
       << "RBP: 0x" << std::setw(16) << rbp << "  RSP: 0x" << std::setw(16) << rsp << "\n"
       << "R8 : 0x" << std::setw(16) << r8  << "  R9 : 0x" << std::setw(16) << r9  << "\n"
       << "R10: 0x" << std::setw(16) << r10 << "  R11: 0x" << std::setw(16) << r11 << "\n"
       << "R12: 0x" << std::setw(16) << r12 << "  R13: 0x" << std::setw(16) << r13 << "\n"
       << "R14: 0x" << std::setw(16) << r14 << "  R15: 0x" << std::setw(16) << r15 << "\n";

    LOG_DEBUG("CPU", ss.str());
}

} // namespace Scarlett
