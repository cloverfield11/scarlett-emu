#include "kernel/modules/kernel32.h"
#include "common/logging.h"
#include <chrono>
#include <mach/mach_time.h>
#include <unistd.h>

namespace Scarlett::Modules {

void RegisterKernel32(HleKernel& kernel) {
    // ExitProcess(UINT uExitCode)
    kernel.RegisterHook("kernel32.dll", "ExitProcess", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 exitCode = static_cast<u32>(ctx.rcx);
        LOG_INFO("Kernel32", "Game requested ExitProcess with code: " + std::to_string(exitCode));
        return 0;
    });

    // GetCurrentProcessId()
    kernel.RegisterHook("kernel32.dll", "GetCurrentProcessId", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return static_cast<u64>(getpid());
    });

    // GetCurrentThreadId()
    kernel.RegisterHook("kernel32.dll", "GetCurrentThreadId", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1001; // Main GameOS Thread ID
    });

    // QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency)
    kernel.RegisterHook("kernel32.dll", "QueryPerformanceFrequency", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFrequency = ctx.rcx;
        mach_timebase_info_data_t timebase;
        mach_timebase_info(&timebase);

        // Convert to 10MHz standard Xbox timer frequency
        u64 freq = 10000000;
        if (lpFrequency) {
            mem.Write<u64>(lpFrequency, freq);
        }
        return 1; // TRUE
    });

    // QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
    kernel.RegisterHook("kernel32.dll", "QueryPerformanceCounter", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpCount = ctx.rcx;
        u64 time = mach_absolute_time();
        if (lpCount) {
            mem.Write<u64>(lpCount, time);
        }
        return 1; // TRUE
    });

    // VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    kernel.RegisterHook("kernel32.dll", "VirtualAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr preferredBase = ctx.rcx;
        u64 size = ctx.rdx;
        u32 allocType = static_cast<u32>(ctx.r8);
        u32 protect = static_cast<u32>(ctx.r9);

        GuestAddr allocated = mem.Allocate(size, MemoryProtection::ReadWrite, preferredBase);
        LOG_DEBUG("Kernel32", "VirtualAlloc called: Size=0x" + std::to_string(size) + " -> 0x" + std::to_string(allocated));
        return allocated;
    });
}

} // namespace Scarlett::Modules
