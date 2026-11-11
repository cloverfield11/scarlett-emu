#include "kernel/modules/kernel32.h"
#include "common/logging.h"
#include <chrono>
#include <mach/mach_time.h>
#include <unistd.h>
#include <cstring>

namespace Scarlett::Modules {

static GuestAddr s_cmdLineA = 0;
static GuestAddr s_cmdLineW = 0;
static GuestAddr s_envW = 0;

static void EnsureGlobalBuffers(MemoryManager& mem) {
    if (s_cmdLineA != 0) return;

    // Allocate 64KB for OS environment strings at 0x165000000
    GuestAddr base = mem.Allocate(0x10000, MemoryProtection::ReadWrite, 0x165000000);
    s_cmdLineA = base;
    s_cmdLineW = base + 0x1000;
    s_envW = base + 0x2000;

    const char* cmdA = "\"The Mortuary Assistant.exe\"";
    for (size_t i = 0; i <= strlen(cmdA); ++i) {
        mem.Write<u8>(s_cmdLineA + i, static_cast<u8>(cmdA[i]));
    }

    const char16_t* cmdW = u"\"The Mortuary Assistant.exe\"";
    for (size_t i = 0; i <= std::char_traits<char16_t>::length(cmdW); ++i) {
        mem.Write<u16>(s_cmdLineW + i * 2, static_cast<u16>(cmdW[i]));
    }

    const char16_t* env = u"PATH=C:\\\0";
    for (size_t i = 0; i < 10; ++i) {
        mem.Write<u16>(s_envW + i * 2, static_cast<u16>(env[i]));
    }
}

void RegisterKernel32(HleKernel& kernel) {
    // ExitProcess(UINT uExitCode)
    kernel.RegisterHook("kernel32.dll", "ExitProcess", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 exitCode = static_cast<u32>(ctx.rcx);
        LOG_INFO("Kernel32", "Game requested ExitProcess with code: " + std::to_string(exitCode));
        return 0;
    });

    // TerminateProcess(HANDLE hProcess, UINT uExitCode)
    kernel.RegisterHook("kernel32.dll", "TerminateProcess", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 exitCode = static_cast<u32>(ctx.rdx);
        LOG_INFO("Kernel32", "TerminateProcess called with code: " + std::to_string(exitCode));
        return 1;
    });

    // GetCurrentProcessId()
    kernel.RegisterHook("kernel32.dll", "GetCurrentProcessId", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return static_cast<u64>(getpid());
    });

    // GetCurrentThreadId()
    kernel.RegisterHook("kernel32.dll", "GetCurrentThreadId", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1001; // Main GameOS Thread ID
    });

    // GetCurrentProcess()
    kernel.RegisterHook("kernel32.dll", "GetCurrentProcess", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ~0ULL; // Pseudo handle (HANDLE)-1
    });

    // GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
    kernel.RegisterHook("kernel32.dll", "GetSystemTimeAsFileTime", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFileTime = ctx.rcx;
        if (lpFileTime) {
            auto now = std::chrono::system_clock::now();
            auto duration = now.time_since_epoch();
            u64 intervals = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() / 100 + 116444736000000000ULL;
            mem.Write<u64>(lpFileTime, intervals);
        }
        return 0;
    });

    // InitializeSListHead
    kernel.RegisterHook("kernel32.dll", "InitializeSListHead", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr head = ctx.rcx;
        if (head) {
            mem.Write<u64>(head, 0);
            mem.Write<u64>(head + 8, 0);
        }
        return 0;
    });

    // IsDebuggerPresent
    kernel.RegisterHook("kernel32.dll", "IsDebuggerPresent", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0; // Not being debugged
    });

    // IsProcessorFeaturePresent(DWORD feature)
    kernel.RegisterHook("kernel32.dll", "IsProcessorFeaturePresent", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 feature = static_cast<u32>(ctx.rcx);
        // Zen 2 supports all modern x86 features (AVX, AVX2, SSE4.2, etc.)
        return 1;
    });

    // QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency)
    kernel.RegisterHook("kernel32.dll", "QueryPerformanceFrequency", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFrequency = ctx.rcx;
        u64 freq = 10000000; // 10 MHz standard timer
        if (lpFrequency) {
            mem.Write<u64>(lpFrequency, freq);
        }
        return 1;
    });

    // QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
    kernel.RegisterHook("kernel32.dll", "QueryPerformanceCounter", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpCount = ctx.rcx;
        u64 time = mach_absolute_time();
        if (lpCount) {
            mem.Write<u64>(lpCount, time);
        }
        return 1;
    });

    // VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    kernel.RegisterHook("kernel32.dll", "VirtualAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr preferredBase = ctx.rcx;
        u64 size = ctx.rdx;
        GuestAddr allocated = mem.Allocate(size, MemoryProtection::ReadWrite, preferredBase);
        LOG_DEBUG("Kernel32", "VirtualAlloc: Size=0x" + std::to_string(size) + " -> 0x" + std::to_string(allocated));
        return allocated;
    });

    // GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)
    kernel.RegisterHook("kernel32.dll", "GetStartupInfoW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr ptr = ctx.rcx;
        if (ptr) {
            // Zero 104-byte struct and set cb = 104
            for (u32 i = 0; i < 104; i += 8) mem.Write<u64>(ptr + i, 0);
            mem.Write<u32>(ptr, 104);
        }
        return 0;
    });

    // GetCommandLineA()
    kernel.RegisterHook("kernel32.dll", "GetCommandLineA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureGlobalBuffers(mem);
        return s_cmdLineA;
    });

    // GetCommandLineW()
    kernel.RegisterHook("kernel32.dll", "GetCommandLineW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureGlobalBuffers(mem);
        return s_cmdLineW;
    });

    // GetEnvironmentStringsW()
    kernel.RegisterHook("kernel32.dll", "GetEnvironmentStringsW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureGlobalBuffers(mem);
        return s_envW;
    });

    // FreeEnvironmentStringsW(LPWCH penv)
    kernel.RegisterHook("kernel32.dll", "FreeEnvironmentStringsW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1;
    });

    // GetModuleHandleW(LPCWSTR lpModuleName)
    kernel.RegisterHook("kernel32.dll", "GetModuleHandleW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr namePtr = ctx.rcx;
        // If null or empty, return main executable base
        return 0x140000000;
    });

    // GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)
    kernel.RegisterHook("kernel32.dll", "GetModuleHandleExW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr phModule = ctx.r8;
        if (phModule) {
            mem.Write<u64>(phModule, 0x140000000);
        }
        return 1;
    });

    // GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
    kernel.RegisterHook("kernel32.dll", "GetModuleFileNameW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr outBuf = ctx.rdx;
        u32 maxLen = static_cast<u32>(ctx.r8);
        const char16_t* name = u"The Mortuary Assistant.exe";
        u32 len = static_cast<u32>(std::char_traits<char16_t>::length(name));
        if (outBuf && maxLen > len) {
            for (u32 i = 0; i <= len; ++i) mem.Write<u16>(outBuf + i * 2, static_cast<u16>(name[i]));
            return len;
        }
        return 0;
    });

    // GetProcessHeap()
    kernel.RegisterHook("kernel32.dll", "GetProcessHeap", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0x170000000; // Default heap handle
    });

    // HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
    kernel.RegisterHook("kernel32.dll", "HeapAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 size = ctx.r8;
        if (size == 0) size = 16;
        // Align to 16 bytes
        size = (size + 15) & ~15ULL;
        GuestAddr ptr = mem.Allocate(size, MemoryProtection::ReadWrite);
        return ptr;
    });

    // HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
    kernel.RegisterHook("kernel32.dll", "HeapFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1;
    });

    // HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
    kernel.RegisterHook("kernel32.dll", "HeapReAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr oldMem = ctx.r8;
        u64 size = ctx.r9;
        size = (size + 15) & ~15ULL;
        GuestAddr newMem = mem.Allocate(size, MemoryProtection::ReadWrite);
        if (oldMem && newMem) {
            for (u64 i = 0; i < size; i += 8) {
                mem.Write<u64>(newMem + i, mem.Read<u64>(oldMem + i));
            }
        }
        return newMem;
    });

    // HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
    kernel.RegisterHook("kernel32.dll", "HeapSize", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0x1000; // 4 KB placeholder
    });

    // InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCritSection, DWORD dwSpinCount)
    kernel.RegisterHook("kernel32.dll", "InitializeCriticalSectionAndSpinCount", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr cs = ctx.rcx;
        if (cs) {
            for (u32 i = 0; i < 40; i += 8) mem.Write<u64>(cs + i, 0);
        }
        return 1;
    });

    // EnterCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "EnterCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0;
    });

    // LeaveCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "LeaveCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0;
    });

    // DeleteCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "DeleteCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0;
    });

    // TlsAlloc()
    static u32 s_tlsNextIdx = 1;
    kernel.RegisterHook("kernel32.dll", "TlsAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return s_tlsNextIdx++;
    });

    // TlsGetValue(DWORD dwTlsIndex)
    kernel.RegisterHook("kernel32.dll", "TlsGetValue", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0;
    });

    // TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
    kernel.RegisterHook("kernel32.dll", "TlsSetValue", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1;
    });

    // TlsFree(DWORD dwTlsIndex)
    kernel.RegisterHook("kernel32.dll", "TlsFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1;
    });

    // SetUnhandledExceptionFilter
    kernel.RegisterHook("kernel32.dll", "SetUnhandledExceptionFilter", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0;
    });

    // UnhandledExceptionFilter
    kernel.RegisterHook("kernel32.dll", "UnhandledExceptionFilter", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0;
    });

    // RtlCaptureContext, RtlLookupFunctionEntry, RtlVirtualUnwind, RtlUnwindEx
    kernel.RegisterHook("kernel32.dll", "RtlCaptureContext", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "RtlLookupFunctionEntry", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "RtlVirtualUnwind", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "RtlUnwindEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // GetLastError / SetLastError
    kernel.RegisterHook("kernel32.dll", "GetLastError", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "SetLastError", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // CloseHandle
    kernel.RegisterHook("kernel32.dll", "CloseHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    // GetStdHandle(DWORD nStdHandle)
    kernel.RegisterHook("kernel32.dll", "GetStdHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0x100; // Stdout handle
    });

    // WriteFile
    kernel.RegisterHook("kernel32.dll", "WriteFile", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 len = static_cast<u32>(ctx.r8);
        GuestAddr written = ctx.r9;
        if (written) mem.Write<u32>(written, len);
        return 1;
    });

    // WriteConsoleW
    kernel.RegisterHook("kernel32.dll", "WriteConsoleW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 len = static_cast<u32>(ctx.r8);
        GuestAddr written = ctx.r9;
        if (written) mem.Write<u32>(written, len);
        return 1;
    });

    // MultiByteToWideChar
    kernel.RegisterHook("kernel32.dll", "MultiByteToWideChar", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr src = ctx.r8;
        s32 srcLen = static_cast<s32>(ctx.r9);
        GuestAddr dst = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        s32 dstLen = ctx.rsp ? static_cast<s32>(mem.Read<u32>(ctx.rsp + 48)) : 0;
        if (dstLen == 0) return (srcLen > 0) ? srcLen : 32;
        return dstLen;
    });

    // WideCharToMultiByte
    kernel.RegisterHook("kernel32.dll", "WideCharToMultiByte", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 32;
    });

    // Code page functions
    kernel.RegisterHook("kernel32.dll", "GetACP", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 65001; });
    kernel.RegisterHook("kernel32.dll", "GetOEMCP", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 65001; });
    kernel.RegisterHook("kernel32.dll", "GetCPInfo", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "IsValidCodePage", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetStringTypeW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetFileType", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 2; }); // FILE_TYPE_CHAR
    kernel.RegisterHook("kernel32.dll", "LCMapStringW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetConsoleCP", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 65001; });
    kernel.RegisterHook("kernel32.dll", "GetConsoleMode", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpMode = ctx.rdx;
        if (lpMode) mem.Write<u32>(lpMode, 7);
        return 1;
    });
    kernel.RegisterHook("kernel32.dll", "SetFilePointerEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "FlushFileBuffers", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "SetStdHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "CreateFileW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "FreeLibrary", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetProcAddress", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "LoadLibraryExW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "RaiseException", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "FindFirstFileExW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ~0ULL; });
    kernel.RegisterHook("kernel32.dll", "FindNextFileW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "FindClose", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
}

} // namespace Scarlett::Modules
