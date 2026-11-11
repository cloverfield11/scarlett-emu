#include "kernel/modules/kernel32.h"
#include "loader/pe_loader.h"
#include "common/logging.h"
#include <chrono>
#include <mach/mach_time.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fnmatch.h>
#include "gpu/metal_renderer.h"

namespace Scarlett::Modules {

static PeLoader* s_peLoader = nullptr;

void SetPeLoader(PeLoader* loader) {
    s_peLoader = loader;
}

static std::string s_gameRootDir = "The Mortuary Assistant";

void SetGameRootDir(const std::string& path) {
    s_gameRootDir = path;
}

static std::string ResolveGuestPath(const std::string& guestPath) {
    if (guestPath.empty()) return "";

    std::string path = guestPath;

    // Strip \\?\ prefix
    if (path.rfind("\\\\?\\", 0) == 0) {
        path = path.substr(4);
    }

    // Replace backslashes with forward slashes
    for (char& c : path) {
        if (c == '\\') c = '/';
    }

    // Strip Windows drive letter (e.g. "C:/", "D:/")
    if (path.size() >= 3 && std::isalpha(path[0]) && path[1] == ':' && path[2] == '/') {
        path = path.substr(3);
    }

    // Remove redundant leading slashes or "./"
    while (!path.empty() && path.front() == '/') path.erase(path.begin());
    if (path.rfind("./", 0) == 0) path = path.substr(2);

    // 1. Direct candidate
    if (access(path.c_str(), F_OK) == 0) {
        return path;
    }

    // 2. Relative to game root
    std::string candidate = s_gameRootDir.empty() ? path : (s_gameRootDir + "/" + path);
    if (access(candidate.c_str(), F_OK) == 0) {
        return candidate;
    }

    return candidate;
}

struct VfsFile {
    int fd{-1};
    std::string path;
};
static std::unordered_map<u64, VfsFile> s_vfsFiles;
static u64 s_nextVfsHandle = 0x2000;

struct VfsFindHandle {
    DIR* dir{nullptr};
    std::string dirPath;
    std::string pattern;
};
static std::unordered_map<u64, VfsFindHandle> s_vfsFindHandles;
static u64 s_nextFindHandle = 0x5000;

static std::string ReadGuestWideString(MemoryManager& mem, GuestAddr addr, size_t maxLen = 1024) {
    std::wstring ws;
    if (addr) {
        u16 ch = 0;
        size_t off = 0;
        while ((ch = mem.Read<u16>(addr + off)) != 0 && (off / 2) < maxLen) {
            ws += static_cast<wchar_t>(ch);
            off += 2;
        }
    }
    return std::string(ws.begin(), ws.end());
}

static std::string ReadGuestAnsiString(MemoryManager& mem, GuestAddr addr, size_t maxLen = 1024) {
    std::string s;
    if (addr) {
        char ch = 0;
        size_t off = 0;
        while ((ch = mem.Read<char>(addr + off)) != 0 && off < maxLen) {
            s += ch;
            off++;
        }
    }
    return s;
}

static bool MatchFindPattern(const std::string& pattern, const std::string& name) {
    if (pattern.empty() || pattern == "*" || pattern == "*.*") return true;
    return fnmatch(pattern.c_str(), name.c_str(), FNM_CASEFOLD) == 0;
}

static bool PopulateFindData(MemoryManager& mem, GuestAddr lpFindFileData, const std::string& fullPath, const std::string& fileName) {
    if (!lpFindFileData) return false;

    struct stat st;
    if (stat(fullPath.c_str(), &st) != 0) {
        return false;
    }

    u32 attrs = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
    mem.Write<u32>(lpFindFileData + 0, attrs);
    mem.Write<u64>(lpFindFileData + 4, static_cast<u64>(st.st_ctime) * 10000000ULL + 116444736000000000ULL);
    mem.Write<u64>(lpFindFileData + 12, static_cast<u64>(st.st_atime) * 10000000ULL + 116444736000000000ULL);
    mem.Write<u64>(lpFindFileData + 20, static_cast<u64>(st.st_mtime) * 10000000ULL + 116444736000000000ULL);
    mem.Write<u32>(lpFindFileData + 28, static_cast<u32>(st.st_size >> 32));
    mem.Write<u32>(lpFindFileData + 32, static_cast<u32>(st.st_size & 0xFFFFFFFF));
    mem.Write<u32>(lpFindFileData + 36, 0); // dwReserved0
    mem.Write<u32>(lpFindFileData + 40, 0); // dwReserved1

    size_t i = 0;
    for (; i < fileName.size() && i < 259; ++i) {
        mem.Write<u16>(lpFindFileData + 44 + (i * 2), static_cast<u16>(fileName[i]));
    }
    mem.Write<u16>(lpFindFileData + 44 + (i * 2), 0);
    mem.Write<u16>(lpFindFileData + 564, 0); // cAlternateFileName

    return true;
}

static GuestAddr s_cmdLineA = 0;
static GuestAddr s_cmdLineW = 0;
static GuestAddr s_envW = 0;
static u32 s_lastErrorCode = 0;

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
    static GuestAddr s_heapCurrent = 0x280000000ULL;
    kernel.RegisterHook("kernel32.dll", "HeapAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 size = ctx.r8;
        if (size == 0) size = 16;
        size = (size + 15) & ~15ULL; // 16-byte alignment
        GuestAddr ptr = s_heapCurrent;
        s_heapCurrent += size;
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
        GuestAddr newMem = s_heapCurrent;
        s_heapCurrent += size;
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
    kernel.RegisterHook("kernel32.dll", "GetLastError", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return s_lastErrorCode; });
    kernel.RegisterHook("kernel32.dll", "SetLastError", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        s_lastErrorCode = static_cast<u32>(ctx.rcx);
        return 0;
    });

    // CloseHandle
    kernel.RegisterHook("kernel32.dll", "CloseHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        auto it = s_vfsFiles.find(handle);
        if (it != s_vfsFiles.end()) {
            if (it->second.fd >= 0) close(it->second.fd);
            s_vfsFiles.erase(it);
            return 1;
        }
        return 1;
    });

    // GetStdHandle(DWORD nStdHandle)
    kernel.RegisterHook("kernel32.dll", "GetStdHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0x100; // Stdout handle
    });

    // WriteFile
    kernel.RegisterHook("kernel32.dll", "WriteFile", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        GuestAddr lpBuffer = ctx.rdx;
        u32 nNumberOfBytesToWrite = static_cast<u32>(ctx.r8);
        GuestAddr lpNumberOfBytesWritten = ctx.r9;

        auto it = s_vfsFiles.find(handle);
        if (it != s_vfsFiles.end() && it->second.fd >= 0) {
            std::vector<u8> buf(nNumberOfBytesToWrite);
            if (lpBuffer) mem.ReadBytes(lpBuffer, buf.data(), nNumberOfBytesToWrite);
            ssize_t written = write(it->second.fd, buf.data(), nNumberOfBytesToWrite);
            if (lpNumberOfBytesWritten) {
                mem.Write<u32>(lpNumberOfBytesWritten, static_cast<u32>(written > 0 ? written : 0));
            }
            return 1;
        }

        // Standard handles fallback (stdout/stderr)
        if (lpBuffer && nNumberOfBytesToWrite > 0) {
            std::string text(nNumberOfBytesToWrite, 0);
            mem.ReadBytes(lpBuffer, text.data(), nNumberOfBytesToWrite);
            LOG_INFO("GameConsole", text);
        }
        if (lpNumberOfBytesWritten) {
            mem.Write<u32>(lpNumberOfBytesWritten, nNumberOfBytesToWrite);
        }
        return 1;
    });

    // ReadFile
    kernel.RegisterHook("kernel32.dll", "ReadFile", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        GuestAddr lpBuffer = ctx.rdx;
        u32 nNumberOfBytesToRead = static_cast<u32>(ctx.r8);
        GuestAddr lpNumberOfBytesRead = ctx.r9;

        auto it = s_vfsFiles.find(handle);
        if (it == s_vfsFiles.end() || it->second.fd < 0) {
            s_lastErrorCode = 6; // ERROR_INVALID_HANDLE
            if (lpNumberOfBytesRead) mem.Write<u32>(lpNumberOfBytesRead, 0);
            return 0; // FALSE
        }

        int fd = it->second.fd;
        std::vector<u8> buf(nNumberOfBytesToRead);
        ssize_t bytesRead = read(fd, buf.data(), nNumberOfBytesToRead);
        if (bytesRead < 0) {
            s_lastErrorCode = 30; // ERROR_READ_FAULT
            if (lpNumberOfBytesRead) mem.Write<u32>(lpNumberOfBytesRead, 0);
            return 0; // FALSE
        }

        if (bytesRead > 0 && lpBuffer) {
            mem.WriteBytes(lpBuffer, buf.data(), bytesRead);
        }

        if (lpNumberOfBytesRead) {
            mem.Write<u32>(lpNumberOfBytesRead, static_cast<u32>(bytesRead));
        }

        return 1; // TRUE
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
    // VFS File Operations
    auto createFileHandler = [](const std::string& rawPath, u32 desiredAccess, u32 creationDisposition, MemoryManager& mem) -> u64 {
        std::string resolved = ResolveGuestPath(rawPath);
        LOG_INFO("VFS", "CreateFile: '" + rawPath + "' -> resolved: '" + resolved + "'");

        int flags = 0;
        if ((desiredAccess & 0x40000000) && (desiredAccess & 0x80000000)) {
            flags = O_RDWR;
        } else if (desiredAccess & 0x40000000) {
            flags = O_WRONLY;
        } else {
            flags = O_RDONLY;
        }

        if (creationDisposition == 2) { // CREATE_ALWAYS
            flags |= (O_CREAT | O_TRUNC);
        } else if (creationDisposition == 4) { // OPEN_ALWAYS
            flags |= O_CREAT;
        }

        int fd = open(resolved.c_str(), flags, 0644);
        if (fd < 0) {
            LOG_DEBUG("VFS", "CreateFile failed: '" + resolved + "' (errno: " + strerror(errno) + ")");
            s_lastErrorCode = 2; // ERROR_FILE_NOT_FOUND
            return ~0ULL; // INVALID_HANDLE_VALUE
        }

        u64 handle = ++s_nextVfsHandle;
        s_vfsFiles[handle] = {fd, resolved};
        LOG_INFO("VFS", "CreateFile succeeded: '" + resolved + "' -> HANDLE=0x" + std::to_string(handle));
        return handle;
    };

    kernel.RegisterHook("kernel32.dll", "CreateFileW", [createFileHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFileName = ctx.rcx;
        u32 desiredAccess = static_cast<u32>(ctx.rdx);
        u32 creationDisposition = ctx.rsp ? static_cast<u32>(mem.Read<u32>(ctx.rsp + 40)) : 3;

        std::wstring wpath;
        if (lpFileName) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(lpFileName + off)) != 0 && off < 2048) {
                wpath += static_cast<wchar_t>(ch);
                off += 2;
            }
        }
        std::string path(wpath.begin(), wpath.end());
        return createFileHandler(path, desiredAccess, creationDisposition, mem);
    });

    kernel.RegisterHook("kernel32.dll", "CreateFileA", [createFileHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFileName = ctx.rcx;
        u32 desiredAccess = static_cast<u32>(ctx.rdx);
        u32 creationDisposition = ctx.rsp ? static_cast<u32>(mem.Read<u32>(ctx.rsp + 40)) : 3;

        std::string path;
        if (lpFileName) {
            char ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<char>(lpFileName + off)) != 0 && off < 1024) {
                path += ch;
                off++;
            }
        }
        return createFileHandler(path, desiredAccess, creationDisposition, mem);
    });

    kernel.RegisterHook("kernel32.dll", "SetFilePointerEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        s64 liDistanceToMove = static_cast<s64>(ctx.rdx);
        GuestAddr lpNewFilePointer = ctx.r8;
        u32 dwMoveMethod = static_cast<u32>(ctx.r9);

        auto it = s_vfsFiles.find(handle);
        if (it == s_vfsFiles.end() || it->second.fd < 0) {
            s_lastErrorCode = 6; // ERROR_INVALID_HANDLE
            return 0; // FALSE
        }

        int whence = SEEK_SET;
        if (dwMoveMethod == 1) whence = SEEK_CUR;
        else if (dwMoveMethod == 2) whence = SEEK_END;

        off_t newPos = lseek(it->second.fd, static_cast<off_t>(liDistanceToMove), whence);
        if (newPos < 0) {
            s_lastErrorCode = 131; // ERROR_NEGATIVE_SEEK
            return 0; // FALSE
        }

        if (lpNewFilePointer) {
            mem.Write<u64>(lpNewFilePointer, static_cast<u64>(newPos));
        }
        return 1; // TRUE
    });

    kernel.RegisterHook("kernel32.dll", "SetFilePointer", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        s32 lDistanceToMove = static_cast<s32>(ctx.rdx);
        GuestAddr lpDistanceToMoveHigh = ctx.r8;
        u32 dwMoveMethod = static_cast<u32>(ctx.r9);

        auto it = s_vfsFiles.find(handle);
        if (it == s_vfsFiles.end() || it->second.fd < 0) {
            s_lastErrorCode = 6;
            return 0xFFFFFFFF; // INVALID_SET_FILE_POINTER
        }

        s64 dist = lDistanceToMove;
        if (lpDistanceToMoveHigh) {
            s32 high = mem.Read<s32>(lpDistanceToMoveHigh);
            dist |= (static_cast<s64>(high) << 32);
        }

        int whence = SEEK_SET;
        if (dwMoveMethod == 1) whence = SEEK_CUR;
        else if (dwMoveMethod == 2) whence = SEEK_END;

        off_t newPos = lseek(it->second.fd, static_cast<off_t>(dist), whence);
        if (newPos < 0) {
            s_lastErrorCode = 131;
            return 0xFFFFFFFF;
        }

        if (lpDistanceToMoveHigh) {
            mem.Write<s32>(lpDistanceToMoveHigh, static_cast<s32>(newPos >> 32));
        }
        return static_cast<u32>(newPos & 0xFFFFFFFF);
    });

    kernel.RegisterHook("kernel32.dll", "GetFileSizeEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        GuestAddr lpFileSize = ctx.rdx;

        auto it = s_vfsFiles.find(handle);
        if (it == s_vfsFiles.end() || it->second.fd < 0) {
            s_lastErrorCode = 6;
            return 0; // FALSE
        }

        struct stat st;
        if (fstat(it->second.fd, &st) != 0) {
            s_lastErrorCode = 1;
            return 0;
        }

        if (lpFileSize) {
            mem.Write<u64>(lpFileSize, static_cast<u64>(st.st_size));
        }
        return 1; // TRUE
    });

    kernel.RegisterHook("kernel32.dll", "GetFileSize", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        GuestAddr lpFileSizeHigh = ctx.rdx;

        auto it = s_vfsFiles.find(handle);
        if (it == s_vfsFiles.end() || it->second.fd < 0) {
            s_lastErrorCode = 6;
            return 0xFFFFFFFF;
        }

        struct stat st;
        if (fstat(it->second.fd, &st) != 0) {
            s_lastErrorCode = 1;
            return 0xFFFFFFFF;
        }

        if (lpFileSizeHigh) {
            mem.Write<u32>(lpFileSizeHigh, static_cast<u32>(st.st_size >> 32));
        }
        return static_cast<u32>(st.st_size & 0xFFFFFFFF);
    });

    kernel.RegisterHook("kernel32.dll", "FlushFileBuffers", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        auto it = s_vfsFiles.find(handle);
        if (it != s_vfsFiles.end() && it->second.fd >= 0) {
            fsync(it->second.fd);
        }
        return 1;
    });

    kernel.RegisterHook("kernel32.dll", "SetStdHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "FreeLibrary", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    auto loadLibraryHandler = [](const std::string& rawName, MemoryManager& mem) -> u64 {
        std::string name = rawName;
        while (!name.empty() && (name.front() == '"' || name.front() == '\'')) name.erase(name.begin());
        while (!name.empty() && (name.back() == '"' || name.back() == '\'')) name.pop_back();

        size_t lastSlash = name.find_last_of("/\\");
        std::string baseName = (lastSlash != std::string::npos) ? name.substr(lastSlash + 1) : name;

        LOG_INFO("Kernel32", "LoadLibrary requested for: '" + rawName + "' (Base: '" + baseName + "')");

        if (s_peLoader) {
            for (const auto& mod : s_peLoader->GetLoadedModules()) {
                std::string modLower = mod.name;
                std::string baseLower = baseName;
                std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);
                std::transform(baseLower.begin(), baseLower.end(), baseLower.begin(), ::tolower);
                if (modLower == baseLower) {
                    LOG_INFO("Kernel32", "LoadLibrary: Found already loaded module '" + mod.name + "' -> 0x" + std::to_string(mod.imageBase));
                    return mod.imageBase;
                }
            }

            std::vector<std::string> searchPaths = {
                baseName,
                "The Mortuary Assistant/" + baseName,
                "/Users/igor/Desktop/бокс/The Mortuary Assistant/" + baseName
            };
            for (const auto& sp : searchPaths) {
                if (access(sp.c_str(), F_OK) == 0) {
                    LOG_INFO("Kernel32", "LoadLibrary: Dynamically loading module from '" + sp + "'");
                    if (s_peLoader->LoadModule(sp)) {
                        for (const auto& mod : s_peLoader->GetLoadedModules()) {
                            std::string modLower = mod.name;
                            std::string baseLower = baseName;
                            std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);
                            std::transform(baseLower.begin(), baseLower.end(), baseLower.begin(), ::tolower);
                            if (modLower == baseLower) {
                                return mod.imageBase;
                            }
                        }
                    }
                }
            }
        }

        u64 pseudoHandle = 0x170000000ULL + std::hash<std::string>{}(baseName);
        LOG_INFO("Kernel32", "LoadLibrary: Returning pseudo handle 0x" + std::to_string(pseudoHandle) + " for '" + baseName + "'");
        return pseudoHandle;
    };

    kernel.RegisterHook("kernel32.dll", "LoadLibraryA", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpName = ctx.rcx;
        std::string name;
        if (lpName) {
            char ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<char>(lpName + off)) != 0 && off < 512) {
                name += ch;
                off++;
            }
        }
        return loadLibraryHandler(name, mem);
    });

    kernel.RegisterHook("kernel32.dll", "LoadLibraryW", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpName = ctx.rcx;
        std::wstring wname;
        if (lpName) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(lpName + off)) != 0 && off < 1024) {
                wname += static_cast<wchar_t>(ch);
                off += 2;
            }
        }
        std::string name(wname.begin(), wname.end());
        return loadLibraryHandler(name, mem);
    });

    kernel.RegisterHook("kernel32.dll", "LoadLibraryExW", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpName = ctx.rcx;
        std::wstring wname;
        if (lpName) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(lpName + off)) != 0 && off < 1024) {
                wname += static_cast<wchar_t>(ch);
                off += 2;
            }
        }
        std::string name(wname.begin(), wname.end());
        return loadLibraryHandler(name, mem);
    });

    kernel.RegisterHook("kernel32.dll", "GetProcAddress", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hModule = ctx.rcx;
        GuestAddr lpProcName = ctx.rdx;
        std::string funcName;
        if (lpProcName <= 0xFFFF) {
            funcName = "Ordinal_" + std::to_string(lpProcName);
        } else {
            char ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<char>(lpProcName + off)) != 0 && off < 256) {
                funcName += ch;
                off++;
            }
        }

        LOG_INFO("Kernel32", "GetProcAddress(0x" + std::to_string(hModule) + ", '" + funcName + "')");

        if (s_peLoader) {
            for (const auto& mod : s_peLoader->GetLoadedModules()) {
                if (hModule == 0 || mod.imageBase == hModule || hModule >= 0x170000000ULL) {
                    GuestAddr exp = s_peLoader->FindExport(mod.name, funcName);
                    if (exp != 0) {
                        LOG_INFO("Kernel32", "GetProcAddress: Resolved '" + funcName + "' in '" + mod.name + "' -> 0x" + std::to_string(exp));
                        return exp;
                    }
                }
            }
        }

        static GuestAddr s_dummyProc = 0;
        if (s_dummyProc == 0) {
            s_dummyProc = mem.Allocate(16, MemoryProtection::ExecuteReadWrite);
            mem.Write<u8>(s_dummyProc, 0xC3); // RET
        }
        LOG_INFO("Kernel32", "GetProcAddress: Returning fallback stub for '" + funcName + "'");
        return s_dummyProc;
    });
    kernel.RegisterHook("kernel32.dll", "RaiseException", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    auto findFirstHandler = [](const std::string& rawSearchPath, GuestAddr lpFindFileData, MemoryManager& mem) -> u64 {
        std::string search = rawSearchPath;
        for (char& c : search) if (c == '\\') c = '/';

        std::string dirPath = ".";
        std::string pattern = "*";

        size_t lastSlash = search.find_last_of('/');
        if (lastSlash != std::string::npos) {
            dirPath = search.substr(0, lastSlash);
            pattern = search.substr(lastSlash + 1);
        } else {
            pattern = search;
        }

        std::string resolvedDir = ResolveGuestPath(dirPath);
        LOG_INFO("VFS", "FindFirstFile: '" + rawSearchPath + "' -> Dir: '" + resolvedDir + "', Pattern: '" + pattern + "'");

        DIR* dir = opendir(resolvedDir.c_str());
        if (!dir) {
            LOG_DEBUG("VFS", "FindFirstFile opendir failed for: '" + resolvedDir + "'");
            s_lastErrorCode = 3; // ERROR_PATH_NOT_FOUND
            return ~0ULL; // INVALID_HANDLE_VALUE
        }

        struct dirent* entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;
            if (MatchFindPattern(pattern, name)) {
                std::string fullPath = resolvedDir + "/" + name;
                PopulateFindData(mem, lpFindFileData, fullPath, name);

                u64 handle = ++s_nextFindHandle;
                s_vfsFindHandles[handle] = {dir, resolvedDir, pattern};
                LOG_INFO("VFS", "FindFirstFile found: '" + name + "' -> HANDLE=0x" + std::to_string(handle));
                return handle;
            }
        }

        closedir(dir);
        s_lastErrorCode = 18; // ERROR_NO_MORE_FILES
        return ~0ULL;
    };

    kernel.RegisterHook("kernel32.dll", "FindFirstFileW", [findFirstHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string path = ReadGuestWideString(mem, ctx.rcx);
        GuestAddr lpFindFileData = ctx.rdx;
        return findFirstHandler(path, lpFindFileData, mem);
    });

    kernel.RegisterHook("kernel32.dll", "FindFirstFileA", [findFirstHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string path = ReadGuestAnsiString(mem, ctx.rcx);
        GuestAddr lpFindFileData = ctx.rdx;
        return findFirstHandler(path, lpFindFileData, mem);
    });

    kernel.RegisterHook("kernel32.dll", "FindFirstFileExW", [findFirstHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string path = ReadGuestWideString(mem, ctx.rcx);
        GuestAddr lpFindFileData = ctx.r8;
        return findFirstHandler(path, lpFindFileData, mem);
    });

    kernel.RegisterHook("kernel32.dll", "FindNextFileW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        GuestAddr lpFindFileData = ctx.rdx;

        auto it = s_vfsFindHandles.find(handle);
        if (it == s_vfsFindHandles.end() || !it->second.dir) {
            s_lastErrorCode = 6; // ERROR_INVALID_HANDLE
            return 0; // FALSE
        }

        struct dirent* entry = nullptr;
        while ((entry = readdir(it->second.dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;
            if (MatchFindPattern(it->second.pattern, name)) {
                std::string fullPath = it->second.dirPath + "/" + name;
                PopulateFindData(mem, lpFindFileData, fullPath, name);
                return 1; // TRUE
            }
        }

        s_lastErrorCode = 18; // ERROR_NO_MORE_FILES
        return 0; // FALSE
    });

    kernel.RegisterHook("kernel32.dll", "FindClose", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        auto it = s_vfsFindHandles.find(handle);
        if (it != s_vfsFindHandles.end()) {
            if (it->second.dir) closedir(it->second.dir);
            s_vfsFindHandles.erase(it);
            return 1; // TRUE
        }
        return 1;
    });

    // VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
    kernel.RegisterHook("kernel32.dll", "VirtualProtect", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpAddress = ctx.rcx;
        u64 dwSize = ctx.rdx;
        u32 flNewProtect = static_cast<u32>(ctx.r8);
        GuestAddr lpflOldProtect = ctx.r9;
        if (lpflOldProtect) {
            mem.Write<u32>(lpflOldProtect, 0x40); // PAGE_EXECUTE_READWRITE
        }
        return 1; // Success
    });

    // CreateEventW / CreateEventA
    static u64 s_eventHandleCounter = 0x200;
    kernel.RegisterHook("kernel32.dll", "CreateEventW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ++s_eventHandleCounter;
    });
    kernel.RegisterHook("kernel32.dll", "CreateEventA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ++s_eventHandleCounter;
    });
    kernel.RegisterHook("kernel32.dll", "SetEvent", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "ResetEvent", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    // CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)
    kernel.RegisterHook("kernel32.dll", "CreatePipe", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr hRead = ctx.rcx;
        GuestAddr hWrite = ctx.rdx;
        if (hRead) mem.Write<u64>(hRead, ++s_eventHandleCounter);
        if (hWrite) mem.Write<u64>(hWrite, ++s_eventHandleCounter);
        return 1;
    });

    // SetHandleInformation
    kernel.RegisterHook("kernel32.dll", "SetHandleInformation", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    // WaitForSingleObject / WaitForMultipleObjects
    kernel.RegisterHook("kernel32.dll", "WaitForSingleObject", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; }); // WAIT_OBJECT_0
    kernel.RegisterHook("kernel32.dll", "WaitForSingleObjectEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "WaitForMultipleObjects", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // Semaphores
    kernel.RegisterHook("kernel32.dll", "CreateSemaphoreW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ++s_eventHandleCounter;
    });
    kernel.RegisterHook("kernel32.dll", "CreateSemaphoreExW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ++s_eventHandleCounter;
    });
    kernel.RegisterHook("kernel32.dll", "ReleaseSemaphore", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpPrev = ctx.r8;
        if (lpPrev) mem.Write<s32>(lpPrev, 1);
        return 1;
    });

    // System Information
    auto populateSysInfo = [](GuestAddr ptr, MemoryManager& mem) {
        if (!ptr) return;
        mem.Write<u16>(ptr + 0x00, 9); // PROCESSOR_ARCHITECTURE_AMD64
        mem.Write<u16>(ptr + 0x02, 0); // wReserved
        mem.Write<u32>(ptr + 0x04, 4096); // dwPageSize = 4KB
        mem.Write<u64>(ptr + 0x08, 0x10000); // lpMinimumApplicationAddress
        mem.Write<u64>(ptr + 0x10, 0x7FFFFFFEFFFF); // lpMaximumApplicationAddress
        mem.Write<u64>(ptr + 0x18, 0xFF); // dwActiveProcessorMask (8 cores)
        mem.Write<u32>(ptr + 0x20, 8); // dwNumberOfProcessors (Zen 2 8 cores)
        mem.Write<u32>(ptr + 0x24, 8664); // dwProcessorType (PROCESSOR_AMD_X8664)
        mem.Write<u32>(ptr + 0x28, 65536); // dwAllocationGranularity (64 KB)
        mem.Write<u16>(ptr + 0x2C, 23); // wProcessorLevel (Zen 2)
        mem.Write<u16>(ptr + 0x2E, 0x0001); // wProcessorRevision
    };
    kernel.RegisterHook("kernel32.dll", "GetNativeSystemInfo", [populateSysInfo](CpuContext& ctx, MemoryManager& mem) -> u64 {
        populateSysInfo(ctx.rcx, mem);
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "GetSystemInfo", [populateSysInfo](CpuContext& ctx, MemoryManager& mem) -> u64 {
        populateSysInfo(ctx.rcx, mem);
        return 0;
    });

    // Sleep
    kernel.RegisterHook("kernel32.dll", "Sleep", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "SleepEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "SwitchToThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetCurrentProcessorNumber", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
    kernel.RegisterHook("kernel32.dll", "VirtualFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1; // Success
    });

    // LocalFree(HLOCAL hMem)
    kernel.RegisterHook("kernel32.dll", "LocalFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0; // Success
    });

    // CommandLineToArgvW
    kernel.RegisterHook("shell32.dll", "CommandLineToArgvW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureGlobalBuffers(mem);
        GuestAddr pNumArgs = ctx.rdx;
        if (pNumArgs) {
            mem.Write<s32>(pNumArgs, 1);
        }
        static GuestAddr s_argvArray = 0;
        if (!s_argvArray) {
            s_argvArray = mem.Allocate(64, MemoryProtection::ReadWrite);
            mem.Write<u64>(s_argvArray, s_cmdLineW);
            mem.Write<u64>(s_argvArray + 8, 0);
        }
        return s_argvArray;
    });

    // GetFileAttributesW(LPCWSTR lpFileName)
    auto getFileAttributesHandler = [](const std::string& path) -> u32 {
        std::string resolved = ResolveGuestPath(path);
        struct stat st;
        if (stat(resolved.c_str(), &st) != 0) {
            s_lastErrorCode = 2; // ERROR_FILE_NOT_FOUND
            return 0xFFFFFFFF;   // INVALID_FILE_ATTRIBUTES
        }
        u32 attrs = 0;
        if (S_ISDIR(st.st_mode)) {
            attrs |= 0x10; // FILE_ATTRIBUTE_DIRECTORY
        } else {
            attrs |= 0x80; // FILE_ATTRIBUTE_NORMAL
        }
        return attrs;
    };

    kernel.RegisterHook("kernel32.dll", "GetFileAttributesW", [getFileAttributesHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string path = ReadGuestWideString(mem, ctx.rcx);
        return getFileAttributesHandler(path);
    });

    // GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
    kernel.RegisterHook("kernel32.dll", "GetFileAttributesExW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFileName = ctx.rcx;
        GuestAddr info = ctx.r8;

        std::string path = ReadGuestWideString(mem, lpFileName);
        std::string resolved = ResolveGuestPath(path);

        struct stat st;
        if (stat(resolved.c_str(), &st) != 0) {
            s_lastErrorCode = 2; // ERROR_FILE_NOT_FOUND
            return 0; // FALSE
        }

        if (info) {
            u32 attrs = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
            mem.Write<u32>(info + 0, attrs);
            mem.Write<u64>(info + 4, static_cast<u64>(st.st_ctime) * 10000000ULL + 116444736000000000ULL);
            mem.Write<u64>(info + 12, static_cast<u64>(st.st_atime) * 10000000ULL + 116444736000000000ULL);
            mem.Write<u64>(info + 20, static_cast<u64>(st.st_mtime) * 10000000ULL + 116444736000000000ULL);
            mem.Write<u32>(info + 28, static_cast<u32>(st.st_size >> 32));
            mem.Write<u32>(info + 32, static_cast<u32>(st.st_size & 0xFFFFFFFF));
        }
        return 1; // Success
    });

    // DuplicateHandle
    kernel.RegisterHook("kernel32.dll", "DuplicateHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpTargetHandle = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        if (lpTargetHandle) mem.Write<u64>(lpTargetHandle, ++s_eventHandleCounter);
        return 1;
    });

    // SetErrorMode
    kernel.RegisterHook("kernel32.dll", "SetErrorMode", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 mode = static_cast<u32>(ctx.rcx);
        LOG_INFO("Kernel32", "SetErrorMode(0x" + std::to_string(mode) + ")");
        return 0; // Return previous error mode
    });

    // CreateProcessW
    kernel.RegisterHook("kernel32.dll", "CreateProcessW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpApplicationName = ctx.rcx;
        GuestAddr lpCommandLine = ctx.rdx;
        GuestAddr lpStartupInfo = ctx.rsp ? mem.Read<u64>(ctx.rsp + 72) : 0;
        GuestAddr lpProcessInformation = ctx.rsp ? mem.Read<u64>(ctx.rsp + 80) : 0;

        std::wstring cmdLine;
        if (lpCommandLine) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(lpCommandLine + off)) != 0 && off < 512) {
                cmdLine += static_cast<wchar_t>(ch);
                off += 2;
            }
        }
        std::string cmdNarrow(cmdLine.begin(), cmdLine.end());
        LOG_INFO("Kernel32", "CreateProcessW: CommandLine='" + cmdNarrow + "'");

        if (lpProcessInformation) {
            u64 hProc = ++s_eventHandleCounter;
            u64 hThread = ++s_eventHandleCounter;
            mem.Write<u64>(lpProcessInformation + 0, hProc);       // hProcess
            mem.Write<u64>(lpProcessInformation + 8, hThread);     // hThread
            mem.Write<u32>(lpProcessInformation + 16, 2001);        // dwProcessId
            mem.Write<u32>(lpProcessInformation + 20, 2002);        // dwThreadId
        }

        return 1; // Success
    });

    // Thread management
    kernel.RegisterHook("kernel32.dll", "GetCurrentThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ~1ULL; });
    kernel.RegisterHook("kernel32.dll", "SetThreadPriority", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "CreateThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ++s_eventHandleCounter; });
    kernel.RegisterHook("kernel32.dll", "ResumeThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetThreadTimes", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rdx) mem.Write<u64>(ctx.rdx, 0); // CreationTime
        if (ctx.r8) mem.Write<u64>(ctx.r8, 0);   // ExitTime
        if (ctx.r9) mem.Write<u64>(ctx.r9, 0);   // KernelTime
        GuestAddr lpUserTime = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        if (lpUserTime) mem.Write<u64>(lpUserTime, 0);
        return 1;
    });

    // Pointer encoding / decoding
    kernel.RegisterHook("kernel32.dll", "EncodePointer", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ctx.rcx; });
    kernel.RegisterHook("kernel32.dll", "DecodePointer", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ctx.rcx; });

    // GetLogicalProcessorInformationEx
    kernel.RegisterHook("kernel32.dll", "GetLogicalProcessorInformationEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pBuffer = ctx.rdx;
        GuestAddr pReturnedLength = ctx.r8;
        u32 requiredSize = 256;
        if (pReturnedLength) {
            u32 providedSize = mem.Read<u32>(pReturnedLength);
            if (providedSize < requiredSize || !pBuffer) {
                mem.Write<u32>(pReturnedLength, requiredSize);
                s_lastErrorCode = 122; // ERROR_INSUFFICIENT_BUFFER
                return 0; // FALSE
            }
            mem.Write<u32>(pReturnedLength, requiredSize);
            // RelationProcessorCore = 0, Size = 256
            mem.Write<u32>(pBuffer + 0, 0);
            mem.Write<u32>(pBuffer + 4, requiredSize);
            return 1; // TRUE
        }
        return 0;
    });

    // FormatMessageW
    kernel.RegisterHook("kernel32.dll", "FormatMessageW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpBuffer = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        u32 nSize = ctx.rsp ? mem.Read<u32>(ctx.rsp + 48) : 0;
        u32 flags = static_cast<u32>(ctx.rcx);
        const char16_t* msg = u"The operation completed successfully.";
        size_t msgLen = std::char_traits<char16_t>::length(msg);
        if (flags & 0x00000100) { // FORMAT_MESSAGE_ALLOCATE_BUFFER
            GuestAddr buf = mem.Allocate((msgLen + 1) * 2, MemoryProtection::ReadWrite);
            for (size_t i = 0; i <= msgLen; i++) {
                mem.Write<u16>(buf + i * 2, static_cast<u16>(msg[i]));
            }
            if (lpBuffer) mem.Write<u64>(lpBuffer, buf);
            return msgLen;
        } else if (lpBuffer && nSize > 0) {
            size_t len = std::min<size_t>(nSize - 1, msgLen);
            for (size_t i = 0; i < len; i++) {
                mem.Write<u16>(lpBuffer + i * 2, static_cast<u16>(msg[i]));
            }
            mem.Write<u16>(lpBuffer + len * 2, 0);
            return len;
        }
        return 0;
    });

    // user32.dll: MessageBoxA / MessageBoxW
    kernel.RegisterHook("user32.dll", "MessageBoxA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpText = ctx.rdx;
        GuestAddr lpCaption = ctx.r8;
        std::string text, caption;
        if (lpText) {
            char ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<char>(lpText + off)) != 0 && off < 2048) {
                text += ch;
                off++;
            }
        }
        if (lpCaption) {
            char ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<char>(lpCaption + off)) != 0 && off < 256) {
                caption += ch;
                off++;
            }
        }
        LOG_INFO("User32", "MessageBoxA ['" + caption + "']: '" + text + "'");
        return 1; // IDOK
    });

    kernel.RegisterHook("user32.dll", "MessageBoxW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpText = ctx.rdx;
        GuestAddr lpCaption = ctx.r8;
        std::wstring text, caption;
        if (lpText) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(lpText + off)) != 0 && off < 4096) {
                text += static_cast<wchar_t>(ch);
                off += 2;
            }
        }
        if (lpCaption) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(lpCaption + off)) != 0 && off < 512) {
                caption += static_cast<wchar_t>(ch);
                off += 2;
            }
        }
        std::string nText(text.begin(), text.end());
        std::string nCap(caption.begin(), caption.end());
        LOG_INFO("User32", "MessageBoxW ['" + nCap + "']: '" + nText + "'");
        return 1; // IDOK
    });

    // bcrypt.dll
    kernel.RegisterHook("bcrypt.dll", "BCryptGenRandom", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pbBuffer = ctx.rdx;
        u32 cbBuffer = static_cast<u32>(ctx.r8);
        if (pbBuffer && cbBuffer > 0) {
            std::vector<u8> rnd(cbBuffer);
            arc4random_buf(rnd.data(), cbBuffer);
            mem.WriteBytes(pbBuffer, rnd.data(), cbBuffer);
        }
        return 0; // STATUS_SUCCESS
    });

    // ole32.dll
    kernel.RegisterHook("ole32.dll", "CoCreateInstance", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr ppv = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        if (ppv) {
            mem.Write<u64>(ppv, 0);
        }
        return 0x80040154; // REGDB_E_CLASSNOTREG
    });

    kernel.RegisterHook("ole32.dll", "CoInitialize", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ole32.dll", "CoInitializeEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ole32.dll", "CoUninitialize", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // oleaut32.dll: SysAllocStringLen (Ordinal 2), SysAllocString (Ordinal 4), SysFreeString (Ordinal 6), SysStringLen (Ordinal 7)
    auto sysAllocStringLenHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr strIn = ctx.rcx;
        u32 len = static_cast<u32>(ctx.rdx);
        u32 byteCount = len * 2;
        GuestAddr bstrMem = mem.Allocate(byteCount + 6, MemoryProtection::ReadWrite);
        mem.Write<u32>(bstrMem, byteCount);
        GuestAddr bstrStr = bstrMem + 4;
        if (strIn) {
            std::vector<u8> buf(byteCount);
            mem.ReadBytes(strIn, buf.data(), byteCount);
            mem.WriteBytes(bstrStr, buf.data(), byteCount);
        } else {
            std::vector<u8> zeroes(byteCount, 0);
            mem.WriteBytes(bstrStr, zeroes.data(), byteCount);
        }
        mem.Write<u16>(bstrStr + byteCount, 0); // null-terminator
        return bstrStr;
    };

    kernel.RegisterHook("oleaut32.dll", "Ordinal_2", sysAllocStringLenHandler);
    kernel.RegisterHook("oleaut32.dll", "SysAllocStringLen", sysAllocStringLenHandler);

    kernel.RegisterHook("oleaut32.dll", "Ordinal_6", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("oleaut32.dll", "SysFreeString", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    kernel.RegisterHook("oleaut32.dll", "Ordinal_7", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr bstr = ctx.rcx;
        if (!bstr) return 0;
        u32 byteCount = mem.Read<u32>(bstr - 4);
        return byteCount / 2;
    });
    kernel.RegisterHook("oleaut32.dll", "SysStringLen", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr bstr = ctx.rcx;
        if (!bstr) return 0;
        u32 byteCount = mem.Read<u32>(bstr - 4);
        return byteCount / 2;
    });

    // SRW Locks & Synchronization
    kernel.RegisterHook("kernel32.dll", "InitializeSRWLock", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rcx) mem.Write<u64>(ctx.rcx, 0);
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "AcquireSRWLockExclusive", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "ReleaseSRWLockExclusive", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "AcquireSRWLockShared", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "ReleaseSRWLockShared", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // Mutex
    kernel.RegisterHook("kernel32.dll", "CreateMutexW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ++s_eventHandleCounter;
    });
    kernel.RegisterHook("kernel32.dll", "CreateMutexA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ++s_eventHandleCounter;
    });

    // RtlPcToFileHeader
    kernel.RegisterHook("kernel32.dll", "RtlPcToFileHeader", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pc = ctx.rcx;
        GuestAddr pBase = ctx.rdx;
        if (s_peLoader) {
            for (const auto& mod : s_peLoader->GetLoadedModules()) {
                if (pc >= mod.imageBase && pc < mod.imageBase + mod.sizeOfImage) {
                    if (pBase) mem.Write<u64>(pBase, mod.imageBase);
                    return mod.imageBase;
                }
            }
        }
        if (pBase) mem.Write<u64>(pBase, 0x140000000ULL);
        return 0x140000000ULL;
    });

    // Directory & Environment
    kernel.RegisterHook("kernel32.dll", "GetCurrentDirectoryA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 len = static_cast<u32>(ctx.rcx);
        GuestAddr buf = ctx.rdx;
        const char* path = "C:\\Game";
        size_t pLen = strlen(path);
        if (buf && len > pLen) {
            mem.WriteBytes(buf, path, pLen + 1);
            return pLen;
        }
        return pLen + 1;
    });

    kernel.RegisterHook("kernel32.dll", "GetEnvironmentVariableA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        s_lastErrorCode = 203; // ERROR_ENVVAR_NOT_FOUND
        return 0;
    });

    kernel.RegisterHook("kernel32.dll", "GetFileAttributesA", [getFileAttributesHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string path = ReadGuestAnsiString(mem, ctx.rcx);
        return getFileAttributesHandler(path);
    });

    kernel.RegisterHook("kernel32.dll", "GetModuleFileNameA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr buf = ctx.rdx;
        u32 size = static_cast<u32>(ctx.r8);
        const char* name = "The Mortuary Assistant.exe";
        size_t len = strlen(name);
        if (buf && size > len) {
            mem.WriteBytes(buf, name, len + 1);
            return len;
        }
        return 0;
    });

    // ADVAPI32
    kernel.RegisterHook("advapi32.dll", "GetUserNameA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr buf = ctx.rcx;
        GuestAddr pSize = ctx.rdx;
        const char* user = "Player";
        size_t len = strlen(user);
        if (buf) mem.WriteBytes(buf, user, len + 1);
        if (pSize) mem.Write<u32>(pSize, static_cast<u32>(len + 1));
        return 1;
    });

    // VERSION.dll
    auto verSizeHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pHandle = ctx.rdx;
        if (pHandle) mem.Write<u32>(pHandle, 0);
        return 512; // Dummy version block size
    };
    kernel.RegisterHook("version.dll", "GetFileVersionInfoSizeA", verSizeHandler);
    kernel.RegisterHook("version.dll", "GetFileVersionInfoSizeW", verSizeHandler);

    auto verInfoHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pData = ctx.r9;
        u32 len = static_cast<u32>(ctx.r8);
        if (pData && len > 0) {
            std::vector<u8> dummy(len, 0);
            mem.WriteBytes(pData, dummy.data(), len);
        }
        return 1; // Success
    };
    kernel.RegisterHook("version.dll", "GetFileVersionInfoA", verInfoHandler);
    kernel.RegisterHook("version.dll", "GetFileVersionInfoW", verInfoHandler);

    auto verQueryHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lplpBuffer = ctx.r8;
        GuestAddr puLen = ctx.r9;
        static GuestAddr s_dummyVerBuf = 0;
        if (!s_dummyVerBuf) {
            s_dummyVerBuf = mem.Allocate(128, MemoryProtection::ReadWrite);
            // VS_FIXEDFILEINFO: dwSignature (0xFEEF04BD)
            mem.Write<u32>(s_dummyVerBuf + 0, 0xFEEF04BD);
            mem.Write<u32>(s_dummyVerBuf + 4, 0x00010000); // dwStrucVersion
            mem.Write<u32>(s_dummyVerBuf + 8, 0x000A0000); // FileVersionMS (10.0)
            mem.Write<u32>(s_dummyVerBuf + 12, 0x00000000); // FileVersionLS
        }
        if (lplpBuffer) mem.Write<u64>(lplpBuffer, s_dummyVerBuf);
        if (puLen) mem.Write<u32>(puLen, 52); // sizeof(VS_FIXEDFILEINFO)
        return 1; // Success
    };
    kernel.RegisterHook("version.dll", "VerQueryValueA", verQueryHandler);
    kernel.RegisterHook("version.dll", "VerQueryValueW", verQueryHandler);

    // Window Management & Message Loop
    auto regClassHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xC001; };
    kernel.RegisterHook("user32.dll", "RegisterClassExW", regClassHandler);
    kernel.RegisterHook("user32.dll", "RegisterClassExA", regClassHandler);
    kernel.RegisterHook("user32.dll", "RegisterClassW", regClassHandler);
    kernel.RegisterHook("user32.dll", "RegisterClassA", regClassHandler);

    auto createWindowHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hWnd = ++s_eventHandleCounter;
        LOG_INFO("User32", "CreateWindowEx called -> HWND=0x" + std::to_string(hWnd));
        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->CreateWindowAndPipeline();
            renderer->RenderFrame();
            renderer->PollEvents();
        }
        return hWnd;
    };
    kernel.RegisterHook("user32.dll", "CreateWindowExW", createWindowHandler);
    kernel.RegisterHook("user32.dll", "CreateWindowExA", createWindowHandler);

    kernel.RegisterHook("user32.dll", "ShowWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "UpdateWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "SetWindowPos", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "MoveWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "DestroyWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "AdjustWindowRectEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "AdjustWindowRect", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    auto getRectHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpRect = ctx.rdx;
        if (lpRect) {
            mem.Write<s32>(lpRect + 0, 0);    // left
            mem.Write<s32>(lpRect + 4, 0);    // top
            mem.Write<s32>(lpRect + 8, 1920); // right
            mem.Write<s32>(lpRect + 12, 1080);// bottom
        }
        return 1;
    };
    kernel.RegisterHook("user32.dll", "GetClientRect", getRectHandler);
    kernel.RegisterHook("user32.dll", "GetWindowRect", getRectHandler);

    kernel.RegisterHook("user32.dll", "SetWindowLongPtrW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "SetWindowLongPtrA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "GetWindowLongPtrW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "GetWindowLongPtrA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "DefWindowProcW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "DefWindowProcA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    auto peekMessageHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->PollEvents();
        }
        return 0;
    };
    kernel.RegisterHook("user32.dll", "PeekMessageW", peekMessageHandler);
    kernel.RegisterHook("user32.dll", "PeekMessageA", peekMessageHandler);
    kernel.RegisterHook("user32.dll", "GetMessageW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "GetMessageA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "DispatchMessageW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "DispatchMessageA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("user32.dll", "TranslateMessage", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    kernel.RegisterHook("user32.dll", "GetSystemMetrics", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 idx = static_cast<u32>(ctx.rcx);
        if (idx == 0) return 1920; // SM_CXSCREEN
        if (idx == 1) return 1080; // SM_CYSCREEN
        return 0;
    });

    kernel.RegisterHook("user32.dll", "GetDC", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xDC001; });
    kernel.RegisterHook("user32.dll", "ReleaseDC", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "SetCursor", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xCC001; });
    kernel.RegisterHook("user32.dll", "LoadCursorW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xCC001; });
    kernel.RegisterHook("user32.dll", "LoadCursorA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xCC001; });
    kernel.RegisterHook("user32.dll", "SetWindowTextW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "SetWindowTextA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
}

} // namespace Scarlett::Modules
