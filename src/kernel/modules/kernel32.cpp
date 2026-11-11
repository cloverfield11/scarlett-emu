#include "kernel/modules/kernel32.h"
#include "loader/pe_loader.h"
#include "cpu/interpreter.h"
#include "cpu/teb.h"
#include "common/logging.h"
#include <chrono>
#include <mach/mach_time.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fnmatch.h>
#include <algorithm>
#include "gpu/metal_renderer.h"

namespace Scarlett::Modules {

static PeLoader* s_peLoader = nullptr;
static HleKernel* s_hleKernel = nullptr;
static bool s_processExited = false;
static u32 s_processExitCode = 0;

void SetPeLoader(PeLoader* loader) {
    s_peLoader = loader;
}

static std::string s_gameRootDir = "The Mortuary Assistant";
static std::string s_currentWinDir = "C:\\Game";
static const std::string s_vfsSandboxRoot = "/tmp/scarlett_vfs";

void SetGameRootDir(const std::string& path) {
    s_gameRootDir = path;
}

bool HasProcessExited() {
    return s_processExited;
}

u32 GetProcessExitCode() {
    return s_processExitCode;
}

enum class SyncKind { Event, Semaphore, Mutex };
struct SyncObject {
    SyncKind kind{SyncKind::Event};
    bool manualReset{false};
    bool signaled{false};
    s32 count{0};
    s32 maxCount{1};
    u32 ownerTid{0};
    u32 recursion{0};
};

static u64 s_handleCounter = 0x200;
static u64& s_eventHandleCounter = s_handleCounter;
static std::vector<GuestThread> s_threads;
static size_t s_activeThreadIdx = 0;
static u32 s_nextThreadId = 1002;
static u64 s_schedulerRound = 0;
static u64 s_virtualMsOffset = 0;
static u64 s_syncSignalEpoch = 1;
static std::unordered_map<u64, SyncObject> s_syncObjects;
struct CriticalSectionState {
    u32 ownerTid{0};
    u32 recursion{0};
};
struct SrwLockState {
    u32 exclusiveOwnerTid{0};
    u32 sharedCount{0};
};
static std::unordered_map<GuestAddr, CriticalSectionState> s_criticalSections;
static std::unordered_map<GuestAddr, SrwLockState> s_srwLocks;
static GuestAddr s_threadExitTrampoline = 0;
static GuestAddr s_mainTebAddr = 0;

u64 GetSyncSignalEpoch() {
    return s_syncSignalEpoch;
}

u64 GetCurrentSyncMs() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<u64>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count()) + s_virtualMsOffset;
}

void AdvanceSchedulerRound(bool allBlocked) {
    s_schedulerRound++;
    if (allBlocked) {
        u64 now = GetCurrentSyncMs();
        u64 minFiniteDeadline = UINT64_MAX;
        for (const auto& t : s_threads) {
            if (t.exited || t.suspended || !t.waiting) continue;
            if (t.waitIsSleep || !t.waitInfinite) {
                if (t.waitDeadlineMs < minFiniteDeadline) {
                    minFiniteDeadline = t.waitDeadlineMs;
                }
            }
        }
        if (minFiniteDeadline != UINT64_MAX) {
            // Jump directly to the earliest finite sleep/timeout without waking INFINITE waiters
            s_virtualMsOffset += (minFiniteDeadline > now) ? (minFiniteDeadline - now) : 1;
        } else {
            // All alive threads are INFINITE-blocked; break potential deadlock
            s_virtualMsOffset += 16;
            s_syncSignalEpoch++;
        }
    }
}

u64 GetSchedulerRound() {
    return s_schedulerRound;
}

u32 GetCurrentGuestThreadId() {
    if (s_activeThreadIdx < s_threads.size()) {
        return s_threads[s_activeThreadIdx].threadId;
    }
    return 1001;
}

void InitMainThread(const CpuContext& mainCtx, MemoryManager& mem) {
    s_activeThreadIdx = 0;
    s_mainTebAddr = mainCtx.gsBase;
    if (s_hleKernel) {
        s_threadExitTrampoline = s_hleKernel->GetOrCreateHookTrampoline("kernel32.dll", "ExitThread");
    }
    if (s_threads.empty()) {
        GuestThread mainT{};
        mainT.handle = ++s_handleCounter;
        mainT.threadId = 1001;
        mainT.ctx = mainCtx;
        mainT.stackBase = GUEST_MEMORY_BASE;
        mainT.stackTop = GUEST_MEMORY_BASE + 0x800000;
        mainT.isMain = true;
        s_threads.push_back(mainT);
    } else {
        s_threads[0].ctx = mainCtx;
        s_threads[0].stackBase = GUEST_MEMORY_BASE;
        s_threads[0].stackTop = GUEST_MEMORY_BASE + 0x800000;
        s_threads[0].exited = false;
        s_threads[0].suspended = false;
        s_threads[0].waiting = false;
    }
}

size_t GetActiveThreadIndex() {
    return s_activeThreadIdx;
}

std::vector<GuestThread>& GetThreads() {
    return s_threads;
}

void SaveActiveThreadContext(const CpuContext& srcCtx) {
    if (s_activeThreadIdx < s_threads.size()) {
        s_threads[s_activeThreadIdx].ctx = srcCtx;
    }
}

void SwitchToThreadIndex(size_t idx, CpuContext& dstCtx) {
    if (idx < s_threads.size()) {
        s_activeThreadIdx = idx;
        dstCtx = s_threads[idx].ctx;
    }
}

static GuestThread* FindThreadByHandle(u64 handle) {
    for (auto& t : s_threads) {
        if (t.handle == handle) return &t;
    }
    return nullptr;
}

static bool HasOtherActiveThreads() {
    for (size_t i = 0; i < s_threads.size(); ++i) {
        if (i != s_activeThreadIdx && !s_threads[i].exited && !s_threads[i].suspended) {
            return true;
        }
    }
    return false;
}

static bool IsGuestThreadAlive(u32 tid) {
    if (tid == 0) return false;
    for (const auto& t : s_threads) {
        if (t.threadId == tid && !t.exited) return true;
    }
    return false;
}

static void BlockActiveThreadUntilEpoch() {
    if (s_threads.empty() || s_activeThreadIdx >= s_threads.size()) return;
    GuestThread& cur = s_threads[s_activeThreadIdx];
    cur.waiting = true;
    cur.waitIsSleep = false;
    cur.waitingCondVar = false;
    cur.waitStartRound = s_schedulerRound;
    cur.waitObservedEpoch = s_syncSignalEpoch;
    cur.waitInfinite = true;
    cur.waitDeadlineMs = ~0ULL;
    if (s_hleKernel) s_hleKernel->RequestYield(true);
}

static bool TryAcquireCriticalSection(GuestAddr csAddr, u32 tid) {
    if (!csAddr) return true;
    CriticalSectionState& cs = s_criticalSections[csAddr];
    if (cs.ownerTid != 0 && cs.ownerTid != tid && IsGuestThreadAlive(cs.ownerTid) && HasOtherActiveThreads()) {
        return false;
    }
    if (cs.ownerTid == tid) {
        cs.recursion++;
    } else {
        cs.ownerTid = tid;
        cs.recursion = 1;
    }
    return true;
}

static void ReleaseCriticalSection(GuestAddr csAddr, u32 tid) {
    if (!csAddr) return;
    auto it = s_criticalSections.find(csAddr);
    if (it == s_criticalSections.end()) return;
    CriticalSectionState& cs = it->second;
    if (cs.ownerTid == tid && cs.recursion > 0) {
        cs.recursion--;
        if (cs.recursion == 0) {
            cs.ownerTid = 0;
            s_syncSignalEpoch++;
        }
    }
}

static bool TryAcquireSrwLock(GuestAddr lockAddr, u32 tid, bool shared) {
    if (!lockAddr) return true;
    SrwLockState& st = s_srwLocks[lockAddr];
    if (shared) {
        if (st.exclusiveOwnerTid != 0 && IsGuestThreadAlive(st.exclusiveOwnerTid) && HasOtherActiveThreads()) {
            return false;
        }
        if (st.exclusiveOwnerTid != 0 && !IsGuestThreadAlive(st.exclusiveOwnerTid)) {
            st.exclusiveOwnerTid = 0;
        }
        st.sharedCount++;
        return true;
    }
    if (((st.exclusiveOwnerTid != 0 && IsGuestThreadAlive(st.exclusiveOwnerTid)) || st.sharedCount > 0) && HasOtherActiveThreads()) {
        return false;
    }
    st.exclusiveOwnerTid = tid;
    st.sharedCount = 0;
    return true;
}

static void ReleaseSrwLock(GuestAddr lockAddr, u32 tid, bool shared) {
    if (!lockAddr) return;
    auto it = s_srwLocks.find(lockAddr);
    if (it == s_srwLocks.end()) return;
    SrwLockState& st = it->second;
    if (shared) {
        if (st.sharedCount > 0) {
            st.sharedCount--;
            if (st.sharedCount == 0 && st.exclusiveOwnerTid == 0) {
                s_syncSignalEpoch++;
            }
        }
    } else if (st.exclusiveOwnerTid == tid) {
        st.exclusiveOwnerTid = 0;
        s_syncSignalEpoch++;
    }
}

static bool IsHandleSignaled(u64 handle, u32 curTid) {
    if (GuestThread* t = FindThreadByHandle(handle)) {
        return t->exited;
    }
    auto it = s_syncObjects.find(handle);
    if (it == s_syncObjects.end()) {
        return true; // Non-sync/unknown handles succeed immediately
    }
    const SyncObject& obj = it->second;
    if (obj.kind == SyncKind::Event) return obj.signaled;
    if (obj.kind == SyncKind::Semaphore) return obj.count > 0;
    if (obj.kind == SyncKind::Mutex) return obj.ownerTid == 0 || obj.ownerTid == curTid;
    return true;
}

static void ConsumeHandleSignal(u64 handle, u32 curTid) {
    auto it = s_syncObjects.find(handle);
    if (it == s_syncObjects.end()) return;
    SyncObject& obj = it->second;
    if (obj.kind == SyncKind::Event) {
        if (!obj.manualReset) obj.signaled = false;
    } else if (obj.kind == SyncKind::Semaphore) {
        if (obj.count > 0) obj.count--;
    } else if (obj.kind == SyncKind::Mutex) {
        obj.ownerTid = curTid;
        obj.recursion++;
    }
}

static std::string ToLowerAscii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static void EnsureDirectoryRecursive(const std::string& dirPath) {
    if (dirPath.empty()) return;
    std::string cur;
    if (dirPath[0] == '/') cur = "/";
    size_t pos = (dirPath[0] == '/') ? 1 : 0;
    while (pos <= dirPath.size()) {
        size_t next = dirPath.find('/', pos);
        std::string part = (next == std::string::npos) ? dirPath.substr(pos) : dirPath.substr(pos, next - pos);
        if (!part.empty()) {
            if (!cur.empty() && cur.back() != '/') cur += '/';
            cur += part;
            mkdir(cur.c_str(), 0755);
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
}

static std::string GetGuestExeName() {
    if (s_peLoader) {
        for (const auto& mod : s_peLoader->GetLoadedModules()) {
            if (mod.imageBase == 0x140000000ULL) {
                return mod.name;
            }
        }
        const auto& mods = s_peLoader->GetLoadedModules();
        if (!mods.empty()) {
            return mods.back().name;
        }
    }
    return "The Mortuary Assistant.exe";
}

static std::string GetModuleWinPath(u64 hModule) {
    if (s_peLoader) {
        for (const auto& mod : s_peLoader->GetLoadedModules()) {
            if ((hModule == 0 && mod.imageBase == 0x140000000ULL) || mod.imageBase == hModule) {
                return "C:\\Game\\" + mod.name;
            }
        }
    }
    return "C:\\Game\\" + GetGuestExeName();
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

    std::string lower = ToLowerAscii(path);

    // Map virtual Windows User/Temp/ProgramData folders to writable macOS sandbox
    auto mapToSandbox = [&](const std::string& rel) -> std::string {
        std::string mapped = s_vfsSandboxRoot + "/" + rel;
        size_t slash = mapped.find_last_of('/');
        if (slash != std::string::npos) {
            EnsureDirectoryRecursive(mapped.substr(0, slash));
        }
        return mapped;
    };

    if (lower.rfind("c:/users/", 0) == 0 || lower.rfind("c:/temp", 0) == 0 || lower.rfind("c:/programdata", 0) == 0) {
        return mapToSandbox(path.substr(3));
    }
    if (lower.rfind("users/", 0) == 0 || lower.rfind("temp", 0) == 0) {
        return mapToSandbox(path);
    }

    // Map C:/Game or C:/Game/... cleanly to s_gameRootDir
    if (lower == "c:/game" || lower == "c:/game/" || lower == "game" || lower == "game/") {
        return s_gameRootDir.empty() ? "." : s_gameRootDir;
    }
    if (lower.rfind("c:/game/", 0) == 0) {
        path = path.substr(8);
    } else if (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':' && path[2] == '/') {
        // Strip other drive letters (e.g. "C:/", "D:/")
        path = path.substr(3);
    }

    // Remove redundant leading slashes or "./"
    while (!path.empty() && path.front() == '/') path.erase(path.begin());
    if (path.rfind("./", 0) == 0) path = path.substr(2);
    if (ToLowerAscii(path).rfind("game/", 0) == 0) path = path.substr(5);

    if (path.empty() || path == ".") {
        return s_gameRootDir.empty() ? "." : s_gameRootDir;
    }

    // 1. Relative to game root (priority for game assets)
    std::string candidate = s_gameRootDir.empty() ? path : (s_gameRootDir + "/" + path);
    if (access(candidate.c_str(), F_OK) == 0) {
        return candidate;
    }

    // 2. Direct candidate
    if (access(path.c_str(), F_OK) == 0) {
        return path;
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

struct VfsMapping {
    u64 fileHandle{~0ULL};
    u64 size{0};
};
static std::unordered_map<u64, VfsMapping> s_vfsMappings;
static u64 s_nextMappingHandle = 0x7000;

static std::vector<u16> Utf8ToUtf16(const std::string& utf8) {
    std::vector<u16> out;
    size_t i = 0;
    while (i < utf8.size()) {
        u8 c = static_cast<u8>(utf8[i]);
        u32 cp = 0;
        if (c < 0x80) {
            cp = c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < utf8.size()) {
            cp = ((c & 0x1F) << 6) | (static_cast<u8>(utf8[i + 1]) & 0x3F);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < utf8.size()) {
            cp = ((c & 0x0F) << 12) |
                 ((static_cast<u8>(utf8[i + 1]) & 0x3F) << 6) |
                 (static_cast<u8>(utf8[i + 2]) & 0x3F);
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < utf8.size()) {
            cp = ((c & 0x07) << 18) |
                 ((static_cast<u8>(utf8[i + 1]) & 0x3F) << 12) |
                 ((static_cast<u8>(utf8[i + 2]) & 0x3F) << 6) |
                 (static_cast<u8>(utf8[i + 3]) & 0x3F);
            i += 4;
        } else {
            cp = c;
            i += 1;
        }
        if (cp <= 0xFFFF) {
            out.push_back(static_cast<u16>(cp));
        } else {
            cp -= 0x10000;
            out.push_back(static_cast<u16>(0xD800 | (cp >> 10)));
            out.push_back(static_cast<u16>(0xDC00 | (cp & 0x3FF)));
        }
    }
    return out;
}

static std::string Utf16ToUtf8(const std::vector<u16>& utf16) {
    std::string out;
    size_t i = 0;
    while (i < utf16.size()) {
        u32 cp = utf16[i++];
        if (cp >= 0xD800 && cp <= 0xDBFF && i < utf16.size()) {
            u32 low = utf16[i];
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                i++;
            }
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

static void WriteGuestWideString(MemoryManager& mem, GuestAddr addr, const std::string& str) {
    if (!addr) return;
    std::vector<u16> u16s = Utf8ToUtf16(str);
    for (size_t i = 0; i < u16s.size(); ++i) {
        mem.Write<u16>(addr + i * 2, u16s[i]);
    }
    mem.Write<u16>(addr + u16s.size() * 2, 0);
}

static std::string ReadGuestWideString(MemoryManager& mem, GuestAddr addr, size_t maxLen = 1024) {
    std::vector<u16> u16s;
    if (addr) {
        u16 ch = 0;
        size_t off = 0;
        while ((ch = mem.Read<u16>(addr + off)) != 0 && (off / 2) < maxLen) {
            u16s.push_back(ch);
            off += 2;
        }
    }
    return Utf16ToUtf8(u16s);
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

    std::string cmd = "\"" + GetModuleWinPath(0) + "\"";
    mem.WriteBytes(s_cmdLineA, cmd.c_str(), cmd.size() + 1);
    WriteGuestWideString(mem, s_cmdLineW, cmd);

    const char16_t* env = u"PATH=C:\\Game\0";
    for (size_t i = 0; i < 14; ++i) {
        mem.Write<u16>(s_envW + i * 2, static_cast<u16>(env[i]));
    }
}

void RegisterKernel32(HleKernel& kernel) {
    s_hleKernel = &kernel;
    s_processExited = false;
    s_processExitCode = 0;
    EnsureDirectoryRecursive(s_vfsSandboxRoot + "/Users/Player/AppData/LocalLow");
    EnsureDirectoryRecursive(s_vfsSandboxRoot + "/Temp");

    // ExitProcess(UINT uExitCode)
    kernel.RegisterHook("kernel32.dll", "ExitProcess", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 exitCode = static_cast<u32>(ctx.rcx);
        std::stringstream ss;
        ss << "Game requested ExitProcess with code: " << exitCode << " | Stack trace return candidates:";
        for (u64 off = 0; off < 0x400; off += 8) {
            u64 val = mem.Read<u64>(ctx.rsp + off);
            if ((val >= 0x140000000ULL && val < 0x240000000ULL)) {
                ss << " 0x" << std::hex << val;
            }
        }
        LOG_INFO("Kernel32", ss.str());
        s_processExited = true;
        s_processExitCode = exitCode;
        return 0;
    });

    // TerminateProcess(HANDLE hProcess, UINT uExitCode)
    kernel.RegisterHook("kernel32.dll", "TerminateProcess", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hProcess = ctx.rcx;
        u32 exitCode = static_cast<u32>(ctx.rdx);
        LOG_INFO("Kernel32", "TerminateProcess called with code: " + std::to_string(exitCode));
        if (hProcess == ~0ULL || hProcess == static_cast<u64>(getpid())) {
            s_processExited = true;
            s_processExitCode = exitCode;
        }
        return 1;
    });

    // GetCurrentProcessId()
    kernel.RegisterHook("kernel32.dll", "GetCurrentProcessId", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return static_cast<u64>(getpid());
    });

    // GetCurrentThreadId()
    kernel.RegisterHook("kernel32.dll", "GetCurrentThreadId", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return GetCurrentGuestThreadId();
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
        u32 flAllocType = static_cast<u32>(ctx.r8);
        u32 flProtect = static_cast<u32>(ctx.r9);
        if (size == 0) {
            s_lastErrorCode = 87; // ERROR_INVALID_PARAMETER
            return 0;
        }

        auto logHuge = [&](GuestAddr res) {
            if (size >= 0x10000000ULL) {
                GuestAddr retRip = ctx.rsp ? mem.Read<u64>(ctx.rsp) : 0;
                std::stringstream ss;
                ss << "VirtualAlloc(lp=0x" << std::hex << preferredBase
                   << ", size=0x" << size
                   << ", type=0x" << flAllocType
                   << ", prot=0x" << flProtect
                   << ", ret=0x" << retRip << ") -> 0x" << res;
                LOG_INFO("Kernel32", ss.str());
            }
        };

        // MEM_RESET / MEM_RESET_UNDO
        if ((flAllocType & 0x01080000U) && preferredBase != 0) {
            return preferredBase & ~0xFFFULL;
        }

        // Pure MEM_COMMIT on an already reserved guest address range
        if ((flAllocType & 0x1000U) && !(flAllocType & 0x2000U) && preferredBase != 0) {
            GuestAddr pageBase = preferredBase & ~0xFFFULL;
            if (pageBase >= GUEST_MEMORY_BASE && mem.Translate(pageBase) != nullptr &&
                size <= GUEST_MEMORY_SIZE && pageBase <= (GUEST_MEMORY_SIZE - size)) {
                logHuge(pageBase);
                return pageBase;
            }
            s_lastErrorCode = 487; // ERROR_INVALID_ADDRESS
            logHuge(0);
            return 0;
        }

        GuestAddr allocated = mem.Allocate(size, MemoryProtection::ReadWrite, preferredBase);
        if (allocated == 0) {
            s_lastErrorCode = 8; // ERROR_NOT_ENOUGH_MEMORY
        }
        logHuge(allocated);
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

    auto getModuleHandleHandler = [](const std::string& rawName) -> u64 {
        if (rawName.empty()) {
            return 0x140000000ULL;
        }

        std::string name = rawName;
        size_t lastSlash = name.find_last_of("/\\");
        if (lastSlash != std::string::npos) name = name.substr(lastSlash + 1);

        if (s_peLoader) {
            for (const auto& mod : s_peLoader->GetLoadedModules()) {
                std::string modLower = mod.name;
                std::string targetLower = name;
                std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);
                std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::tolower);
                if (modLower == targetLower) {
                    return mod.imageBase;
                }
            }
        }

        return 0x170000000ULL + (std::hash<std::string>{}(ToLowerAscii(name)) & 0x00FFFFFFULL);
    };

    // GetModuleHandleW(LPCWSTR lpModuleName)
    kernel.RegisterHook("kernel32.dll", "GetModuleHandleW", [getModuleHandleHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (!ctx.rcx) return 0x140000000ULL;
        std::string name = ReadGuestWideString(mem, ctx.rcx);
        return getModuleHandleHandler(name);
    });

    kernel.RegisterHook("kernel32.dll", "GetModuleHandleA", [getModuleHandleHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (!ctx.rcx) return 0x140000000ULL;
        std::string name = ReadGuestAnsiString(mem, ctx.rcx);
        return getModuleHandleHandler(name);
    });

    // GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)
    kernel.RegisterHook("kernel32.dll", "GetModuleHandleExW", [getModuleHandleHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 dwFlags = static_cast<u32>(ctx.rcx);
        GuestAddr lpModuleName = ctx.rdx;
        GuestAddr phModule = ctx.r8;

        u64 handle = 0;
        if (dwFlags & 0x00000004) { // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            if (s_peLoader) {
                for (const auto& mod : s_peLoader->GetLoadedModules()) {
                    if (lpModuleName >= mod.imageBase && lpModuleName < (mod.imageBase + mod.sizeOfImage)) {
                        handle = mod.imageBase;
                        break;
                    }
                }
            }
            if (!handle) handle = 0x180000000ULL;
        } else if (!lpModuleName) {
            handle = 0x140000000ULL;
        } else {
            std::string name = ReadGuestWideString(mem, lpModuleName);
            handle = getModuleHandleHandler(name);
        }

        if (phModule) {
            mem.Write<u64>(phModule, handle);
        }
        return 1;
    });

    // GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
    kernel.RegisterHook("kernel32.dll", "GetModuleFileNameW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hModule = ctx.rcx;
        GuestAddr outBuf = ctx.rdx;
        u32 maxLen = static_cast<u32>(ctx.r8);
        std::string fullPath = GetModuleWinPath(hModule);
        std::vector<u16> u16s = Utf8ToUtf16(fullPath);
        u32 len = static_cast<u32>(u16s.size());
        if (!outBuf || maxLen == 0) {
            s_lastErrorCode = 122; // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }
        u32 copyLen = std::min<u32>(len, maxLen - 1);
        for (u32 i = 0; i < copyLen; ++i) mem.Write<u16>(outBuf + i * 2, u16s[i]);
        mem.Write<u16>(outBuf + copyLen * 2, 0);
        if (maxLen <= len) {
            s_lastErrorCode = 122;
            return maxLen;
        }
        s_lastErrorCode = 0;
        return len;
    });

    // GetProcessHeap()
    kernel.RegisterHook("kernel32.dll", "GetProcessHeap", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0x170000000; // Default heap handle
    });

    // HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
    static GuestAddr s_heapCurrent = 0x240000000ULL;
    static std::unordered_map<GuestAddr, u64> s_heapSizes;
    kernel.RegisterHook("kernel32.dll", "HeapAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 flags = static_cast<u32>(ctx.rdx);
        u64 size = ctx.r8;
        if (size == 0) size = 16;
        u64 alignedSize = (size + 15) & ~15ULL; // 16-byte alignment
        if (s_heapCurrent + alignedSize > GUEST_MEMORY_SIZE) {
            s_lastErrorCode = 8; // ERROR_NOT_ENOUGH_MEMORY
            return 0;
        }
        GuestAddr ptr = s_heapCurrent;
        s_heapCurrent += alignedSize;
        s_heapSizes[ptr] = size;
        if (flags & 0x00000008U) { // HEAP_ZERO_MEMORY
            if (void* host = mem.Translate(ptr)) {
                std::memset(host, 0, size);
            }
        }
        return ptr;
    });

    // HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
    kernel.RegisterHook("kernel32.dll", "HeapFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.r8) s_heapSizes.erase(ctx.r8);
        return 1;
    });

    // HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
    kernel.RegisterHook("kernel32.dll", "HeapReAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 flags = static_cast<u32>(ctx.rdx);
        GuestAddr oldMem = ctx.r8;
        u64 size = ctx.r9;
        if (size == 0) size = 16;
        u64 alignedSize = (size + 15) & ~15ULL;
        if (s_heapCurrent + alignedSize > GUEST_MEMORY_SIZE) {
            s_lastErrorCode = 8;
            return 0;
        }
        GuestAddr newMem = s_heapCurrent;
        s_heapCurrent += alignedSize;
        u64 oldSize = size;
        if (oldMem) {
            auto it = s_heapSizes.find(oldMem);
            if (it != s_heapSizes.end()) oldSize = it->second;
            u64 copyLen = std::min(oldSize, size);
            if (void* dst = mem.Translate(newMem)) {
                if (void* src = mem.Translate(oldMem)) {
                    std::memcpy(dst, src, copyLen);
                }
            }
            if ((flags & 0x00000008U) && size > copyLen) {
                if (void* dst = mem.Translate(newMem + copyLen)) {
                    std::memset(dst, 0, size - copyLen);
                }
            }
            s_heapSizes.erase(oldMem);
        } else if (flags & 0x00000008U) {
            if (void* dst = mem.Translate(newMem)) std::memset(dst, 0, size);
        }
        s_heapSizes[newMem] = size;
        return newMem;
    });

    // HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
    kernel.RegisterHook("kernel32.dll", "HeapSize", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpMem = ctx.r8;
        auto it = s_heapSizes.find(lpMem);
        if (it != s_heapSizes.end()) return it->second;
        return 0x1000;
    });

    // InitializeCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "InitializeCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr cs = ctx.rcx;
        if (cs) {
            for (u32 i = 0; i < 40; i += 8) mem.Write<u64>(cs + i, 0);
            s_criticalSections[cs] = CriticalSectionState{};
        }
        return 0;
    });

    // InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCritSection, DWORD dwSpinCount)
    kernel.RegisterHook("kernel32.dll", "InitializeCriticalSectionAndSpinCount", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr cs = ctx.rcx;
        if (cs) {
            for (u32 i = 0; i < 40; i += 8) mem.Write<u64>(cs + i, 0);
            s_criticalSections[cs] = CriticalSectionState{};
        }
        return 1;
    });

    // EnterCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "EnterCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 curTid = GetCurrentGuestThreadId();
        if (TryAcquireCriticalSection(ctx.rcx, curTid)) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                s_threads[s_activeThreadIdx].waiting = false;
            }
            return 0;
        }
        BlockActiveThreadUntilEpoch();
        return 0;
    });

    // LeaveCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "LeaveCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        ReleaseCriticalSection(ctx.rcx, GetCurrentGuestThreadId());
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "TryEnterCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return TryAcquireCriticalSection(ctx.rcx, GetCurrentGuestThreadId()) ? 1 : 0;
    });

    // DeleteCriticalSection(LPCRITICAL_SECTION lpCritSection)
    kernel.RegisterHook("kernel32.dll", "DeleteCriticalSection", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rcx) {
            auto it = s_criticalSections.find(ctx.rcx);
            if (it != s_criticalSections.end()) {
                bool wasOwned = (it->second.ownerTid != 0);
                s_criticalSections.erase(it);
                if (wasOwned) s_syncSignalEpoch++;
            }
        }
        return 0;
    });

    // TlsAlloc()
    static u32 s_tlsNextIdx = 1;
    static std::unordered_map<u64, u64> s_tlsSlots;
    kernel.RegisterHook("kernel32.dll", "TlsAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 idx = s_tlsNextIdx++;
        return idx;
    });

    // TlsGetValue(DWORD dwTlsIndex)
    kernel.RegisterHook("kernel32.dll", "TlsGetValue", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 idx = static_cast<u32>(ctx.rcx);
        u64 key = (static_cast<u64>(GetCurrentGuestThreadId()) << 32) | idx;
        auto it = s_tlsSlots.find(key);
        return (it != s_tlsSlots.end()) ? it->second : 0;
    });

    // TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
    kernel.RegisterHook("kernel32.dll", "TlsSetValue", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 idx = static_cast<u32>(ctx.rcx);
        u64 val = ctx.rdx;
        u64 key = (static_cast<u64>(GetCurrentGuestThreadId()) << 32) | idx;
        s_tlsSlots[key] = val;
        return 1;
    });

    // TlsFree(DWORD dwTlsIndex)
    kernel.RegisterHook("kernel32.dll", "TlsFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1;
    });

    // Fiber Local Storage (FLS)
    static u64 s_flsCounter = 0;
    static std::unordered_map<u64, u64> s_flsSlots;
    kernel.RegisterHook("kernel32.dll", "FlsAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 slot = ++s_flsCounter;
        return slot;
    });
    kernel.RegisterHook("kernel32.dll", "FlsSetValue", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 slot = static_cast<u32>(ctx.rcx);
        u64 val = ctx.rdx;
        u64 key = (static_cast<u64>(GetCurrentGuestThreadId()) << 32) | slot;
        s_flsSlots[key] = val;
        return 1;
    });
    kernel.RegisterHook("kernel32.dll", "FlsGetValue", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 slot = static_cast<u32>(ctx.rcx);
        u64 key = (static_cast<u64>(GetCurrentGuestThreadId()) << 32) | slot;
        auto it = s_flsSlots.find(key);
        return (it != s_flsSlots.end()) ? it->second : 0;
    });
    kernel.RegisterHook("kernel32.dll", "FlsFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 1;
    });

    kernel.RegisterHook("kernel32.dll", "InitializeCriticalSectionEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr cs = ctx.rcx;
        if (cs) {
            for (u32 i = 0; i < 40; i += 8) mem.Write<u64>(cs + i, 0);
            s_criticalSections[cs] = CriticalSectionState{};
        }
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
        auto mapIt = s_vfsMappings.find(handle);
        if (mapIt != s_vfsMappings.end()) {
            s_vfsMappings.erase(mapIt);
            return 1;
        }
        return 1;
    });

    // CreateFileMappingW / CreateFileMappingA / MapViewOfFile / UnmapViewOfFile
    auto createFileMappingHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hFile = ctx.rcx;
        u32 dwMaxHigh = static_cast<u32>(ctx.r9);
        u32 dwMaxLow = ctx.rsp ? mem.Read<u32>(ctx.rsp + 40) : 0;
        u64 size = (static_cast<u64>(dwMaxHigh) << 32) | dwMaxLow;

        if (hFile != ~0ULL) {
            auto it = s_vfsFiles.find(hFile);
            if (it == s_vfsFiles.end() || it->second.fd < 0) {
                s_lastErrorCode = 6; // ERROR_INVALID_HANDLE
                return 0;
            }
            if (size == 0) {
                struct stat st;
                if (fstat(it->second.fd, &st) == 0) {
                    size = static_cast<u64>(st.st_size);
                }
            }
        }
        if (size == 0) size = 4096;

        u64 handle = ++s_nextMappingHandle;
        s_vfsMappings[handle] = {hFile, size};
        LOG_INFO("VFS", "CreateFileMapping(file=0x" + std::to_string(hFile) + ", size=" + std::to_string(size) + ") -> HANDLE=0x" + std::to_string(handle));
        s_lastErrorCode = 0;
        return handle;
    };
    kernel.RegisterHook("kernel32.dll", "CreateFileMappingW", createFileMappingHandler);
    kernel.RegisterHook("kernel32.dll", "CreateFileMappingA", createFileMappingHandler);

    kernel.RegisterHook("kernel32.dll", "MapViewOfFile", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hMapping = ctx.rcx;
        u32 offHigh = static_cast<u32>(ctx.r8);
        u32 offLow = static_cast<u32>(ctx.r9);
        u64 numBytes = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;

        auto mapIt = s_vfsMappings.find(hMapping);
        if (mapIt == s_vfsMappings.end()) {
            s_lastErrorCode = 6;
            return 0;
        }

        u64 offset = (static_cast<u64>(offHigh) << 32) | offLow;
        u64 mapSize = numBytes;
        if (mapSize == 0) {
            mapSize = (mapIt->second.size > offset) ? (mapIt->second.size - offset) : 4096;
        }
        if (mapSize == 0) mapSize = 4096;

        GuestAddr viewAddr = mem.Allocate(mapSize, MemoryProtection::ReadWrite);
        if (!viewAddr) return 0;

        if (mapIt->second.fileHandle != ~0ULL) {
            auto fIt = s_vfsFiles.find(mapIt->second.fileHandle);
            if (fIt != s_vfsFiles.end() && fIt->second.fd >= 0) {
                std::vector<u8> buf(mapSize);
                ssize_t n = pread(fIt->second.fd, buf.data(), mapSize, static_cast<off_t>(offset));
                if (n > 0) {
                    mem.WriteBytes(viewAddr, buf.data(), static_cast<size_t>(n));
                }
            }
        }
        LOG_INFO("VFS", "MapViewOfFile(map=0x" + std::to_string(hMapping) + ", size=" + std::to_string(mapSize) + ") -> 0x" + std::to_string(viewAddr));
        return viewAddr;
    });

    kernel.RegisterHook("kernel32.dll", "UnmapViewOfFile", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

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
        GuestAddr lpBuffer = ctx.rdx;
        u32 len = static_cast<u32>(ctx.r8);
        GuestAddr written = ctx.r9;
        if (lpBuffer && len > 0) {
            std::vector<u16> u16s(len);
            for (u32 i = 0; i < len; ++i) u16s[i] = mem.Read<u16>(lpBuffer + i * 2);
            LOG_INFO("GameConsole", Utf16ToUtf8(u16s));
        }
        if (written) mem.Write<u32>(written, len);
        return 1;
    });

    // MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
    kernel.RegisterHook("kernel32.dll", "MultiByteToWideChar", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr src = ctx.r8;
        s32 srcLen = static_cast<s32>(ctx.r9);
        GuestAddr dst = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        s32 dstLen = ctx.rsp ? static_cast<s32>(mem.Read<u32>(ctx.rsp + 48)) : 0;
        if (!src || srcLen == 0) return 0;

        std::string inStr;
        bool includeNull = (srcLen < 0);
        if (srcLen < 0) {
            char ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<char>(src + off)) != 0 && off < 65536) {
                inStr.push_back(ch);
                off++;
            }
        } else {
            inStr.resize(static_cast<size_t>(srcLen));
            mem.ReadBytes(src, inStr.data(), static_cast<size_t>(srcLen));
        }

        std::vector<u16> u16s = Utf8ToUtf16(inStr);
        if (includeNull) u16s.push_back(0);

        if (dstLen == 0) {
            return static_cast<u64>(u16s.size());
        }
        if (!dst || static_cast<s32>(u16s.size()) > dstLen) {
            s_lastErrorCode = 122; // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }
        for (size_t i = 0; i < u16s.size(); ++i) {
            mem.Write<u16>(dst + i * 2, u16s[i]);
        }
        s_lastErrorCode = 0;
        return static_cast<u64>(u16s.size());
    });

    // WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
    kernel.RegisterHook("kernel32.dll", "WideCharToMultiByte", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr src = ctx.r8;
        s32 srcLen = static_cast<s32>(ctx.r9);
        GuestAddr dst = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        s32 dstLen = ctx.rsp ? static_cast<s32>(mem.Read<u32>(ctx.rsp + 48)) : 0;
        GuestAddr lpUsedDefault = ctx.rsp ? mem.Read<u64>(ctx.rsp + 64) : 0;
        if (lpUsedDefault) mem.Write<u32>(lpUsedDefault, 0);
        if (!src || srcLen == 0) return 0;

        std::vector<u16> u16s;
        bool includeNull = (srcLen < 0);
        if (srcLen < 0) {
            u16 ch = 0;
            size_t off = 0;
            while ((ch = mem.Read<u16>(src + off)) != 0 && (off / 2) < 65536) {
                u16s.push_back(ch);
                off += 2;
            }
        } else {
            u16s.resize(static_cast<size_t>(srcLen));
            for (s32 i = 0; i < srcLen; ++i) {
                u16s[i] = mem.Read<u16>(src + i * 2);
            }
        }

        std::string utf8 = Utf16ToUtf8(u16s);
        size_t totalBytes = utf8.size() + (includeNull ? 1 : 0);
        if (dstLen == 0) {
            return static_cast<u64>(totalBytes);
        }
        if (!dst || static_cast<s32>(totalBytes) > dstLen) {
            s_lastErrorCode = 122; // ERROR_INSUFFICIENT_BUFFER
            return 0;
        }
        if (!utf8.empty()) {
            mem.WriteBytes(dst, utf8.data(), utf8.size());
        }
        if (includeNull) {
            mem.Write<u8>(dst + utf8.size(), 0);
        }
        s_lastErrorCode = 0;
        return static_cast<u64>(totalBytes);
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
                (s_gameRootDir.empty() ? "." : s_gameRootDir) + "/" + baseName,
                (s_gameRootDir.empty() ? "." : s_gameRootDir) + "/The Mortuary Assistant_Data/Plugins/x86_64/" + baseName,
                (s_gameRootDir.empty() ? "." : s_gameRootDir) + "/The Mortuary Assistant_Data/Plugins/" + baseName
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

        u64 pseudoHandle = 0x170000000ULL + (std::hash<std::string>{}(ToLowerAscii(baseName)) & 0x00FFFFFFULL);
        LOG_INFO("Kernel32", "LoadLibrary: Returning pseudo handle 0x" + std::to_string(pseudoHandle) + " for '" + baseName + "'");
        return pseudoHandle;
    };

    kernel.RegisterHook("kernel32.dll", "LoadLibraryA", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string name = ReadGuestAnsiString(mem, ctx.rcx, 512);
        return loadLibraryHandler(name, mem);
    });

    kernel.RegisterHook("kernel32.dll", "LoadLibraryW", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string name = ReadGuestWideString(mem, ctx.rcx, 512);
        return loadLibraryHandler(name, mem);
    });

    kernel.RegisterHook("kernel32.dll", "LoadLibraryExA", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string name = ReadGuestAnsiString(mem, ctx.rcx, 512);
        return loadLibraryHandler(name, mem);
    });

    kernel.RegisterHook("kernel32.dll", "LoadLibraryExW", [loadLibraryHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string name = ReadGuestWideString(mem, ctx.rcx, 512);
        return loadLibraryHandler(name, mem);
    });

    // Additional CRT & Win32 dynamic GetProcAddress hooks
    kernel.RegisterHook("kernel32.dll", "InitOnceExecuteOnce", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpInitOnce = ctx.rcx;
        GuestAddr initFn = ctx.rdx;
        GuestAddr parameter = ctx.r8;
        GuestAddr lpContext = ctx.r9;

        if (!lpInitOnce) return 0;
        if (mem.Read<u64>(lpInitOnce) == 2) return 1;

        if (initFn != 0 && s_hleKernel && s_peLoader) {
            static GuestAddr s_haltTrap = 0;
            if (s_haltTrap == 0) {
                s_haltTrap = mem.Allocate(16, MemoryProtection::ExecuteReadWrite);
                mem.Write<u8>(s_haltTrap, 0xF4); // HLT
            }

            CpuContext subCtx = ctx;
            subCtx.rip = initFn;
            subCtx.rsp = ((ctx.rsp - 0x200) & ~0xFULL) - 8;
            mem.Write<u64>(subCtx.rsp, s_haltTrap);
            subCtx.rcx = lpInitOnce;
            subCtx.rdx = parameter;
            subCtx.r8 = lpContext;

            Interpreter subInterp(subCtx, mem, s_hleKernel, &s_peLoader->GetImports());
            subInterp.Run(1000000);
            if (subCtx.rax != 0) {
                mem.Write<u64>(lpInitOnce, 2);
                return 1;
            }
            return 0;
        }

        mem.Write<u64>(lpInitOnce, 2);
        return 1;
    });

    kernel.RegisterHook("kernel32.dll", "GetTickCount64", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<u64>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
    });

    kernel.RegisterHook("kernel32.dll", "GetSystemTimePreciseAsFileTime", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFileTime = ctx.rcx;
        if (lpFileTime) {
            auto now = std::chrono::system_clock::now().time_since_epoch();
            u64 ticks = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(now).count()) * 10ULL + 116444736000000000ULL;
            mem.Write<u32>(lpFileTime, static_cast<u32>(ticks & 0xFFFFFFFF));
            mem.Write<u32>(lpFileTime + 4, static_cast<u32>(ticks >> 32));
        }
        return 0;
    });

    kernel.RegisterHook("kernel32.dll", "AreFileApisANSI", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "GetCurrentPackageId", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 15700; }); // APPMODEL_ERROR_NO_PACKAGE
    kernel.RegisterHook("kernel32.dll", "TryAcquireSRWLockExclusive", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return TryAcquireSrwLock(ctx.rcx, GetCurrentGuestThreadId(), false) ? 1 : 0;
    });
    kernel.RegisterHook("kernel32.dll", "TryAcquireSRWLockShared", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return TryAcquireSrwLock(ctx.rcx, GetCurrentGuestThreadId(), true) ? 1 : 0;
    });
    kernel.RegisterHook("kernel32.dll", "InitializeConditionVariable", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rcx) mem.Write<u64>(ctx.rcx, 0);
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "WakeConditionVariable", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr cv = ctx.rcx;
        for (auto& t : s_threads) {
            if (t.waiting && t.waitingCondVar && t.condVarAddr == cv && !t.wokenCondVar) {
                t.wokenCondVar = true;
                s_syncSignalEpoch++;
                break;
            }
        }
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "WakeAllConditionVariable", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr cv = ctx.rcx;
        bool any = false;
        for (auto& t : s_threads) {
            if (t.waiting && t.waitingCondVar && t.condVarAddr == cv) {
                t.wokenCondVar = true;
                any = true;
            }
        }
        if (any) s_syncSignalEpoch++;
        return 0;
    });
    auto sleepCondVarImpl = [](CpuContext& ctx, bool isSrw) -> u64 {
        GuestAddr cv = ctx.rcx;
        GuestAddr lockAddr = ctx.rdx;
        u32 dwMs = static_cast<u32>(ctx.r8);
        bool srwShared = isSrw && ((ctx.r9 & 1ULL) != 0);
        u32 curTid = GetCurrentGuestThreadId();
        auto tryReacquire = [&]() -> bool {
            return isSrw ? TryAcquireSrwLock(lockAddr, curTid, srwShared) : TryAcquireCriticalSection(lockAddr, curTid);
        };
        auto releaseLock = [&]() {
            if (isSrw) ReleaseSrwLock(lockAddr, curTid, srwShared);
            else ReleaseCriticalSection(lockAddr, curTid);
        };
        if (s_threads.empty() || s_activeThreadIdx >= s_threads.size() || !HasOtherActiveThreads()) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                s_threads[s_activeThreadIdx].waiting = false;
                s_threads[s_activeThreadIdx].waitingCondVar = false;
                s_threads[s_activeThreadIdx].condVarReacquirePending = false;
            }
            return 1;
        }
        GuestThread& cur = s_threads[s_activeThreadIdx];
        if (cur.condVarReacquirePending) {
            if (tryReacquire()) {
                cur.waiting = false;
                cur.condVarReacquirePending = false;
                if (!cur.condVarReacquireResult) s_lastErrorCode = 1460;
                return cur.condVarReacquireResult;
            }
            BlockActiveThreadUntilEpoch();
            return 0;
        }
        if (!cur.waiting) {
            if (dwMs == 0) {
                s_lastErrorCode = 1460; // ERROR_TIMEOUT
                return 0;
            }
            releaseLock();
            cur.waiting = true;
            cur.waitIsSleep = false;
            cur.waitingCondVar = true;
            cur.condVarAddr = cv;
            cur.wokenCondVar = false;
            cur.waitStartRound = s_schedulerRound;
            cur.waitObservedEpoch = s_syncSignalEpoch;
            cur.waitInfinite = (dwMs == 0xFFFFFFFFU);
            cur.waitDeadlineMs = cur.waitInfinite ? ~0ULL : (GetCurrentSyncMs() + dwMs);
            if (s_hleKernel) s_hleKernel->RequestYield(true);
            return 0;
        }
        if (cur.wokenCondVar || (!cur.waitInfinite && (s_schedulerRound - cur.waitStartRound) >= 2 && GetCurrentSyncMs() >= cur.waitDeadlineMs)) {
            u64 result = cur.wokenCondVar ? 1 : 0;
            cur.waiting = false;
            cur.waitingCondVar = false;
            cur.wokenCondVar = false;
            if (tryReacquire()) {
                if (!result) s_lastErrorCode = 1460;
                return result;
            }
            cur.condVarReacquirePending = true;
            cur.condVarReacquireResult = result;
            BlockActiveThreadUntilEpoch();
            return 0;
        }
        cur.waitObservedEpoch = s_syncSignalEpoch;
        if (s_hleKernel) s_hleKernel->RequestYield(true);
        return 0;
    };
    kernel.RegisterHook("kernel32.dll", "SleepConditionVariableCS", [sleepCondVarImpl](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return sleepCondVarImpl(ctx, false);
    });
    kernel.RegisterHook("kernel32.dll", "SleepConditionVariableSRW", [sleepCondVarImpl](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return sleepCondVarImpl(ctx, true);
    });
    kernel.RegisterHook("kernel32.dll", "CreateThreadpoolWork", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x8001; });
    kernel.RegisterHook("kernel32.dll", "SubmitThreadpoolWork", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "CloseThreadpoolWork", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "CreateThreadpoolTimer", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x8002; });
    kernel.RegisterHook("kernel32.dll", "SetThreadpoolTimer", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "LCMapStringEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "CompareStringEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 2; }); // CSTR_EQUAL
    kernel.RegisterHook("kernel32.dll", "GetLocaleInfoEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

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
                if (hModule == 0 || mod.imageBase == hModule) {
                    GuestAddr exp = s_peLoader->FindExport(mod.name, funcName);
                    if (exp != 0) {
                        LOG_INFO("Kernel32", "GetProcAddress: Resolved '" + funcName + "' in '" + mod.name + "' -> 0x" + std::to_string(exp));
                        return exp;
                    }
                }
            }
        }

        if (s_hleKernel) {
            static const char* searchMods[] = {
                "kernel32.dll", "ntdll.dll", "user32.dll", "ole32.dll",
                "oleaut32.dll", "bcrypt.dll", "version.dll", "advapi32.dll",
                "shell32.dll", "psapi.dll", "gdi32.dll", "winmm.dll",
                "d3d11.dll", "d3d12.dll", "d3d12_x.dll", "dxgi.dll",
                "shcore.dll", "dwmapi.dll", "ws2_32.dll", "userenv.dll",
                "imm32.dll", "setupapi.dll", "hid.dll", "opengl32.dll", "dsound.dll"
            };
            for (const char* sm : searchMods) {
                if (s_hleKernel->HasHook(sm, funcName)) {
                    GuestAddr tramp = s_hleKernel->GetOrCreateHookTrampoline(sm, funcName);
                    LOG_INFO("Kernel32", "GetProcAddress: Resolved HLE hook '" + funcName + "' -> 0x" + std::to_string(tramp));
                    return tramp;
                }
            }
        }

        static GuestAddr s_dummyProc = 0;
        if (s_dummyProc == 0) {
            s_dummyProc = mem.Allocate(16, MemoryProtection::ExecuteReadWrite);
            // xor eax, eax; ret (return 0 safely instead of garbage RAX)
            u8 stub[3] = {0x31, 0xC0, 0xC3};
            mem.WriteBytes(s_dummyProc, stub, sizeof(stub));
        }
        LOG_INFO("Kernel32", "GetProcAddress: Returning zero-return fallback stub for '" + funcName + "'");
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
    auto createEventHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 h = ++s_handleCounter;
        SyncObject obj{};
        obj.kind = SyncKind::Event;
        obj.manualReset = (ctx.rdx != 0);
        obj.signaled = (ctx.r8 != 0);
        s_syncObjects[h] = obj;
        return h;
    };
    kernel.RegisterHook("kernel32.dll", "CreateEventW", createEventHandler);
    kernel.RegisterHook("kernel32.dll", "CreateEventA", createEventHandler);
    kernel.RegisterHook("kernel32.dll", "SetEvent", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        auto it = s_syncObjects.find(ctx.rcx);
        if (it != s_syncObjects.end()) {
            it->second.signaled = true;
            s_syncSignalEpoch++;
        }
        return 1;
    });
    kernel.RegisterHook("kernel32.dll", "ResetEvent", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        auto it = s_syncObjects.find(ctx.rcx);
        if (it != s_syncObjects.end()) it->second.signaled = false;
        return 1;
    });

    // CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)
    kernel.RegisterHook("kernel32.dll", "CreatePipe", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr hRead = ctx.rcx;
        GuestAddr hWrite = ctx.rdx;
        if (hRead) mem.Write<u64>(hRead, ++s_handleCounter);
        if (hWrite) mem.Write<u64>(hWrite, ++s_handleCounter);
        return 1;
    });

    // SetHandleInformation
    kernel.RegisterHook("kernel32.dll", "SetHandleInformation", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    // WaitForSingleObject / WaitForMultipleObjects
    auto waitSingleHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        u32 dwMs = static_cast<u32>(ctx.rdx);
        u32 curTid = GetCurrentGuestThreadId();
        if (IsHandleSignaled(handle, curTid)) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                s_threads[s_activeThreadIdx].waiting = false;
            }
            ConsumeHandleSignal(handle, curTid);
            return 0; // WAIT_OBJECT_0
        }
        if (dwMs == 0 || s_threads.empty() || s_activeThreadIdx >= s_threads.size() || !HasOtherActiveThreads()) {
            return (dwMs == 0) ? 0x102ULL : 0ULL;
        }
        GuestThread& cur = s_threads[s_activeThreadIdx];
        if (!cur.waiting) {
            cur.waiting = true;
            cur.waitIsSleep = false;
            cur.waitingCondVar = false;
            cur.waitStartRound = s_schedulerRound;
            cur.waitObservedEpoch = s_syncSignalEpoch;
            cur.waitInfinite = (dwMs == 0xFFFFFFFFU);
            cur.waitDeadlineMs = cur.waitInfinite ? ~0ULL : (GetCurrentSyncMs() + dwMs);
            if (s_hleKernel) s_hleKernel->RequestYield(true);
            return 0;
        }
        if (!cur.waitInfinite && (s_schedulerRound - cur.waitStartRound) >= 2 && GetCurrentSyncMs() >= cur.waitDeadlineMs) {
            cur.waiting = false;
            return 0x102ULL; // WAIT_TIMEOUT
        }
        cur.waitObservedEpoch = s_syncSignalEpoch;
        if (s_hleKernel) s_hleKernel->RequestYield(true);
        return 0;
    };
    kernel.RegisterHook("kernel32.dll", "WaitForSingleObject", waitSingleHandler);
    kernel.RegisterHook("kernel32.dll", "WaitForSingleObjectEx", waitSingleHandler);

    auto waitMultipleHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 nCount = static_cast<u32>(ctx.rcx);
        GuestAddr lpHandles = ctx.rdx;
        bool bWaitAll = (ctx.r8 != 0);
        u32 dwMs = static_cast<u32>(ctx.r9);
        if (nCount == 0 || !lpHandles || nCount > 64) return 0;
        u32 curTid = GetCurrentGuestThreadId();

        if (bWaitAll) {
            bool allReady = true;
            for (u32 i = 0; i < nCount; ++i) {
                u64 h = mem.Read<u64>(lpHandles + i * 8);
                if (!IsHandleSignaled(h, curTid)) { allReady = false; break; }
            }
            if (allReady) {
                for (u32 i = 0; i < nCount; ++i) {
                    ConsumeHandleSignal(mem.Read<u64>(lpHandles + i * 8), curTid);
                }
                if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                    s_threads[s_activeThreadIdx].waiting = false;
                }
                return 0;
            }
        } else {
            for (u32 i = 0; i < nCount; ++i) {
                u64 h = mem.Read<u64>(lpHandles + i * 8);
                if (IsHandleSignaled(h, curTid)) {
                    ConsumeHandleSignal(h, curTid);
                    if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                        s_threads[s_activeThreadIdx].waiting = false;
                    }
                    return i;
                }
            }
        }

        if (dwMs == 0 || s_threads.empty() || s_activeThreadIdx >= s_threads.size() || !HasOtherActiveThreads()) {
            return (dwMs == 0) ? 0x102ULL : 0ULL;
        }
        GuestThread& cur = s_threads[s_activeThreadIdx];
        if (!cur.waiting) {
            cur.waiting = true;
            cur.waitIsSleep = false;
            cur.waitingCondVar = false;
            cur.waitStartRound = s_schedulerRound;
            cur.waitObservedEpoch = s_syncSignalEpoch;
            cur.waitInfinite = (dwMs == 0xFFFFFFFFU);
            cur.waitDeadlineMs = cur.waitInfinite ? ~0ULL : (GetCurrentSyncMs() + dwMs);
            if (s_hleKernel) s_hleKernel->RequestYield(true);
            return 0;
        }
        if (!cur.waitInfinite && (s_schedulerRound - cur.waitStartRound) >= 2 && GetCurrentSyncMs() >= cur.waitDeadlineMs) {
            cur.waiting = false;
            return 0x102ULL;
        }
        cur.waitObservedEpoch = s_syncSignalEpoch;
        if (s_hleKernel) s_hleKernel->RequestYield(true);
        return 0;
    };
    kernel.RegisterHook("kernel32.dll", "WaitForMultipleObjects", waitMultipleHandler);
    kernel.RegisterHook("kernel32.dll", "WaitForMultipleObjectsEx", waitMultipleHandler);

    // Semaphores
    auto createSemHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 h = ++s_handleCounter;
        SyncObject obj{};
        obj.kind = SyncKind::Semaphore;
        obj.count = static_cast<s32>(ctx.rdx);
        obj.maxCount = std::max<s32>(1, static_cast<s32>(ctx.r8));
        s_syncObjects[h] = obj;
        return h;
    };
    kernel.RegisterHook("kernel32.dll", "CreateSemaphoreW", createSemHandler);
    kernel.RegisterHook("kernel32.dll", "CreateSemaphoreExW", createSemHandler);
    kernel.RegisterHook("kernel32.dll", "ReleaseSemaphore", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 h = ctx.rcx;
        s32 rel = static_cast<s32>(ctx.rdx);
        GuestAddr lpPrev = ctx.r8;
        auto it = s_syncObjects.find(h);
        if (it != s_syncObjects.end()) {
            if (lpPrev) mem.Write<s32>(lpPrev, it->second.count);
            it->second.count = std::min(it->second.maxCount, it->second.count + rel);
            s_syncSignalEpoch++;
            return 1;
        }
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
    auto doSleep = [](u32 dwMs) -> u64 {
        if (s_threads.empty() || s_activeThreadIdx >= s_threads.size()) return 0;
        GuestThread& cur = s_threads[s_activeThreadIdx];
        if (!HasOtherActiveThreads()) {
            cur.waiting = false;
            return 0;
        }
        if (dwMs == 0) {
            cur.waiting = false;
            if (s_hleKernel) s_hleKernel->RequestYield(false);
            return 0;
        }
        if (!cur.waiting) {
            cur.waiting = true;
            cur.waitIsSleep = true;
            cur.waitInfinite = false;
            cur.waitStartRound = s_schedulerRound;
            cur.waitDeadlineMs = GetCurrentSyncMs() + dwMs;
            if (s_hleKernel) s_hleKernel->RequestYield(true);
            return 0;
        }
        if ((s_schedulerRound - cur.waitStartRound) >= 1 && GetCurrentSyncMs() >= cur.waitDeadlineMs) {
            cur.waiting = false;
            cur.waitIsSleep = false;
            return 0;
        }
        if (s_hleKernel) s_hleKernel->RequestYield(true);
        return 0;
    };
    kernel.RegisterHook("kernel32.dll", "Sleep", [doSleep](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return doSleep(static_cast<u32>(ctx.rcx));
    });
    kernel.RegisterHook("kernel32.dll", "SleepEx", [doSleep](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return doSleep(static_cast<u32>(ctx.rcx));
    });
    kernel.RegisterHook("kernel32.dll", "SwitchToThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (HasOtherActiveThreads() && s_hleKernel) s_hleKernel->RequestYield(false);
        return 1;
    });
    kernel.RegisterHook("kernel32.dll", "GetCurrentProcessorNumber", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    // VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
    kernel.RegisterHook("kernel32.dll", "VirtualFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpAddr = ctx.rcx;
        u64 dwSize = ctx.rdx;
        u32 dwFreeType = static_cast<u32>(ctx.r8);
        // MEM_RELEASE (0x8000) frees the entire reserved region
        if ((dwFreeType & 0x8000U) && lpAddr != 0) {
            if (dwSize != 0) {
                s_lastErrorCode = 87; // ERROR_INVALID_PARAMETER
                return 0;
            }
            static u32 s_freeLogCount = 0;
            if (s_freeLogCount < 40) {
                s_freeLogCount++;
                GuestAddr retRip = ctx.rsp ? mem.Read<u64>(ctx.rsp) : 0;
                std::stringstream ss;
                ss << "VirtualFree(MEM_RELEASE, lp=0x" << std::hex << lpAddr
                   << ", topAfterBefore=0x" << mem.GetCurrentAllocTop()
                   << ", ret=0x" << retRip << ")";
                LOG_INFO("Kernel32", ss.str());
            }
            mem.Free(lpAddr);
        }
        return 1; // Success
    });

    // VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
    kernel.RegisterHook("kernel32.dll", "VirtualQuery", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpAddr = ctx.rcx;
        GuestAddr lpBuf = ctx.rdx;
        u64 dwLen = ctx.r8;
        if (!lpBuf || dwLen < 48) {
            s_lastErrorCode = 24; // ERROR_BAD_LENGTH
            return 0;
        }
        constexpr u64 MAX_USER_ADDR = 0x7FFFFFFF0000ULL;
        u64 pageBase = lpAddr & ~0xFFFULL;
        if (pageBase >= MAX_USER_ADDR) {
            s_lastErrorCode = 87; // ERROR_INVALID_PARAMETER
            return 0;
        }

        struct MemRegion {
            u64 start;
            u64 end;
            u32 protect;
            u32 type;
            u64 allocBase;
            u32 state = 0x1000; // MEM_COMMIT
        };
        static std::vector<MemRegion> s_staticRegions;
        static size_t s_cachedModCount = static_cast<size_t>(-1);
        size_t modCount = s_peLoader ? s_peLoader->GetLoadedModules().size() : 0;
        if (s_cachedModCount != modCount) {
            s_cachedModCount = modCount;
            s_staticRegions.clear();
            s_staticRegions.reserve(64);
            // Windows stack layout: reserved bottom, 1 guard page, committed upper stack (768KB+ below 0x100800000)
            s_staticRegions.push_back({0x100000000ULL, 0x10073F000ULL, 0x01,  0x20000, 0x100000000ULL, 0x2000});
            s_staticRegions.push_back({0x10073F000ULL, 0x100740000ULL, 0x104, 0x20000, 0x100000000ULL, 0x1000});
            s_staticRegions.push_back({0x100740000ULL, 0x100900000ULL, 0x04,  0x20000, 0x100000000ULL, 0x1000});
            s_staticRegions.push_back({0x150000000ULL, 0x150100000ULL, 0x20, 0x20000, 0x150000000ULL}); // Trampolines
            s_staticRegions.push_back({0x160000000ULL, 0x166000000ULL, 0x04, 0x20000, 0x160000000ULL}); // TEB/PEB/Env

            if (s_peLoader) {
                for (const auto& mod : s_peLoader->GetLoadedModules()) {
                    if (mod.imageBase == 0 || mod.sizeOfImage == 0) continue;
                    u64 firstSecStart = (mod.imageBase + mod.sizeOfImage + 0xFFFULL) & ~0xFFFULL;
                    for (const auto& sec : mod.sections) {
                        u64 secStart = (mod.imageBase + sec.virtualAddress) & ~0xFFFULL;
                        u64 rawOrVirt = std::max<u64>(sec.virtualSize, sec.sizeOfRawData);
                        if (rawOrVirt == 0) rawOrVirt = 0x1000;
                        u64 secEnd = (mod.imageBase + sec.virtualAddress + rawOrVirt + 0xFFFULL) & ~0xFFFULL;
                        if (secStart < firstSecStart) firstSecStart = secStart;
                        bool isExec = (sec.characteristics & 0x20000000U) != 0;
                        bool isWrite = (sec.characteristics & 0x80000000U) != 0;
                        u32 prot = isExec ? (isWrite ? 0x40 : 0x20) : (isWrite ? 0x04 : 0x02);
                        s_staticRegions.push_back({secStart, secEnd, prot, 0x1000000, mod.imageBase});
                    }
                    if (firstSecStart > mod.imageBase) {
                        s_staticRegions.push_back({mod.imageBase, firstSecStart, 0x02, 0x1000000, mod.imageBase});
                    }
                }
            }
            std::sort(s_staticRegions.begin(), s_staticRegions.end(), [](const MemRegion& a, const MemRegion& b) {
                return a.start < b.start;
            });
        }

        u64 heapEnd = (s_heapCurrent + 0xFFFULL) & ~0xFFFULL;
        u64 allocTop = (mem.GetCurrentAllocTop() + 0xFFFULL) & ~0xFFFULL;

        const MemRegion* hit = nullptr;
        MemRegion dynHit{};
        u64 nextRegionStart = MAX_USER_ADDR;

        // Dynamic heap & VirtualAlloc arenas sit strictly above 0x240000000ULL
        if (pageBase >= 0x300000000ULL && pageBase < allocTop) {
            dynHit = {0x300000000ULL, allocTop, 0x04, 0x20000, 0x300000000ULL};
            hit = &dynHit;
        } else if (pageBase >= 0x240000000ULL && pageBase < heapEnd) {
            dynHit = {0x240000000ULL, heapEnd, 0x04, 0x20000, 0x240000000ULL};
            hit = &dynHit;
        } else {
            for (const auto& r : s_staticRegions) {
                if (r.start <= pageBase && pageBase < r.end) {
                    hit = &r;
                    break;
                }
                if (r.start > pageBase) {
                    nextRegionStart = r.start;
                    break;
                }
            }
            if (!hit) {
                if (heapEnd > 0x240000000ULL && 0x240000000ULL > pageBase && 0x240000000ULL < nextRegionStart) {
                    nextRegionStart = 0x240000000ULL;
                } else if (allocTop > 0x300000000ULL && 0x300000000ULL > pageBase && 0x300000000ULL < nextRegionStart) {
                    nextRegionStart = 0x300000000ULL;
                }
            }
        }

        if (hit) {
            mem.Write<u64>(lpBuf + 0, pageBase);                // BaseAddress
            mem.Write<u64>(lpBuf + 8, hit->allocBase);          // AllocationBase
            mem.Write<u32>(lpBuf + 16, hit->protect);           // AllocationProtect
            mem.Write<u32>(lpBuf + 20, 0);                      // PartitionId
            mem.Write<u64>(lpBuf + 24, hit->end - pageBase);    // RegionSize
            mem.Write<u32>(lpBuf + 32, hit->state);             // State
            mem.Write<u32>(lpBuf + 36, hit->protect);           // Protect
            mem.Write<u32>(lpBuf + 40, hit->type);              // Type
            mem.Write<u32>(lpBuf + 44, 0);
        } else {
            mem.Write<u64>(lpBuf + 0, pageBase);                // BaseAddress
            mem.Write<u64>(lpBuf + 8, 0);                       // AllocationBase
            mem.Write<u32>(lpBuf + 16, 0);                      // AllocationProtect
            mem.Write<u32>(lpBuf + 20, 0);                      // PartitionId
            mem.Write<u64>(lpBuf + 24, nextRegionStart - pageBase); // RegionSize
            mem.Write<u32>(lpBuf + 32, 0x10000);                // State = MEM_FREE
            mem.Write<u32>(lpBuf + 36, 0x01);                   // Protect = PAGE_NOACCESS
            mem.Write<u32>(lpBuf + 40, 0);                      // Type = 0
            mem.Write<u32>(lpBuf + 44, 0);
        }
        return 48;
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

    // DuplicateHandle(hSourceProcess, hSourceHandle, hTargetProcess, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)
    kernel.RegisterHook("kernel32.dll", "DuplicateHandle", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hSource = ctx.rdx;
        GuestAddr lpTargetHandle = ctx.r9;
        u64 dupHandle = hSource;
        if (hSource == ~1ULL || hSource == 0xFFFFFFFEULL) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                dupHandle = s_threads[s_activeThreadIdx].handle;
            }
        }
        if (lpTargetHandle) mem.Write<u64>(lpTargetHandle, dupHandle);
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
    kernel.RegisterHook("kernel32.dll", "GetThreadPriority", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "CreateThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 stackSize = ctx.rdx;
        GuestAddr startAddr = ctx.r8;
        u64 param = ctx.r9;
        u32 creationFlags = ctx.rsp ? mem.Read<u32>(ctx.rsp + 40) : 0;
        GuestAddr lpThreadId = ctx.rsp ? mem.Read<u64>(ctx.rsp + 48) : 0;

        u64 allocStackSize = std::max<u64>(stackSize, 1024ULL * 1024ULL);
        GuestAddr stackBase = mem.Allocate(allocStackSize, MemoryProtection::ReadWrite);
        if (!stackBase) {
            s_lastErrorCode = 8; // ERROR_NOT_ENOUGH_MEMORY
            return 0;
        }
        GuestAddr stackTop = stackBase + allocStackSize;

        static u32 s_nextThreadId = 1001;
        u32 tid = ++s_nextThreadId;
        u64 handle = ++s_handleCounter;

        GuestAddr tebAddr = EnvironmentManager::CreateThreadTeb(mem, s_mainTebAddr, stackBase, stackTop, tid);
        if (!tebAddr) tebAddr = s_mainTebAddr;

        GuestThread t{};
        t.handle = handle;
        t.threadId = tid;
        t.stackBase = stackBase;
        t.stackTop = stackTop;
        t.suspended = (creationFlags & 0x4) != 0;

        if (!s_threads.empty()) {
            t.ctx = s_threads[0].ctx;
        }
        t.ctx.rip = startAddr;
        t.ctx.rcx = param;
        t.ctx.rdx = 0;
        t.ctx.r8 = 0;
        t.ctx.r9 = 0;
        t.ctx.rax = 0;
        t.ctx.gsBase = tebAddr;

        GuestAddr initRsp = ((stackTop - 0x48) & ~0xFULL) - 8;
        mem.Write<u64>(initRsp, s_threadExitTrampoline);
        t.ctx.rsp = initRsp;

        s_threads.push_back(t);
        if (lpThreadId) mem.Write<u32>(lpThreadId, tid);

        std::stringstream ss;
        ss << "CreateThread: handle=0x" << std::hex << handle << " tid=" << std::dec << tid
           << " start=0x" << std::hex << startAddr << " param=0x" << param
           << " teb=0x" << tebAddr << " suspended=" << (t.suspended ? 1 : 0);
        LOG_INFO("Kernel32", ss.str());
        return handle;
    });
    auto resolveThreadHandle = [](u64 hThread) -> GuestThread* {
        if (hThread == ~1ULL || hThread == 0xFFFFFFFEULL) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) return &s_threads[s_activeThreadIdx];
            return nullptr;
        }
        return FindThreadByHandle(hThread);
    };
    kernel.RegisterHook("kernel32.dll", "ResumeThread", [resolveThreadHandle](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestThread* t = resolveThreadHandle(ctx.rcx);
        if (!t) return 0xFFFFFFFFULL;
        u32 prev = t->suspended ? 1 : 0;
        t->suspended = false;
        return prev;
    });
    kernel.RegisterHook("kernel32.dll", "SuspendThread", [resolveThreadHandle](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestThread* t = resolveThreadHandle(ctx.rcx);
        if (!t) {
            static u32 s_missLogs = 0;
            if (s_missLogs < 5) {
                s_missLogs++;
                std::stringstream ss;
                ss << "SuspendThread unknown handle=0x" << std::hex << ctx.rcx
                   << " caller=0x" << (ctx.rsp ? mem.Read<u64>(ctx.rsp) : 0);
                LOG_WARN("Kernel32", ss.str());
            }
            return 0xFFFFFFFFULL;
        }
        u32 prev = t->suspended ? 1 : 0;
        t->suspended = true;
        if (!s_threads.empty() && s_activeThreadIdx < s_threads.size() && t == &s_threads[s_activeThreadIdx] && s_hleKernel) {
            s_hleKernel->RequestYield(false);
        }
        return prev;
    });
    kernel.RegisterHook("kernel32.dll", "OpenThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 tid = static_cast<u32>(ctx.r8);
        for (const auto& t : s_threads) {
            if (t.threadId == tid && !t.exited) return t.handle;
        }
        s_lastErrorCode = 87; // ERROR_INVALID_PARAMETER
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "GetThreadContext", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hThread = ctx.rcx;
        GuestAddr lpContext = ctx.rdx;
        GuestThread* t = nullptr;
        if (hThread == ~1ULL || hThread == 0xFFFFFFFEULL) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) t = &s_threads[s_activeThreadIdx];
        } else {
            t = FindThreadByHandle(hThread);
        }
        if (!t || !lpContext) {
            s_lastErrorCode = 6; // ERROR_INVALID_HANDLE
            return 0;
        }
        const CpuContext& src = (!s_threads.empty() && s_activeThreadIdx < s_threads.size() && t == &s_threads[s_activeThreadIdx]) ? ctx : t->ctx;
        mem.Write<u32>(lpContext + 0x34, 0x1F80); // MxCsr
        mem.Write<u16>(lpContext + 0x38, 0x33);   // SegCs
        mem.Write<u16>(lpContext + 0x3A, 0x2B);   // SegDs
        mem.Write<u16>(lpContext + 0x3C, 0x2B);   // SegEs
        mem.Write<u16>(lpContext + 0x3E, 0x53);   // SegFs
        mem.Write<u16>(lpContext + 0x40, 0x2B);   // SegGs
        mem.Write<u16>(lpContext + 0x42, 0x2B);   // SegSs
        mem.Write<u32>(lpContext + 0x44, static_cast<u32>(src.rflags));
        mem.Write<u64>(lpContext + 0x78, src.rax);
        mem.Write<u64>(lpContext + 0x80, src.rcx);
        mem.Write<u64>(lpContext + 0x88, src.rdx);
        mem.Write<u64>(lpContext + 0x90, src.rbx);
        mem.Write<u64>(lpContext + 0x98, src.rsp);
        mem.Write<u64>(lpContext + 0xA0, src.rbp);
        mem.Write<u64>(lpContext + 0xA8, src.rsi);
        mem.Write<u64>(lpContext + 0xB0, src.rdi);
        mem.Write<u64>(lpContext + 0xB8, src.r8);
        mem.Write<u64>(lpContext + 0xC0, src.r9);
        mem.Write<u64>(lpContext + 0xC8, src.r10);
        mem.Write<u64>(lpContext + 0xD0, src.r11);
        mem.Write<u64>(lpContext + 0xD8, src.r12);
        mem.Write<u64>(lpContext + 0xE0, src.r13);
        mem.Write<u64>(lpContext + 0xE8, src.r14);
        mem.Write<u64>(lpContext + 0xF0, src.r15);
        mem.Write<u64>(lpContext + 0xF8, src.rip);
        return 1;
    });
    kernel.RegisterHook("kernel32.dll", "ExitThread", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 code = static_cast<u32>(ctx.rcx);
        if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
            GuestThread& cur = s_threads[s_activeThreadIdx];
            cur.exited = true;
            cur.exitCode = code;
            cur.waiting = false;
            cur.suspended = false;
            s_syncSignalEpoch++;
            if (cur.isMain) {
                s_processExited = true;
                s_processExitCode = code;
            }
            if (s_hleKernel) s_hleKernel->RequestYield(false);
        }
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "GetExitCodeThread", [resolveThreadHandle](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpExitCode = ctx.rdx;
        GuestThread* t = resolveThreadHandle(ctx.rcx);
        if (!t) {
            s_lastErrorCode = 6; // ERROR_INVALID_HANDLE
            return 0;
        }
        if (lpExitCode) {
            mem.Write<u32>(lpExitCode, t->exited ? t->exitCode : 259); // STILL_ACTIVE = 259
        }
        return 1;
    });
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

    // GlobalMemoryStatusEx
    kernel.RegisterHook("kernel32.dll", "GlobalMemoryStatusEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpBuffer = ctx.rcx;
        if (!lpBuffer) return 0;
        u32 len = mem.Read<u32>(lpBuffer);
        if (len >= 64) {
            mem.Write<u32>(lpBuffer + 4, 25); // dwMemoryLoad
            mem.Write<u64>(lpBuffer + 8, 16ULL * 1024 * 1024 * 1024);   // ullTotalPhys
            mem.Write<u64>(lpBuffer + 16, 12ULL * 1024 * 1024 * 1024);  // ullAvailPhys
            mem.Write<u64>(lpBuffer + 24, 16ULL * 1024 * 1024 * 1024);  // ullTotalPageFile
            mem.Write<u64>(lpBuffer + 32, 12ULL * 1024 * 1024 * 1024);  // ullAvailPageFile
            mem.Write<u64>(lpBuffer + 40, 0x7FFFFFFE0000ULL);           // ullTotalVirtual
            mem.Write<u64>(lpBuffer + 48, 0x7FF000000000ULL);           // ullAvailVirtual
            mem.Write<u64>(lpBuffer + 56, 0);                           // ullAvailExtendedVirtual
        }
        return 1;
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
    kernel.RegisterHook("ole32.dll", "CoTaskMemAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 size = ctx.rcx ? ctx.rcx : 16;
        size = (size + 15) & ~15ULL;
        GuestAddr ptr = s_heapCurrent;
        s_heapCurrent += size;
        return ptr;
    });
    kernel.RegisterHook("ole32.dll", "CoTaskMemFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ole32.dll", "CoGetContextToken", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pContext = ctx.rcx;
        if (pContext) mem.Write<u64>(pContext, 0);
        return 0x800401F0ULL; // CO_E_NOTINITIALIZED -> clean fallback
    });
    kernel.RegisterHook("ole32.dll", "CoCreateFreeThreadedMarshaler", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr ppunkMarshal = ctx.rdx;
        if (ppunkMarshal) mem.Write<u64>(ppunkMarshal, 0);
        return 0x80004002ULL; // E_NOINTERFACE
    });
    kernel.RegisterHook("kernel32.dll", "LocaleNameToLCID", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return 0x0409; // en-US LCID
    });
    kernel.RegisterHook("kernel32.dll", "LCIDToLocaleName", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpName = ctx.rdx;
        s32 cchName = static_cast<s32>(ctx.r8);
        const std::string loc = "en-US";
        if (cchName == 0) return loc.size() + 1;
        if (lpName && cchName > static_cast<s32>(loc.size())) {
            WriteGuestWideString(mem, lpName, loc);
            return loc.size() + 1;
        }
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "GetUserDefaultLocaleName", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpLocaleName = ctx.rcx;
        s32 cchLocaleName = static_cast<s32>(ctx.rdx);
        const std::string loc = "en-US";
        if (lpLocaleName && cchLocaleName > static_cast<s32>(loc.size())) {
            WriteGuestWideString(mem, lpLocaleName, loc);
            return loc.size() + 1;
        }
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "IsValidLocaleName", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "EnumSystemLocalesEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    // SHELL32: SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PWSTR* ppszPath)
    kernel.RegisterHook("shell32.dll", "SHGetKnownFolderPath", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr ppszPath = ctx.r9;
        std::string folder = "C:\\Users\\Player\\AppData\\LocalLow";
        std::vector<u16> u16s = Utf8ToUtf16(folder);
        u64 allocSize = ((u16s.size() + 1) * 2 + 15) & ~15ULL;
        GuestAddr outPtr = s_heapCurrent;
        s_heapCurrent += allocSize;
        WriteGuestWideString(mem, outPtr, folder);
        if (ppszPath) {
            mem.Write<u64>(ppszPath, outPtr);
        }
        EnsureDirectoryRecursive(s_vfsSandboxRoot + "/Users/Player/AppData/LocalLow");
        LOG_INFO("Shell32", "SHGetKnownFolderPath -> '" + folder + "'");
        return 0; // S_OK
    });

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
        if (ctx.rcx) {
            mem.Write<u64>(ctx.rcx, 0);
            s_srwLocks[ctx.rcx] = SrwLockState{};
        }
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "AcquireSRWLockExclusive", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (TryAcquireSrwLock(ctx.rcx, GetCurrentGuestThreadId(), false)) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                s_threads[s_activeThreadIdx].waiting = false;
            }
            return 0;
        }
        BlockActiveThreadUntilEpoch();
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "ReleaseSRWLockExclusive", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        ReleaseSrwLock(ctx.rcx, GetCurrentGuestThreadId(), false);
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "AcquireSRWLockShared", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (TryAcquireSrwLock(ctx.rcx, GetCurrentGuestThreadId(), true)) {
            if (!s_threads.empty() && s_activeThreadIdx < s_threads.size()) {
                s_threads[s_activeThreadIdx].waiting = false;
            }
            return 0;
        }
        BlockActiveThreadUntilEpoch();
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "ReleaseSRWLockShared", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        ReleaseSrwLock(ctx.rcx, GetCurrentGuestThreadId(), true);
        return 0;
    });

    // Mutex
    kernel.RegisterHook("kernel32.dll", "CreateMutexW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 h = ++s_handleCounter;
        bool initialOwner = ctx.rdx != 0;
        SyncObject obj{};
        obj.kind = SyncKind::Mutex;
        obj.ownerTid = initialOwner ? GetCurrentGuestThreadId() : 0;
        obj.recursion = initialOwner ? 1 : 0;
        s_syncObjects[h] = obj;
        return h;
    });
    kernel.RegisterHook("kernel32.dll", "CreateMutexA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 h = ++s_handleCounter;
        bool initialOwner = ctx.rdx != 0;
        SyncObject obj{};
        obj.kind = SyncKind::Mutex;
        obj.ownerTid = initialOwner ? GetCurrentGuestThreadId() : 0;
        obj.recursion = initialOwner ? 1 : 0;
        s_syncObjects[h] = obj;
        return h;
    });
    kernel.RegisterHook("kernel32.dll", "ReleaseMutex", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        auto it = s_syncObjects.find(ctx.rcx);
        if (it != s_syncObjects.end() && it->second.kind == SyncKind::Mutex) {
            if (it->second.recursion > 0) it->second.recursion--;
            if (it->second.recursion == 0) {
                it->second.ownerTid = 0;
                s_syncSignalEpoch++;
            }
            return 1;
        }
        return 1;
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
        size_t pLen = s_currentWinDir.size();
        if (buf && len > pLen) {
            mem.WriteBytes(buf, s_currentWinDir.c_str(), pLen + 1);
            return pLen;
        }
        return pLen + 1;
    });

    kernel.RegisterHook("kernel32.dll", "GetCurrentDirectoryW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 len = static_cast<u32>(ctx.rcx);
        GuestAddr buf = ctx.rdx;
        std::vector<u16> u16s = Utf8ToUtf16(s_currentWinDir);
        u32 pLen = static_cast<u32>(u16s.size());
        if (buf && len > pLen) {
            WriteGuestWideString(mem, buf, s_currentWinDir);
            return pLen;
        }
        return pLen + 1;
    });

    kernel.RegisterHook("kernel32.dll", "SetCurrentDirectoryW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string dir = ReadGuestWideString(mem, ctx.rcx);
        if (!dir.empty()) s_currentWinDir = dir;
        return 1;
    });
    kernel.RegisterHook("kernel32.dll", "SetCurrentDirectoryA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string dir = ReadGuestAnsiString(mem, ctx.rcx);
        if (!dir.empty()) s_currentWinDir = dir;
        return 1;
    });

    kernel.RegisterHook("kernel32.dll", "GetTempPathW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 nBufferLength = static_cast<u32>(ctx.rcx);
        GuestAddr lpBuffer = ctx.rdx;
        const std::string tmp = "C:\\Temp\\";
        std::vector<u16> u16s = Utf8ToUtf16(tmp);
        if (lpBuffer && nBufferLength > u16s.size()) {
            WriteGuestWideString(mem, lpBuffer, tmp);
            return u16s.size();
        }
        return u16s.size() + 1;
    });
    kernel.RegisterHook("kernel32.dll", "GetTempPathA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 nBufferLength = static_cast<u32>(ctx.rcx);
        GuestAddr lpBuffer = ctx.rdx;
        const std::string tmp = "C:\\Temp\\";
        if (lpBuffer && nBufferLength > tmp.size()) {
            mem.WriteBytes(lpBuffer, tmp.c_str(), tmp.size() + 1);
            return tmp.size();
        }
        return tmp.size() + 1;
    });

    auto createDirHandler = [](const std::string& rawPath) -> u64 {
        if (rawPath.empty()) {
            s_lastErrorCode = 3; // ERROR_PATH_NOT_FOUND
            return 0;
        }
        std::string resolved = ResolveGuestPath(rawPath);
        struct stat st;
        if (stat(resolved.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            s_lastErrorCode = 183; // ERROR_ALREADY_EXISTS
            return 0;
        }
        EnsureDirectoryRecursive(resolved);
        if (stat(resolved.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            s_lastErrorCode = 0;
            return 1;
        }
        s_lastErrorCode = 0;
        return 1;
    };
    kernel.RegisterHook("kernel32.dll", "CreateDirectoryW", [createDirHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return createDirHandler(ReadGuestWideString(mem, ctx.rcx));
    });
    kernel.RegisterHook("kernel32.dll", "CreateDirectoryA", [createDirHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return createDirHandler(ReadGuestAnsiString(mem, ctx.rcx));
    });

    kernel.RegisterHook("kernel32.dll", "GetFullPathNameW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string inPath = ReadGuestWideString(mem, ctx.rcx);
        u32 nBuf = static_cast<u32>(ctx.rdx);
        GuestAddr lpBuffer = ctx.r8;
        GuestAddr lpFilePart = ctx.r9;

        std::string full = inPath;
        if (full.size() < 2 || full[1] != ':') {
            if (!full.empty() && (full[0] == '\\' || full[0] == '/')) {
                full = "C:" + full;
            } else {
                full = s_currentWinDir + "\\" + full;
            }
        }
        for (char& c : full) if (c == '/') c = '\\';

        std::vector<u16> u16s = Utf8ToUtf16(full);
        if (!lpBuffer || nBuf <= u16s.size()) {
            return u16s.size() + 1;
        }
        WriteGuestWideString(mem, lpBuffer, full);
        if (lpFilePart) {
            size_t slash = full.find_last_of('\\');
            u64 partAddr = (slash != std::string::npos) ? (lpBuffer + (slash + 1) * 2) : lpBuffer;
            mem.Write<u64>(lpFilePart, partAddr);
        }
        return u16s.size();
    });

    kernel.RegisterHook("kernel32.dll", "GetFullPathNameA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string inPath = ReadGuestAnsiString(mem, ctx.rcx);
        u32 nBuf = static_cast<u32>(ctx.rdx);
        GuestAddr lpBuffer = ctx.r8;
        GuestAddr lpFilePart = ctx.r9;

        std::string full = inPath;
        if (full.size() < 2 || full[1] != ':') {
            full = s_currentWinDir + "\\" + full;
        }
        for (char& c : full) if (c == '/') c = '\\';

        if (!lpBuffer || nBuf <= full.size()) {
            return full.size() + 1;
        }
        mem.WriteBytes(lpBuffer, full.c_str(), full.size() + 1);
        if (lpFilePart) {
            size_t slash = full.find_last_of('\\');
            u64 partAddr = (slash != std::string::npos) ? (lpBuffer + slash + 1) : lpBuffer;
            mem.Write<u64>(lpFilePart, partAddr);
        }
        return full.size();
    });

    kernel.RegisterHook("kernel32.dll", "LocalAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 flags = static_cast<u32>(ctx.rcx);
        u64 size = ctx.rdx ? ctx.rdx : 16;
        size = (size + 15) & ~15ULL;
        GuestAddr ptr = s_heapCurrent;
        s_heapCurrent += size;
        if (flags & 0x0040) { // LMEM_ZEROINIT
            std::vector<u8> zeros(std::min<u64>(size, 65536), 0);
            for (u64 off = 0; off < size; off += zeros.size()) {
                mem.WriteBytes(ptr + off, zeros.data(), std::min<u64>(zeros.size(), size - off));
            }
        }
        return ptr;
    });

    kernel.RegisterHook("kernel32.dll", "GlobalAlloc", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 size = ctx.rdx ? ctx.rdx : 16;
        size = (size + 15) & ~15ULL;
        GuestAddr ptr = s_heapCurrent;
        s_heapCurrent += size;
        return ptr;
    });
    kernel.RegisterHook("kernel32.dll", "GlobalFree", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("kernel32.dll", "GlobalLock", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ctx.rcx; });
    kernel.RegisterHook("kernel32.dll", "GlobalUnlock", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "SetEnvironmentVariableW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "SetEnvironmentVariableA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    // WS2_32.dll WinSock hooks (Ordinal_115 = WSAStartup, Ordinal_116 = WSACleanup, Ordinal_111 = WSAGetLastError)
    auto wsaStartupHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u16 wVersionRequested = static_cast<u16>(ctx.rcx & 0xFFFF);
        GuestAddr lpWSAData = ctx.rdx;
        if (lpWSAData) {
            for (u32 i = 0; i < 408; i += 8) mem.Write<u64>(lpWSAData + i, 0);
            mem.Write<u16>(lpWSAData + 0, wVersionRequested ? wVersionRequested : 0x0202); // wVersion
            mem.Write<u16>(lpWSAData + 2, 0x0202); // wHighVersion
        }
        return 0; // Success
    };
    kernel.RegisterHook("ws2_32.dll", "WSAStartup", wsaStartupHandler);
    kernel.RegisterHook("ws2_32.dll", "Ordinal_115", wsaStartupHandler);
    kernel.RegisterHook("ws2_32.dll", "WSACleanup", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ws2_32.dll", "Ordinal_116", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ws2_32.dll", "WSAGetLastError", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ws2_32.dll", "Ordinal_111", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ws2_32.dll", "WSASetLastError", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("ws2_32.dll", "Ordinal_112", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });

    auto createEventEx = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 h = ++s_handleCounter;
        u32 flags = static_cast<u32>(ctx.r8);
        SyncObject obj{};
        obj.kind = SyncKind::Event;
        obj.manualReset = (flags & 1) != 0; // CREATE_EVENT_MANUAL_RESET
        obj.signaled = (flags & 2) != 0;    // CREATE_EVENT_INITIAL_SET
        s_syncObjects[h] = obj;
        return h;
    };
    kernel.RegisterHook("kernel32.dll", "CreateEventExW", createEventEx);
    kernel.RegisterHook("kernel32.dll", "CreateEventExA", createEventEx);

    kernel.RegisterHook("kernel32.dll", "GetFileInformationByHandleEx", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 handle = ctx.rcx;
        u32 infoClass = static_cast<u32>(ctx.rdx);
        GuestAddr lpInfo = ctx.r8;
        u32 bufSize = static_cast<u32>(ctx.r9);
        auto it = s_vfsFiles.find(handle);
        if (it == s_vfsFiles.end() || it->second.fd < 0 || !lpInfo) {
            s_lastErrorCode = 6;
            return 0;
        }
        struct stat st;
        if (fstat(it->second.fd, &st) != 0) return 0;
        if (infoClass == 1 && bufSize >= 24) { // FileStandardInfo
            mem.Write<u64>(lpInfo + 0, static_cast<u64>(st.st_blocks) * 512);
            mem.Write<u64>(lpInfo + 8, static_cast<u64>(st.st_size));
            mem.Write<u32>(lpInfo + 16, static_cast<u32>(st.st_nlink));
            mem.Write<u8>(lpInfo + 20, 0);
            mem.Write<u8>(lpInfo + 21, S_ISDIR(st.st_mode) ? 1 : 0);
            return 1;
        }
        return 0;
    });

    kernel.RegisterHook("kernel32.dll", "GetEnvironmentVariableA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        s_lastErrorCode = 203; // ERROR_ENVVAR_NOT_FOUND
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "GetEnvironmentVariableW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        s_lastErrorCode = 203;
        return 0;
    });

    kernel.RegisterHook("kernel32.dll", "GetFileAttributesA", [getFileAttributesHandler](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string path = ReadGuestAnsiString(mem, ctx.rcx);
        return getFileAttributesHandler(path);
    });

    kernel.RegisterHook("kernel32.dll", "GetModuleFileNameA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hModule = ctx.rcx;
        GuestAddr buf = ctx.rdx;
        u32 size = static_cast<u32>(ctx.r8);
        std::string fullPath = GetModuleWinPath(hModule);
        size_t len = fullPath.size();
        if (!buf || size == 0) {
            s_lastErrorCode = 122;
            return 0;
        }
        size_t copyLen = std::min<size_t>(len, size - 1);
        mem.WriteBytes(buf, fullPath.c_str(), copyLen);
        mem.Write<u8>(buf + copyLen, 0);
        if (size <= len) {
            s_lastErrorCode = 122;
            return size;
        }
        s_lastErrorCode = 0;
        return len;
    });

    // PSAPI.dll / K32 module enumeration
    auto getModFileNameExA = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hModule = ctx.rdx;
        GuestAddr buf = ctx.r8;
        u32 size = static_cast<u32>(ctx.r9);
        std::string fullPath = GetModuleWinPath(hModule);
        if (!buf || size == 0) return 0;
        size_t copyLen = std::min<size_t>(fullPath.size(), size - 1);
        mem.WriteBytes(buf, fullPath.c_str(), copyLen);
        mem.Write<u8>(buf + copyLen, 0);
        return copyLen;
    };
    kernel.RegisterHook("psapi.dll", "GetModuleFileNameExA", getModFileNameExA);
    kernel.RegisterHook("kernel32.dll", "K32GetModuleFileNameExA", getModFileNameExA);

    auto getModFileNameExW = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hModule = ctx.rdx;
        GuestAddr buf = ctx.r8;
        u32 size = static_cast<u32>(ctx.r9);
        std::string fullPath = GetModuleWinPath(hModule);
        std::vector<u16> u16s = Utf8ToUtf16(fullPath);
        if (!buf || size == 0) return 0;
        size_t copyLen = std::min<size_t>(u16s.size(), size - 1);
        for (size_t i = 0; i < copyLen; ++i) mem.Write<u16>(buf + i * 2, u16s[i]);
        mem.Write<u16>(buf + copyLen * 2, 0);
        return copyLen;
    };
    kernel.RegisterHook("psapi.dll", "GetModuleFileNameExW", getModFileNameExW);
    kernel.RegisterHook("kernel32.dll", "K32GetModuleFileNameExW", getModFileNameExW);

    auto enumProcessModules = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lphModule = ctx.rdx;
        u32 cb = static_cast<u32>(ctx.r8);
        GuestAddr lpcbNeeded = ctx.r9;
        if (!s_peLoader) return 0;
        const auto& mods = s_peLoader->GetLoadedModules();
        u32 needed = static_cast<u32>(mods.size() * 8);
        if (lpcbNeeded) mem.Write<u32>(lpcbNeeded, needed);
        if (lphModule && cb >= 8) {
            u32 maxCount = cb / 8;
            for (u32 i = 0; i < std::min<u32>(maxCount, static_cast<u32>(mods.size())); ++i) {
                mem.Write<u64>(lphModule + i * 8, mods[i].imageBase);
            }
        }
        return 1;
    };
    kernel.RegisterHook("psapi.dll", "EnumProcessModules", enumProcessModules);
    kernel.RegisterHook("kernel32.dll", "K32EnumProcessModules", enumProcessModules);

    auto getModuleInfo = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u64 hModule = ctx.rdx;
        GuestAddr lpModInfo = ctx.r8;
        u32 cb = static_cast<u32>(ctx.r9);
        if (lpModInfo && cb >= 24 && s_peLoader) {
            for (const auto& mod : s_peLoader->GetLoadedModules()) {
                if ((hModule == 0 && mod.imageBase == 0x140000000ULL) || mod.imageBase == hModule) {
                    mem.Write<u64>(lpModInfo + 0, mod.imageBase);
                    mem.Write<u32>(lpModInfo + 8, mod.sizeOfImage);
                    mem.Write<u32>(lpModInfo + 12, 0);
                    mem.Write<u64>(lpModInfo + 16, mod.entryPoint);
                    return 1;
                }
            }
        }
        return 0;
    };
    kernel.RegisterHook("psapi.dll", "GetModuleInformation", getModuleInfo);
    kernel.RegisterHook("kernel32.dll", "K32GetModuleInformation", getModuleInfo);

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
    kernel.RegisterHook("advapi32.dll", "GetUserNameW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr buf = ctx.rcx;
        GuestAddr pSize = ctx.rdx;
        const std::string user = "Player";
        if (buf) WriteGuestWideString(mem, buf, user);
        if (pSize) mem.Write<u32>(pSize, static_cast<u32>(user.size() + 1));
        return 1;
    });
    kernel.RegisterHook("advapi32.dll", "OpenProcessToken", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pTokenHandle = ctx.r8;
        if (pTokenHandle) mem.Write<u64>(pTokenHandle, 0x7001);
        return 1;
    });
    kernel.RegisterHook("advapi32.dll", "GetTokenInformation", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 infoClass = static_cast<u32>(ctx.rdx);
        GuestAddr tokenInfo = ctx.r8;
        u32 len = static_cast<u32>(ctx.r9);
        GuestAddr pReturnLength = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        // TokenElevation = 20 (4 bytes), TokenIntegrityLevel = 25 (TOKEN_MANDATORY_LABEL = 16 bytes + SID 12 bytes)
        if (infoClass == 20) { // TokenElevation
            if (pReturnLength) mem.Write<u32>(pReturnLength, 4);
            if (!tokenInfo || len < 4) { s_lastErrorCode = 122; return 0; }
            mem.Write<u32>(tokenInfo, 0); // Not elevated
            return 1;
        }
        if (infoClass == 25) { // TokenIntegrityLevel
            if (pReturnLength) mem.Write<u32>(pReturnLength, 32);
            if (!tokenInfo || len < 32) { s_lastErrorCode = 122; return 0; }
            GuestAddr sidAddr = tokenInfo + 16;
            mem.Write<u64>(tokenInfo + 0, sidAddr);
            mem.Write<u32>(tokenInfo + 8, 0x60);
            // Minimal SID: Revision=1, SubAuthorityCount=1, Authority=16, SubAuth[0]=0x2000 (Medium)
            mem.Write<u8>(sidAddr + 0, 1);
            mem.Write<u8>(sidAddr + 1, 1);
            mem.Write<u8>(sidAddr + 7, 16);
            mem.Write<u32>(sidAddr + 8, 0x2000);
            return 1;
        }
        if (pReturnLength) mem.Write<u32>(pReturnLength, 0);
        return 0;
    });
    kernel.RegisterHook("advapi32.dll", "GetSidSubAuthorityCount", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        return ctx.rcx ? (ctx.rcx + 1) : 0;
    });
    kernel.RegisterHook("advapi32.dll", "GetSidSubAuthority", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pSid = ctx.rcx;
        u32 idx = static_cast<u32>(ctx.rdx);
        return pSid ? (pSid + 8 + idx * 4) : 0;
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
        if (idx == 0 || idx == 78) return 1920; // SM_CXSCREEN / SM_CXVIRTUALSCREEN
        if (idx == 1 || idx == 79) return 1080; // SM_CYSCREEN / SM_CYVIRTUALSCREEN
        if (idx == 80) return 1;                // SM_CMONITORS
        return 0;
    });

    // Display device & monitor enumeration
    kernel.RegisterHook("user32.dll", "EnumDisplayDevicesA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpDevice = ctx.rcx;
        u32 iDevNum = static_cast<u32>(ctx.rdx);
        GuestAddr lpDD = ctx.r8;
        if (iDevNum != 0 || !lpDD) return 0;
        u32 cb = mem.Read<u32>(lpDD);
        if (cb < 168) return 0;
        std::string devName = lpDevice ? "\\\\.\\DISPLAY1\\Monitor0" : "\\\\.\\DISPLAY1";
        std::string devStr = lpDevice ? "Generic PnP Monitor" : "Apple Metal Virtual GPU";
        std::string devId = "MONITOR\\APP0001\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000";
        for (u32 i = 4; i < std::min<u32>(cb, 424); ++i) mem.Write<u8>(lpDD + i, 0);
        mem.WriteBytes(lpDD + 4, devName.data(), std::min<size_t>(devName.size() + 1, 32));
        mem.WriteBytes(lpDD + 36, devStr.data(), std::min<size_t>(devStr.size() + 1, 128));
        mem.Write<u32>(lpDD + 164, 0x00000005); // DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE
        if (cb >= 296) mem.WriteBytes(lpDD + 168, devId.data(), std::min<size_t>(devId.size() + 1, 128));
        return 1;
    });

    kernel.RegisterHook("user32.dll", "EnumDisplayDevicesW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpDevice = ctx.rcx;
        u32 iDevNum = static_cast<u32>(ctx.rdx);
        GuestAddr lpDD = ctx.r8;
        if (iDevNum != 0 || !lpDD) return 0;
        u32 cb = mem.Read<u32>(lpDD);
        if (cb < 328) return 0;
        std::string devName = lpDevice ? "\\\\.\\DISPLAY1\\Monitor0" : "\\\\.\\DISPLAY1";
        std::string devStr = lpDevice ? "Generic PnP Monitor" : "Apple Metal Virtual GPU";
        for (u32 i = 4; i < std::min<u32>(cb, 840); ++i) mem.Write<u8>(lpDD + i, 0);
        WriteGuestWideString(mem, lpDD + 4, devName);
        WriteGuestWideString(mem, lpDD + 68, devStr);
        mem.Write<u32>(lpDD + 324, 0x00000005);
        return 1;
    });

    auto enumDispSettingsA = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 iModeNum = static_cast<u32>(ctx.rdx);
        GuestAddr lpDevMode = ctx.r8;
        if (!lpDevMode) return 0;
        if (iModeNum != 0 && iModeNum != 0xFFFFFFFFU && iModeNum != 0xFFFFFFFEU) return 0;
        std::string devName = "\\\\.\\DISPLAY1";
        mem.WriteBytes(lpDevMode + 0, devName.data(), devName.size() + 1);
        mem.Write<u16>(lpDevMode + 32, 0x0401);
        mem.Write<u16>(lpDevMode + 34, 0x0400);
        mem.Write<u16>(lpDevMode + 36, 156);
        mem.Write<u32>(lpDevMode + 40, 0x005C0000); // DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY
        mem.Write<s32>(lpDevMode + 44, 0);          // dmPosition.x
        mem.Write<s32>(lpDevMode + 48, 0);          // dmPosition.y
        mem.Write<u32>(lpDevMode + 104, 32);        // dmBitsPerPel
        mem.Write<u32>(lpDevMode + 108, 1920);      // dmPelsWidth
        mem.Write<u32>(lpDevMode + 112, 1080);      // dmPelsHeight
        mem.Write<u32>(lpDevMode + 116, 0);         // dmDisplayFlags
        mem.Write<u32>(lpDevMode + 120, 60);        // dmDisplayFrequency
        return 1;
    };
    kernel.RegisterHook("user32.dll", "EnumDisplaySettingsA", enumDispSettingsA);
    kernel.RegisterHook("user32.dll", "EnumDisplaySettingsExA", enumDispSettingsA);

    auto enumDispSettingsW = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 iModeNum = static_cast<u32>(ctx.rdx);
        GuestAddr lpDevMode = ctx.r8;
        if (!lpDevMode) return 0;
        if (iModeNum != 0 && iModeNum != 0xFFFFFFFFU && iModeNum != 0xFFFFFFFEU) return 0;
        WriteGuestWideString(mem, lpDevMode + 0, "\\\\.\\DISPLAY1");
        mem.Write<u16>(lpDevMode + 64, 0x0401);
        mem.Write<u16>(lpDevMode + 66, 0x0400);
        mem.Write<u16>(lpDevMode + 68, 220);
        mem.Write<u32>(lpDevMode + 72, 0x005C0000);
        mem.Write<s32>(lpDevMode + 76, 0);
        mem.Write<s32>(lpDevMode + 80, 0);
        mem.Write<u32>(lpDevMode + 168, 32);
        mem.Write<u32>(lpDevMode + 172, 1920);
        mem.Write<u32>(lpDevMode + 176, 1080);
        mem.Write<u32>(lpDevMode + 180, 0);
        mem.Write<u32>(lpDevMode + 184, 60);
        return 1;
    };
    kernel.RegisterHook("user32.dll", "EnumDisplaySettingsW", enumDispSettingsW);
    kernel.RegisterHook("user32.dll", "EnumDisplaySettingsExW", enumDispSettingsW);

    kernel.RegisterHook("user32.dll", "MonitorFromWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x10001; });
    kernel.RegisterHook("user32.dll", "MonitorFromRect", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x10001; });
    kernel.RegisterHook("user32.dll", "MonitorFromPoint", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x10001; });
    auto getMonitorInfoA = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpmi = ctx.rdx;
        if (!lpmi) return 0;
        u32 cbSize = mem.Read<u32>(lpmi);
        // rcMonitor (0..1920, 0..1080)
        mem.Write<s32>(lpmi + 4, 0);
        mem.Write<s32>(lpmi + 8, 0);
        mem.Write<s32>(lpmi + 12, 1920);
        mem.Write<s32>(lpmi + 16, 1080);
        // rcWork
        mem.Write<s32>(lpmi + 20, 0);
        mem.Write<s32>(lpmi + 24, 0);
        mem.Write<s32>(lpmi + 28, 1920);
        mem.Write<s32>(lpmi + 32, 1080);
        mem.Write<u32>(lpmi + 36, 1); // MONITORINFOF_PRIMARY
        if (cbSize >= 72) {
            std::string dev = "\\\\.\\DISPLAY1";
            mem.WriteBytes(lpmi + 40, dev.data(), dev.size() + 1);
        }
        return 1;
    };
    auto getMonitorInfoW = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpmi = ctx.rdx;
        if (!lpmi) return 0;
        u32 cbSize = mem.Read<u32>(lpmi);
        mem.Write<s32>(lpmi + 4, 0);
        mem.Write<s32>(lpmi + 8, 0);
        mem.Write<s32>(lpmi + 12, 1920);
        mem.Write<s32>(lpmi + 16, 1080);
        mem.Write<s32>(lpmi + 20, 0);
        mem.Write<s32>(lpmi + 24, 0);
        mem.Write<s32>(lpmi + 28, 1920);
        mem.Write<s32>(lpmi + 32, 1080);
        mem.Write<u32>(lpmi + 36, 1);
        if (cbSize >= 104) {
            WriteGuestWideString(mem, lpmi + 40, "\\\\.\\DISPLAY1");
        }
        return 1;
    };
    kernel.RegisterHook("user32.dll", "GetMonitorInfoA", getMonitorInfoA);
    kernel.RegisterHook("user32.dll", "GetMonitorInfoW", getMonitorInfoW);
    kernel.RegisterHook("user32.dll", "EnumDisplayMonitors", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpfnEnum = ctx.r8;
        GuestAddr dwData = ctx.r9;
        if (lpfnEnum && s_hleKernel && s_peLoader) {
            GuestAddr retHaltAddr = 0x1500F0000ULL;
            u8 haltOp = 0xF4;
            mem.WriteBytes(retHaltAddr, &haltOp, 1);

            GuestAddr rectAddr = ctx.rsp - 0x3000;
            mem.Write<s32>(rectAddr + 0, 0);
            mem.Write<s32>(rectAddr + 4, 0);
            mem.Write<s32>(rectAddr + 8, 1920);
            mem.Write<s32>(rectAddr + 12, 1080);

            CpuContext cbCpu;
            cbCpu.gsBase = ctx.gsBase;
            cbCpu.rsp = (ctx.rsp - 0x4000) & ~0xFULL;
            cbCpu.rsp -= 8; // Return address slot (RSP+8 is 16-byte aligned at entry)
            mem.Write<u64>(cbCpu.rsp, retHaltAddr);
            cbCpu.rip = lpfnEnum;
            cbCpu.rcx = 0x10001; // HMONITOR
            cbCpu.rdx = ctx.rcx; // HDC
            cbCpu.r8 = rectAddr; // LPRECT
            cbCpu.r9 = dwData;   // LPARAM

            Interpreter cbInterp(cbCpu, mem, s_hleKernel, &s_peLoader->GetImports());
            u64 steps = 0;
            while (!cbInterp.IsHalted() && cbCpu.rip != retHaltAddr && cbCpu.rip != 0 && steps < 5000000) {
                cbInterp.Run(100000);
                steps += 100000;
            }
        }
        return 1;
    });
    kernel.RegisterHook("shcore.dll", "GetDpiForMonitor", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.r8) mem.Write<u32>(ctx.r8, 96);
        if (ctx.r9) mem.Write<u32>(ctx.r9, 96);
        return 0; // S_OK
    });
    kernel.RegisterHook("dwmapi.dll", "DwmGetWindowAttribute", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pvAttr = ctx.r8;
        u32 cbAttr = static_cast<u32>(ctx.r9);
        if (pvAttr && cbAttr >= 4) mem.Write<u32>(pvAttr, 0);
        return 0; // S_OK
    });
    kernel.RegisterHook("dwmapi.dll", "DwmSetWindowAttribute", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("dwmapi.dll", "DwmIsCompositionEnabled", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rcx) mem.Write<u32>(ctx.rcx, 1);
        return 0;
    });
    kernel.RegisterHook("kernel32.dll", "VerSetConditionMask", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ctx.rcx | 1; });
    kernel.RegisterHook("kernel32.dll", "VerifyVersionInfoW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "VerifyVersionInfoA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "SetDllDirectoryW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "SetDllDirectoryA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("kernel32.dll", "AddDllDirectory", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });

    kernel.RegisterHook("user32.dll", "GetDC", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xDC001; });
    kernel.RegisterHook("user32.dll", "ReleaseDC", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "SetCursor", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xCC001; });
    kernel.RegisterHook("user32.dll", "LoadCursorW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xCC001; });
    kernel.RegisterHook("user32.dll", "LoadCursorA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0xCC001; });
    kernel.RegisterHook("user32.dll", "SetWindowTextW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "SetWindowTextA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "ClipCursor", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "ShowCursor", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 1; });
    kernel.RegisterHook("user32.dll", "DialogBoxParamW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        LOG_WARN("User32", "DialogBoxParamW suppressed (returning IDOK=1)");
        return 1;
    });
    kernel.RegisterHook("user32.dll", "GetActiveWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x201; });
    kernel.RegisterHook("user32.dll", "GetFocus", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x201; });
    kernel.RegisterHook("user32.dll", "GetForegroundWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x201; });
    kernel.RegisterHook("user32.dll", "IsWindow", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ctx.rcx ? 1 : 0; });

    static u32 s_nextWindowMsg = 0xC000;
    kernel.RegisterHook("user32.dll", "RegisterWindowMessageA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ++s_nextWindowMsg; });
    kernel.RegisterHook("user32.dll", "RegisterWindowMessageW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return ++s_nextWindowMsg; });
    kernel.RegisterHook("user32.dll", "GetThreadDesktop", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0x6001; });
    auto getUserObjInfo = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 index = static_cast<u32>(ctx.rdx);
        GuestAddr pvInfo = ctx.r8;
        u32 nLen = static_cast<u32>(ctx.r9);
        GuestAddr pNeeded = ctx.rsp ? mem.Read<u64>(ctx.rsp + 40) : 0;
        if (index == 1 && pvInfo && nLen >= 12) { // UOI_FLAGS (USEROBJECTFLAGS: fInherit=0, fReserved=0, dwFlags=1 WSF_VISIBLE)
            mem.Write<u32>(pvInfo + 0, 0);
            mem.Write<u32>(pvInfo + 4, 0);
            mem.Write<u32>(pvInfo + 8, 1);
            if (pNeeded) mem.Write<u32>(pNeeded, 12);
            return 1;
        }
        if (pNeeded) mem.Write<u32>(pNeeded, 12);
        return 1;
    };
    kernel.RegisterHook("user32.dll", "GetUserObjectInformationA", getUserObjInfo);
    kernel.RegisterHook("user32.dll", "GetUserObjectInformationW", getUserObjInfo);

    kernel.RegisterHook("kernel32.dll", "GetLocalTime", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpSysTime = ctx.rcx;
        if (lpSysTime) {
            std::time_t now = std::time(nullptr);
            std::tm tmVal{};
            localtime_r(&now, &tmVal);
            mem.Write<u16>(lpSysTime + 0, static_cast<u16>(tmVal.tm_year + 1900));
            mem.Write<u16>(lpSysTime + 2, static_cast<u16>(tmVal.tm_mon + 1));
            mem.Write<u16>(lpSysTime + 4, static_cast<u16>(tmVal.tm_wday));
            mem.Write<u16>(lpSysTime + 6, static_cast<u16>(tmVal.tm_mday));
            mem.Write<u16>(lpSysTime + 8, static_cast<u16>(tmVal.tm_hour));
            mem.Write<u16>(lpSysTime + 10, static_cast<u16>(tmVal.tm_min));
            mem.Write<u16>(lpSysTime + 12, static_cast<u16>(tmVal.tm_sec));
            mem.Write<u16>(lpSysTime + 14, 0);
        }
        return 0;
    });

    kernel.RegisterHook("kernel32.dll", "SystemTimeToFileTime", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr lpFileTime = ctx.rdx;
        if (lpFileTime) {
            auto now = std::chrono::system_clock::now().time_since_epoch();
            u64 ticks = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(now).count()) * 10ULL + 116444736000000000ULL;
            mem.Write<u32>(lpFileTime, static_cast<u32>(ticks & 0xFFFFFFFF));
            mem.Write<u32>(lpFileTime + 4, static_cast<u32>(ticks >> 32));
        }
        return 1;
    });

    kernel.RegisterHook("kernel32.dll", "GetSystemDirectoryA", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr buf = ctx.rcx;
        u32 size = static_cast<u32>(ctx.rdx);
        const char* sysDir = "C:\\Windows\\System32";
        u32 len = static_cast<u32>(strlen(sysDir));
        if (buf && size > len) mem.WriteBytes(buf, sysDir, len + 1);
        return len;
    });
    kernel.RegisterHook("kernel32.dll", "GetSystemDirectoryW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr buf = ctx.rcx;
        u32 size = static_cast<u32>(ctx.rdx);
        const std::string sysDir = "C:\\Windows\\System32";
        if (buf && size > sysDir.size()) WriteGuestWideString(mem, buf, sysDir);
        return sysDir.size();
    });
    kernel.RegisterHook("kernel32.dll", "GetTempFileNameW", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        std::string dir = ReadGuestWideString(mem, ctx.rcx);
        std::string prefix = ReadGuestWideString(mem, ctx.rdx);
        u32 unique = static_cast<u32>(ctx.r8);
        GuestAddr outBuf = ctx.r9;
        static u32 s_tempSeq = 1;
        u32 id = unique ? unique : s_tempSeq++;
        std::string name = dir;
        if (!name.empty() && name.back() != '\\' && name.back() != '/') name += '\\';
        name += (prefix.empty() ? "tmp" : prefix.substr(0, 3)) + std::to_string(id) + ".tmp";
        if (outBuf) WriteGuestWideString(mem, outBuf, name);
        return id;
    });

    // Multimedia timer & DirectSound audio stubs
    kernel.RegisterHook("winmm.dll", "timeGetTime", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        static auto s_start = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - s_start).count();
        return static_cast<u32>(ms);
    });
    kernel.RegisterHook("winmm.dll", "timeBeginPeriod", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("winmm.dll", "timeEndPeriod", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("dsound.dll", "DirectSoundCreate8", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rdx) mem.Write<u64>(ctx.rdx, 0);
        return 0x88780078; // DSERR_NODRIVER
    });
    kernel.RegisterHook("dsound.dll", "DirectSoundCreate", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rdx) mem.Write<u64>(ctx.rdx, 0);
        return 0x88780078; // DSERR_NODRIVER
    });
    kernel.RegisterHook("dsound.dll", "DirectSoundEnumerateW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("dsound.dll", "DirectSoundEnumerateA", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
    kernel.RegisterHook("dsound.dll", "DirectSoundCaptureCreate8", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rdx) mem.Write<u64>(ctx.rdx, 0);
        return 0x88780078;
    });
    kernel.RegisterHook("dsound.dll", "DirectSoundCaptureCreate", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        if (ctx.rdx) mem.Write<u64>(ctx.rdx, 0);
        return 0x88780078;
    });
    kernel.RegisterHook("dsound.dll", "DirectSoundCaptureEnumerateW", [](CpuContext& ctx, MemoryManager& mem) -> u64 { return 0; });
}

} // namespace Scarlett::Modules
