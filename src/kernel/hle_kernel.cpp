#include "kernel/hle_kernel.h"
#include "kernel/modules/kernel32.h"
#include "kernel/modules/d3d12_x.h"
#include "common/logging.h"
#include <algorithm>

namespace Scarlett {

HleKernel::HleKernel(MemoryManager& memory) : m_memory(memory) {}

void HleKernel::Initialize() {
    LOG_INFO("Kernel", "Initializing Xbox GameOS HLE subsystem...");

    // Reserve 16MB for HLE trampolines
    m_trampolineBase = m_memory.Allocate(0x1000000, MemoryProtection::ExecuteReadWrite);
    m_nextTrampolineOffset = 0;

    RegisterDefaultModules();
}

static std::vector<std::string> GetModuleAliases(const std::string& lowerMod) {
    if (lowerMod.find("api-ms-win-core-") == 0 || 
        lowerMod.find("ext-ms-win-") == 0 || 
        lowerMod.find("api-ms-win-downlevel-") == 0) {
        return {"kernel32.dll", "kernelbase.dll", "advapi32.dll", "user32.dll", "ntdll.dll"};
    }
    if (lowerMod.find("api-ms-win-crt-") == 0 || 
        lowerMod.find("vcruntime") == 0 || 
        lowerMod.find("msvcp") == 0) {
        return {"ucrtbase.dll", "vcruntime140.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-string-l1-1-0.dll", "msvcr120.dll", "msvcrt.dll", "kernel32.dll"};
    }
    if (lowerMod == "d3d12_xs.dll" || lowerMod == "d3d12_x.dll" || lowerMod == "d3d12.dll") {
        return {"d3d12_x.dll", "d3d12.dll"};
    }
    if (lowerMod == "xg_xs.dll" || lowerMod == "xg_x.dll") {
        return {"xg_x.dll", "xg.dll"};
    }
    return {};
}

void HleKernel::RegisterHook(const std::string& moduleName, const std::string& functionName, HleFunction handler) {
    std::string key = moduleName + "!" + functionName;
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    m_hooks[key] = handler;
    LOG_DEBUG("Kernel", "Registered HLE Hook: " + moduleName + " -> " + functionName);
}

static thread_local std::string s_currentExecutingHookKey;

std::string HleKernel::GetCurrentExecutingHook() {
    return s_currentExecutingHookKey;
}

bool HleKernel::ExecuteHook(const std::string& moduleName, const std::string& functionName, CpuContext& ctx) {
    std::string key = moduleName + "!" + functionName;
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    auto it = m_hooks.find(key);
    if (it != m_hooks.end()) {
        m_callCounts[key]++;
        std::string prevHook = s_currentExecutingHookKey;
        s_currentExecutingHookKey = key;
        u64 result = it->second(ctx, m_memory);
        s_currentExecutingHookKey = prevHook;
        if (!(m_yieldRequested && m_retryOnWake)) {
            ctx.rax = result; // Fastcall return value in RAX
        }
        return true;
    }

    std::string lowerMod = moduleName;
    std::transform(lowerMod.begin(), lowerMod.end(), lowerMod.begin(), ::tolower);
    std::string lowerFunc = functionName;
    std::transform(lowerFunc.begin(), lowerFunc.end(), lowerFunc.begin(), ::tolower);

    // Try module aliases
    std::vector<std::string> aliases = GetModuleAliases(lowerMod);
    for (const auto& aliasMod : aliases) {
        std::string aliasKey = aliasMod + "!" + lowerFunc;
        auto aliasIt = m_hooks.find(aliasKey);
        if (aliasIt != m_hooks.end()) {
            m_hooks[key] = aliasIt->second; // Cache resolved alias
            m_callCounts[aliasKey]++;
            std::string prevHook = s_currentExecutingHookKey;
            s_currentExecutingHookKey = aliasKey;
            u64 result = aliasIt->second(ctx, m_memory);
            s_currentExecutingHookKey = prevHook;
            if (!(m_yieldRequested && m_retryOnWake)) {
                ctx.rax = result;
            }
            return true;
        }
    }

    // Fallback: check any registered module with this function name
    std::string funcSuffix = "!" + lowerFunc;
    for (const auto& [regKey, handler] : m_hooks) {
        if (regKey.size() >= funcSuffix.size() &&
            regKey.compare(regKey.size() - funcSuffix.size(), funcSuffix.size(), funcSuffix) == 0) {
            m_hooks[key] = handler; // Cache alias
            m_callCounts[regKey]++;
            std::string prevHook = s_currentExecutingHookKey;
            s_currentExecutingHookKey = regKey;
            u64 result = handler(ctx, m_memory);
            s_currentExecutingHookKey = prevHook;
            if (!(m_yieldRequested && m_retryOnWake)) {
                ctx.rax = result;
            }
            return true;
        }
    }

    LOG_WARN("Kernel", "Unimplemented HLE function called: " + moduleName + "!" + functionName);
    ctx.rax = 0;
    return false;
}

bool HleKernel::ExecuteHookByTrampoline(GuestAddr trampolineAddr, CpuContext& ctx) {
    auto it = m_trampolineMap.find(trampolineAddr);
    if (it != m_trampolineMap.end()) {
        const std::string& key = it->second;
        size_t sep = key.find('!');
        if (sep != std::string::npos) {
            std::string mod = key.substr(0, sep);
            std::string func = key.substr(sep + 1);
            return ExecuteHook(mod, func, ctx);
        }
    }
    return false;
}

std::vector<std::pair<std::string, u64>> HleKernel::GetTopCallStats(size_t limit) const {
    std::vector<std::pair<std::string, u64>> items(m_callCounts.begin(), m_callCounts.end());
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    if (items.size() > limit) items.resize(limit);
    return items;
}

bool HleKernel::HasHook(const std::string& moduleName, const std::string& functionName) const {
    std::string key = moduleName + "!" + functionName;
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
    if (m_hooks.find(key) != m_hooks.end()) return true;

    std::string lowerMod = moduleName;
    std::transform(lowerMod.begin(), lowerMod.end(), lowerMod.begin(), ::tolower);
    std::string lowerFunc = functionName;
    std::transform(lowerFunc.begin(), lowerFunc.end(), lowerFunc.begin(), ::tolower);

    std::vector<std::string> aliases = GetModuleAliases(lowerMod);
    for (const auto& aliasMod : aliases) {
        if (m_hooks.find(aliasMod + "!" + lowerFunc) != m_hooks.end()) return true;
    }

    std::string funcSuffix = "!" + lowerFunc;
    for (const auto& [regKey, _] : m_hooks) {
        if (regKey.size() >= funcSuffix.size() &&
            regKey.compare(regKey.size() - funcSuffix.size(), funcSuffix.size(), funcSuffix) == 0) {
            return true;
        }
    }
    return false;
}

GuestAddr HleKernel::GetOrCreateHookTrampoline(const std::string& moduleName, const std::string& functionName) {
    std::string key = moduleName + "!" + functionName;
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    for (const auto& [addr, k] : m_trampolineMap) {
        if (k == key) return addr;
    }

    GuestAddr targetAddr = m_trampolineBase + m_nextTrampolineOffset;
    m_nextTrampolineOffset += 16;

    // UD2 + 4-byte ID + RET (matches X86Decoder's 6-byte HleTrap encoding + RET)
    u8 trapCode[7] = {0x0F, 0x0B, 0x00, 0x00, 0x00, 0x00, 0xC3};
    m_memory.WriteBytes(targetAddr, trapCode, sizeof(trapCode));

    m_trampolineMap[targetAddr] = key;
    return targetAddr;
}

void HleKernel::RegisterDefaultModules() {
    Modules::RegisterKernel32(*this);
    Modules::RegisterD3D12X(*this);

    // Register Unity Engine Entry Point
    RegisterHook("unityplayer.dll", "UnityMain", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        LOG_INFO("Unity", "============================================================");
        LOG_INFO("Unity", "  🚀 SUCCESS: UnityPlayer.dll!UnityMain EXECUTION REACHED!   ");
        LOG_INFO("Unity", "============================================================");
        LOG_INFO("Unity", "The Mortuary Assistant launcher passed CRT & security checks!");
        LOG_INFO("Unity", "Engine parameters: hInstance=0x" + std::to_string(ctx.rcx) + 
                          ", hPrevInstance=0x" + std::to_string(ctx.rdx) + 
                          ", lpCmdLine=0x" + std::to_string(ctx.r8) + 
                          ", nShowCmd=0x" + std::to_string(ctx.r9));
        return 0; // Success
    });
}

} // namespace Scarlett
