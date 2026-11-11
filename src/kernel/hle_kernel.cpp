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

void HleKernel::RegisterHook(const std::string& moduleName, const std::string& functionName, HleFunction handler) {
    std::string key = moduleName + "!" + functionName;
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    m_hooks[key] = handler;
    LOG_DEBUG("Kernel", "Registered HLE Hook: " + moduleName + " -> " + functionName);
}

bool HleKernel::ExecuteHook(const std::string& moduleName, const std::string& functionName, CpuContext& ctx) {
    std::string key = moduleName + "!" + functionName;
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    auto it = m_hooks.find(key);
    if (it != m_hooks.end()) {
        m_callCounts[key]++;
        u64 result = it->second(ctx, m_memory);
        if (!(m_yieldRequested && m_retryOnWake)) {
            ctx.rax = result; // Fastcall return value in RAX
        }
        return true;
    }

    LOG_WARN("Kernel", "Unimplemented HLE function called: " + moduleName + "!" + functionName);
    ctx.rax = 0;
    return false;
}

bool HleKernel::ExecuteHookByTrampoline(GuestAddr trampolineAddr, CpuContext& ctx) {
    auto it = m_trampolineMap.find(trampolineAddr);
    if (it != m_trampolineMap.end()) {
        const std::string& key = it->second;
        auto hookIt = m_hooks.find(key);
        if (hookIt != m_hooks.end()) {
            m_callCounts[key]++;
            u64 result = hookIt->second(ctx, m_memory);
            if (!(m_yieldRequested && m_retryOnWake)) {
                ctx.rax = result;
            }
            return true;
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
    return m_hooks.find(key) != m_hooks.end();
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
