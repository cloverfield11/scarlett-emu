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
        u64 result = it->second(ctx, m_memory);
        ctx.rax = result; // Fastcall return value in RAX
        return true;
    }

    LOG_WARN("Kernel", "Unimplemented HLE function called: " + moduleName + "!" + functionName);
    return false;
}

void HleKernel::RegisterDefaultModules() {
    Modules::RegisterKernel32(*this);
    Modules::RegisterD3D12X(*this);
}

} // namespace Scarlett
