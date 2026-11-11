#pragma once

#include "common/types.h"
#include "cpu/cpu_context.h"
#include "cpu/memory_manager.h"
#include <string>
#include <unordered_map>
#include <functional>

namespace Scarlett {

using HleFunction = std::function<u64(CpuContext&, MemoryManager&)>;

struct ExportHook {
    std::string moduleName;
    std::string functionName;
    HleFunction handler;
};

class HleKernel {
public:
    HleKernel(MemoryManager& memory);

    void Initialize();
    void RegisterHook(const std::string& moduleName, const std::string& functionName, HleFunction handler);

    bool ExecuteHook(const std::string& moduleName, const std::string& functionName, CpuContext& ctx);
    bool ExecuteHookByTrampoline(GuestAddr trampolineAddr, CpuContext& ctx);
    bool HasHook(const std::string& moduleName, const std::string& functionName) const;
    GuestAddr GetOrCreateHookTrampoline(const std::string& moduleName, const std::string& functionName);

    // Get dummy trampolines address in guest memory
    GuestAddr GetTrampolineBase() const { return m_trampolineBase; }

    // Cooperative thread yield control
    void RequestYield(bool retryOnWake) { m_yieldRequested = true; m_retryOnWake = retryOnWake; }
    void ClearYieldRequest() { m_yieldRequested = false; m_retryOnWake = false; }
    bool ShouldYield() const { return m_yieldRequested; }
    bool ShouldRetryOnWake() const { return m_retryOnWake; }
    std::vector<std::pair<std::string, u64>> GetTopCallStats(size_t limit = 15) const;

private:
    void RegisterDefaultModules();

    MemoryManager& m_memory;
    GuestAddr m_trampolineBase{0};
    u64 m_nextTrampolineOffset{0};
    bool m_yieldRequested{false};
    bool m_retryOnWake{false};

    // key: "module.dll!FunctionName"
    std::unordered_map<std::string, HleFunction> m_hooks;
    std::unordered_map<GuestAddr, std::string> m_trampolineMap;
    std::unordered_map<std::string, u64> m_callCounts;
};

} // namespace Scarlett
