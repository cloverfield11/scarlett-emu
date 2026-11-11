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

    // Get dummy trampolines address in guest memory
    GuestAddr GetTrampolineBase() const { return m_trampolineBase; }

private:
    void RegisterDefaultModules();

    MemoryManager& m_memory;
    GuestAddr m_trampolineBase{0};
    u64 m_nextTrampolineOffset{0};

    // key: "module.dll!FunctionName"
    std::unordered_map<std::string, HleFunction> m_hooks;
    std::unordered_map<GuestAddr, std::string> m_trampolineMap;
};

} // namespace Scarlett
