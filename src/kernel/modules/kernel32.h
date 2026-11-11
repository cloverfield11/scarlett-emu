#pragma once

#include "kernel/hle_kernel.h"
#include "cpu/cpu_context.h"
#include <vector>

namespace Scarlett {
class PeLoader;
}

namespace Scarlett::Modules {

struct GuestThread {
    u64 handle{0};
    u32 threadId{0};
    CpuContext ctx{};
    GuestAddr stackBase{0};
    GuestAddr stackTop{0};
    bool isMain{false};
    bool suspended{false};
    bool exited{false};
    u32 exitCode{0};
    bool waiting{false};
    bool waitIsSleep{false};
    u64 waitStartRound{0};
    u64 waitObservedEpoch{0};
    u64 waitDeadlineMs{0};
    bool waitInfinite{false};
    bool waitingCondVar{false};
    GuestAddr condVarAddr{0};
    bool wokenCondVar{false};
    bool condVarReacquirePending{false};
    u64 condVarReacquireResult{1};
};

u64 GetSyncSignalEpoch();

void SetPeLoader(PeLoader* loader);
void SetGameRootDir(const std::string& path);
bool HasProcessExited();
u32 GetProcessExitCode();
void InitMainThread(const CpuContext& mainCtx, MemoryManager& mem);
size_t GetActiveThreadIndex();
std::vector<GuestThread>& GetThreads();
void SaveActiveThreadContext(const CpuContext& srcCtx);
void SwitchToThreadIndex(size_t idx, CpuContext& dstCtx);
u32 GetCurrentGuestThreadId();
u64 GetCurrentSyncMs();
void AdvanceSchedulerRound(bool allBlocked);
u64 GetSchedulerRound();
void RegisterKernel32(HleKernel& kernel);

} // namespace Scarlett::Modules
