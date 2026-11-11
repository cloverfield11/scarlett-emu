#pragma once

#include "common/types.h"
#include <vector>
#include <memory>
#include <unordered_map>
#include <map>
#include <mutex>

namespace Scarlett {

enum class MemoryProtection : u32 {
    NoAccess = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    ExecuteRead = 3,
    ExecuteReadWrite = 4
};

class MemoryManager {
public:
    MemoryManager();
    ~MemoryManager();

    bool Initialize(u64 totalUnifiedMemorySize = GUEST_MEMORY_SIZE);

    GuestAddr Allocate(u64 size, MemoryProtection protection, GuestAddr preferredBase = 0);
    bool Free(GuestAddr address);
    bool Protect(GuestAddr address, u64 size, MemoryProtection protection);

    void* Translate(GuestAddr guestAddress);
    GuestAddr GetCurrentAllocTop() const { return m_nextAllocOffset; }

    template<typename T>
    T Read(GuestAddr address) {
        void* hostPtr = Translate(address);
        if (!hostPtr) return T{};
        return *reinterpret_cast<T*>(hostPtr);
    }

    template<typename T>
    bool Write(GuestAddr address, const T& value) {
        void* hostPtr = Translate(address);
        if (!hostPtr) return false;
        *reinterpret_cast<T*>(hostPtr) = value;
        return true;
    }

    bool WriteBytes(GuestAddr address, const void* data, size_t size);
    bool ReadBytes(GuestAddr address, void* outData, size_t size);

private:
    void* m_hostBase{nullptr};
    u64 m_totalSize{0};
    u64 m_nextAllocOffset{0x300000000ULL}; // Start at 12GB mark cleanly above PE modules (5-8GB) and Heap (9-12GB)
    std::mutex m_allocMutex;
    std::map<GuestAddr, u64> m_allocatedRegions;
    std::map<GuestAddr, u64> m_freeRegions;
};

} // namespace Scarlett
