#include "cpu/memory_manager.h"
#include "common/logging.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace Scarlett {

MemoryManager::MemoryManager() = default;

MemoryManager::~MemoryManager() {
    if (m_hostBase && m_totalSize > 0) {
        munmap(m_hostBase, m_totalSize);
        m_hostBase = nullptr;
    }
}

bool MemoryManager::Initialize(u64 totalUnifiedMemorySize) {
    m_totalSize = totalUnifiedMemorySize;

    // Allocate unified virtual address space for Scarlett guest memory
    m_hostBase = mmap(nullptr, m_totalSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (m_hostBase == MAP_FAILED) {
        LOG_FATAL("Memory", "Failed to allocate unified virtual address space of size " + std::to_string(m_totalSize / (1024 * 1024)) + " MB");
        m_hostBase = nullptr;
        return false;
    }

    std::stringstream ss;
    ss << "Unified GDDR6 Virtual Memory initialized: " 
       << (m_totalSize / (1024 * 1024 * 1024)) << " GB allocated at host address 0x" 
       << std::hex << reinterpret_cast<uintptr_t>(m_hostBase);
    LOG_INFO("Memory", ss.str());

    return true;
}

GuestAddr MemoryManager::Allocate(u64 size, MemoryProtection protection, GuestAddr preferredBase) {
    // Align to 64KB page allocation granularity (standard for Windows / GameOS)
    u64 alignedSize = (size + 0xFFFF) & ~0xFFFF;

    GuestAddr guestAddr = 0;
    if (preferredBase != 0 && (preferredBase + alignedSize <= m_totalSize)) {
        guestAddr = preferredBase;
    } else {
        guestAddr = m_nextAllocOffset;
        m_nextAllocOffset += alignedSize;
    }

    int prot = PROT_NONE;
    switch (protection) {
        case MemoryProtection::ReadOnly: prot = PROT_READ; break;
        case MemoryProtection::ReadWrite: prot = PROT_READ | PROT_WRITE; break;
        case MemoryProtection::ExecuteRead: prot = PROT_READ | PROT_EXEC; break;
        case MemoryProtection::ExecuteReadWrite: prot = PROT_READ | PROT_WRITE | PROT_EXEC; break;
        default: break;
    }

    void* targetHostPtr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_hostBase) + guestAddr);
    mprotect(targetHostPtr, alignedSize, prot);

    std::stringstream ss;
    ss << "Allocated 0x" << std::hex << alignedSize << " bytes at GuestAddr 0x" << guestAddr;
    LOG_DEBUG("Memory", ss.str());

    return guestAddr;
}

bool MemoryManager::Free(GuestAddr address) {
    // Soft unmap / reset protection
    void* hostPtr = Translate(address);
    if (!hostPtr) return false;
    mprotect(hostPtr, PAGE_SIZE, PROT_NONE);
    return true;
}

bool MemoryManager::Protect(GuestAddr address, u64 size, MemoryProtection protection) {
    void* hostPtr = Translate(address);
    if (!hostPtr) return false;

    int prot = PROT_NONE;
    switch (protection) {
        case MemoryProtection::ReadOnly: prot = PROT_READ; break;
        case MemoryProtection::ReadWrite: prot = PROT_READ | PROT_WRITE; break;
        case MemoryProtection::ExecuteRead: prot = PROT_READ | PROT_EXEC; break;
        case MemoryProtection::ExecuteReadWrite: prot = PROT_READ | PROT_WRITE | PROT_EXEC; break;
        default: break;
    }

    return mprotect(hostPtr, size, prot) == 0;
}

void* MemoryManager::Translate(GuestAddr guestAddress) {
    if (!m_hostBase || guestAddress >= m_totalSize) {
        return nullptr;
    }
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_hostBase) + guestAddress);
}

bool MemoryManager::WriteBytes(GuestAddr address, const void* data, size_t size) {
    void* dest = Translate(address);
    if (!dest) return false;
    std::memcpy(dest, data, size);
    return true;
}

bool MemoryManager::ReadBytes(GuestAddr address, void* outData, size_t size) {
    void* src = Translate(address);
    if (!src) return false;
    std::memcpy(outData, src, size);
    return true;
}

} // namespace Scarlett
