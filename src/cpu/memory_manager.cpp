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
    if (size == 0) size = 1;
    if (size > m_totalSize - 0xFFFF) {
        std::stringstream ss;
        ss << "Allocation request too large (0x" << std::hex << size << " bytes), returning 0";
        LOG_WARN("Memory", ss.str());
        return 0;
    }

    // Align to 64KB page allocation granularity (standard for Windows / GameOS)
    u64 alignedSize = (size + 0xFFFF) & ~0xFFFFULL;

    GuestAddr guestAddr = 0;
    std::lock_guard<std::mutex> lock(m_allocMutex);
    if (preferredBase != 0 && preferredBase >= 0x10000 && preferredBase <= m_totalSize && alignedSize <= (m_totalSize - preferredBase)) {
        guestAddr = preferredBase;
    } else if (preferredBase != 0) {
        return 0;
    } else {
        // First-fit reuse from freed guest regions before growing m_nextAllocOffset
        for (auto it = m_freeRegions.begin(); it != m_freeRegions.end(); ++it) {
            if (it->second >= alignedSize) {
                guestAddr = it->first;
                u64 remaining = it->second - alignedSize;
                m_freeRegions.erase(it);
                if (remaining > 0) {
                    m_freeRegions[guestAddr + alignedSize] = remaining;
                }
                break;
            }
        }

        if (guestAddr == 0) {
            if (alignedSize > m_totalSize || m_nextAllocOffset > (m_totalSize - alignedSize)) {
                std::stringstream ss;
                ss << "Out of guest memory arena (req=0x" << std::hex << alignedSize
                   << ", top=0x" << m_nextAllocOffset << ", max=0x" << m_totalSize
                   << ", freeRegions=" << std::dec << m_freeRegions.size() << ")";
                LOG_WARN("Memory", ss.str());
                return 0;
            }
            guestAddr = m_nextAllocOffset;
            m_nextAllocOffset += alignedSize;
        }
        m_allocatedRegions[guestAddr] = alignedSize;
    }

    std::stringstream ss;
    ss << "Allocated 0x" << std::hex << alignedSize << " bytes at GuestAddr 0x" << guestAddr;
    LOG_DEBUG("Memory", ss.str());

    return guestAddr;
}

bool MemoryManager::Free(GuestAddr address) {
    if (address == 0) return true;
    std::lock_guard<std::mutex> lock(m_allocMutex);
    auto allocIt = m_allocatedRegions.find(address);
    if (allocIt == m_allocatedRegions.end()) {
        return true;
    }

    u64 size = allocIt->second;
    m_allocatedRegions.erase(allocIt);

    // Return physical backing pages to the OS so reused ranges start zero-filled cleanly
    if (m_hostBase && address < m_totalSize && size <= (m_totalSize - address)) {
        void* regionPtr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_hostBase) + address);
        mmap(regionPtr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    }

    // Insert and coalesce adjacent free regions
    GuestAddr mergedStart = address;
    u64 mergedSize = size;
    auto nextIt = m_freeRegions.lower_bound(address);
    if (nextIt != m_freeRegions.begin()) {
        auto prevIt = std::prev(nextIt);
        if (prevIt->first + prevIt->second == mergedStart) {
            mergedStart = prevIt->first;
            mergedSize += prevIt->second;
            m_freeRegions.erase(prevIt);
        }
    }
    if (nextIt != m_freeRegions.end() && mergedStart + mergedSize == nextIt->first) {
        mergedSize += nextIt->second;
        m_freeRegions.erase(nextIt);
    }

    if (mergedStart + mergedSize == m_nextAllocOffset) {
        m_nextAllocOffset = mergedStart;
    } else {
        m_freeRegions[mergedStart] = mergedSize;
    }
    return true;
}

bool MemoryManager::Protect(GuestAddr address, u64 size, MemoryProtection protection) {
    // Guest protection tracked logically without restricting host memory access
    return true;
}

void* MemoryManager::Translate(GuestAddr guestAddress) {
    if (!m_hostBase || guestAddress < 0x10000 || guestAddress >= m_totalSize) {
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
