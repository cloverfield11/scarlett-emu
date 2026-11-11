#pragma once

#include "common/types.h"
#include "cpu/memory_manager.h"

namespace Scarlett {

// Minimal Thread Environment Block (TEB) and Process Environment Block (PEB)
// required by Microsoft Visual C++ CRT startup and Unity bootstrap
#pragma pack(push, 1)
struct GuestTeb {
    GuestAddr exceptionList;               // 0x00: Current SEH frame
    GuestAddr stackBase;                   // 0x08: Top of stack
    GuestAddr stackLimit;                  // 0x10: Bottom of stack
    GuestAddr subSystemTib;                // 0x18
    GuestAddr fiberData;                   // 0x20
    GuestAddr arbitraryData;               // 0x28
    GuestAddr self;                        // 0x30: Linear address of TEB
    GuestAddr environmentPointer;          // 0x38
    u64 processId;                         // 0x40
    u64 threadId;                          // 0x48
    GuestAddr activeRpcHandle;             // 0x50
    GuestAddr threadLocalStoragePointer;   // 0x58: ThreadLocalStoragePointer
    GuestAddr peb;                         // 0x60: Pointer to PEB
    u32 lastError;                         // 0x68
    u32 countOfOwnedCriticalSections;      // 0x6C
    GuestAddr csrClientThread;             // 0x70
    GuestAddr win32ThreadInfo;             // 0x78
    u32 currentLocale;                     // 0x80
    u32 fPSoftwareStatusRegister;          // 0x84
    GuestAddr reserved2[54];               // 0x88 - 0x238
    GuestAddr tlsSlots[64];                // 0x238 - 0x438: TLS Slots
};

struct GuestPeb {
    u8 inheritedAddressSpace;    // 0x00
    u8 readImageFileExecOptions; // 0x01
    u8 beingDebugged;            // 0x02
    u8 bitField;                 // 0x03
    GuestAddr mutant;            // 0x08
    GuestAddr imageBaseAddress;  // 0x10
    GuestAddr ldrData;           // 0x18
    GuestAddr processParameters; // 0x20
    GuestAddr subSystemData;     // 0x28
    GuestAddr processHeap;       // 0x30
};
#pragma pack(pop)

class EnvironmentManager {
public:
    static GuestAddr InitializeTebPeb(MemoryManager& memory, GuestAddr imageBase) {
        GuestAddr tebAddr = memory.Allocate(0x2000, MemoryProtection::ReadWrite, 0x160000000);
        GuestAddr pebAddr = tebAddr + 0x1000;

        // Allocate Thread Local Storage (TLS) array and module slots
        GuestAddr tlsArray = memory.Allocate(0x1000, MemoryProtection::ReadWrite, 0x160200000);
        for (int i = 0; i < 32; ++i) {
            GuestAddr modTls = memory.Allocate(0x10000, MemoryProtection::ReadWrite);
            memory.Write<u64>(tlsArray + i * 8, modTls);
        }

        GuestTeb teb{};
        teb.stackBase = GUEST_MEMORY_BASE + 0x800000;  // 0x100800000
        teb.stackLimit = GUEST_MEMORY_BASE + 0x000000; // 0x100000000 (8 MB stack)
        teb.self = tebAddr;
        teb.processId = 1000;
        teb.threadId = 1001;
        teb.threadLocalStoragePointer = tlsArray;
        teb.peb = pebAddr;

        GuestPeb peb{};
        peb.beingDebugged = 0;
        peb.imageBaseAddress = imageBase;
        peb.processHeap = memory.Allocate(0x100000, MemoryProtection::ReadWrite, 0x160100000);

        memory.WriteBytes(tebAddr, &teb, sizeof(teb));
        memory.WriteBytes(pebAddr, &peb, sizeof(peb));

        return tebAddr;
    }

    static GuestAddr CreateThreadTeb(MemoryManager& memory, GuestAddr mainTebAddr, GuestAddr stackBase, GuestAddr stackTop, u32 threadId) {
        GuestAddr tebAddr = memory.Allocate(0x1000, MemoryProtection::ReadWrite);
        GuestAddr pebAddr = mainTebAddr ? memory.Read<u64>(mainTebAddr + 0x60) : 0;
        GuestAddr tlsArray = memory.Allocate(0x1000, MemoryProtection::ReadWrite);
        for (int i = 0; i < 16; ++i) {
            GuestAddr modTls = memory.Allocate(0x10000, MemoryProtection::ReadWrite);
            memory.Write<u64>(tlsArray + i * 8, modTls);
        }

        GuestTeb teb{};
        teb.exceptionList = ~0ULL;
        teb.stackBase = stackTop;
        teb.stackLimit = stackBase;
        teb.self = tebAddr;
        teb.processId = 1000;
        teb.threadId = threadId;
        teb.threadLocalStoragePointer = tlsArray;
        teb.peb = pebAddr;
        memory.WriteBytes(tebAddr, &teb, sizeof(teb));
        return tebAddr;
    }
};

} // namespace Scarlett
