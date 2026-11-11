#pragma once

#include "common/types.h"
#include "cpu/memory_manager.h"

namespace Scarlett {

// Minimal Thread Environment Block (TEB) and Process Environment Block (PEB)
// required by Microsoft Visual C++ CRT startup and Unity bootstrap
#pragma pack(push, 1)
struct GuestTeb {
    GuestAddr exceptionList; // 0x00: Current Structured Exception Handling (SEH) frame
    GuestAddr stackBase;     // 0x08: Top of stack
    GuestAddr stackLimit;    // 0x10: Bottom of stack (used by __chkstk)
    GuestAddr subSystemTib;  // 0x18
    GuestAddr fiberData;     // 0x20
    GuestAddr arbitraryData; // 0x28
    GuestAddr self;          // 0x30: Linear address of TEB (points to self)
    GuestAddr reserved1[5];  // 0x38 - 0x60
    GuestAddr peb;           // 0x60: Pointer to PEB
    u32 lastError;           // 0x68
    u32 countOfOwnedCriticalSections; // 0x6C
    GuestAddr csrClientThread;        // 0x70
    GuestAddr win32ThreadInfo;        // 0x78
    u32 currentLocale;                // 0x80
    u32 fPSoftwareStatusRegister;     // 0x84
    GuestAddr reserved2[54];          // 0x88 - 0x238
    GuestAddr tlsSlots[64];           // 0x238 - 0x438: TLS Slots
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

        GuestTeb teb{};
        teb.stackBase = GUEST_MEMORY_BASE + 0x800000;  // 0x100800000
        teb.stackLimit = GUEST_MEMORY_BASE + 0x000000; // 0x100000000 (8 MB stack)
        teb.self = tebAddr;
        teb.peb = pebAddr;

        GuestPeb peb{};
        peb.beingDebugged = 0;
        peb.imageBaseAddress = imageBase;
        peb.processHeap = memory.Allocate(0x100000, MemoryProtection::ReadWrite, 0x160100000);

        memory.WriteBytes(tebAddr, &teb, sizeof(teb));
        memory.WriteBytes(pebAddr, &peb, sizeof(peb));

        return tebAddr;
    }
};

} // namespace Scarlett
