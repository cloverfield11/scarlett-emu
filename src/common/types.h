#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace Scarlett {

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using s8  = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;

using GuestAddr = u64;

constexpr u64 PAGE_SIZE = 4096;
constexpr u64 GUEST_MEMORY_BASE = 0x0000000100000000ULL; // 4GB base
constexpr u64 GUEST_MEMORY_SIZE = 0x0000002000000000ULL; // 128GB virtual address space for unified RAM, heap, and VM arenas

} // namespace Scarlett
