# Grand Theft Auto VI (Project Scarlett / Xbox Series S) Launch & Execution Guide

This document outlines the technical architecture, execution parameters, and current emulation frontier for running the leaked Xbox Series S master binary of **Grand Theft Auto VI** (`game_scarlett_master.exe`) using **ScarlettEmu** on Apple Silicon (macOS).

---

## 1. Binary Specifications

* **Target Binary:** `game_scarlett_master.exe`
* **File Size:** ~120,181,760 bytes (~120 MB)
* **Architecture:** 64-bit Portable Executable (`PE32+`, AMD64 / Zen 2)
* **Engine:** Rockstar Advanced Game Engine (RAGE)
* **Target Platform:** Xbox Series S (`Project Scarlett`, GameOS / Xbox GDK)
* **Graphics API:** Direct3D 12.X (`d3d12_xs.dll`) + DirectStorage (`xcrdapi.dll`)
* **Audio / Multimedia:** ACP HAL (`AcpHal.dll`), Bink Video (`Bink2Scarlett.dll`), XAPU (`xapu.dll`)

---

## 2. Quick Start & Execution

### 2.1 Build the Emulator
```bash
# Clone and build ScarlettEmu with maximum host threads
git clone https://github.com/cloverfield11/scarlett-emu.git
cd scarlett-emu
cmake -B build -S .
cmake --build build -j$(sysctl -n hw.ncpu)
```

### 2.2 Place the Binary & Assets
Place the master executable and assets into `scarlet-americas/`:
```
scarlett-emu/
├── build/
├── docs/
│   └── GTA6_LAUNCH_GUIDE.md
├── scarlet-americas/
│   ├── game_scarlett_master.exe    <-- [120 MB Xbox Series S binary]
│   ├── common/
│   │   └── data/
│   └── platform/
│       ├── data/
│       └── shaders/
├── src/
└── README.md
```

### 2.3 Run Execution (Batch Mode)
Execute the binary through the AMD Zen 2 CPU interpreter:
```bash
# Run up to 5,000,000,000 instructions in batch mode
./build/scarlett_emu scarlet-americas/game_scarlett_master.exe --batch 5000000000
```

---

## 3. Current Emulation Milestone: 5,000,000,000+ (5 BILLION) Instructions

ScarlettEmu has cleanly executed **5,000,157,047 instructions** (5 BILLION instructions) from cold boot, sustaining an emulation throughput of **~125–129 MIPS** across **21 concurrent guest threads**:

```
[INFO] [Core] ScarlettEmu subsystems initialized on Apple Silicon ARM64
[INFO] [Memory] Unified GDDR6 Virtual Memory initialized: 128 GB allocated
[INFO] [Loader] Ingesting 'game_scarlett_master.exe' (ImageBase: 0x140000000, Size: 0x7655000)
[INFO] [Kernel] Registered HLE Hooks for DirectStorage, D3D12, CRT, XMem, and Synchronization
[INFO] [D3D12X] Bridged Xbox D3D12 Device and CommandQueue (PresentX, GetTimestampFrequency, WaitFrameEventX)
[INFO] [Kernel] Lazy-initialized RAGE grcDeviceContext TLS block at 0x75898159104
[INFO] [Core] Runtime: 126 FPS | Total: 4786M | Threads: 21 (run=1, wait=20) | tid=1020 RIP=0x14000a3d7
[INFO] [Core] Batch execution limit reached (5000157047 instructions). Exiting loop cleanly.
```

### Key Subsystems Implemented:

1. **AMD Zen 2 Native Instructions & AVX/AVX2:**
   - Implemented AMD Zen 2 `CLZERO` (`0F 01 FC`) instruction decoding and execution to zero 64-byte cache lines aligned to `RAX`.
   - Vector operations: `VPERMILPS`, `VPBLENDW`, `VPBLENDD`, `VMOVMSKPS`, `VCMPPS`, `VMULPS`, `VADDPS`.
2. **PE Thread Local Storage (TLS) & RAGE Device Context:**
   - Fully resolved PE TLS directory template parsing and initialization.
   - Dynamic lazy-allocation and binding of the 384 KB RAGE `grcDeviceContext` structure at `%gs:0x58 -> 0x12a8(%rax)` upon first hardware graphics access.
3. **Xbox Series X/S Presentation (`PresentX`) & D3D12 Bridging:**
   - Console graphics does not use `dxgi.dll` swap chains; presentation occurs via `ID3D12CommandQueue::PresentX` at Slot 24 (`0xc0`).
   - Mapped `ID3D12Device::CreateCommandQueue` at standard Slot 8 (`0x40`).
   - Implemented `ID3D12CommandQueue::GetTimestampFrequency` returning 100 MHz GPU clock.
   - Implemented Xbox device methods: `CreateConstantBufferView`, `CreateShaderResourceView`, `CreateUnorderedAccessView`, `CreateRenderTargetView`, `CreateDepthStencilView`, `CreateSampler`, `GetResourceAllocationInfo`, `GetCustomHeapProperties`, `SetStablePowerState`, `SetResidencyPriority`, `WaitFrameEventX`, `SetFramePacingX`.
4. **Physical Memory Management (`xmem.dll`):**
   - Corrected Xbox fastcall argument unpacking for `XMemAllocatePhysicalPages` (`dwSize` in `RCX`, descriptor pointers in `RDX`).
   - Managed 6.5 GB+ dynamic physical allocations via unified GDDR6 memory arena without exhaustion.
5. **VFS Path Translation Normalization:**
   - Seamlessly translates console pseudo-device paths (`common:\data\version.txt` -> `common/data/version.txt`, `platform:\...` -> `platform/...`, `title:\...` -> `...`).
6. **Multi-Threaded Cooperative Job Scheduling:**
   - 21 concurrent guest threads executing round-robin job distribution across RAGE's internal `sysJobManager`.

---

## 4. Active VFS Asset Requests

The engine has advanced past initial runtime configuration and is actively requesting game assets through the Virtual File System (VFS):

| VFS Path | Purpose | Status in Emulator |
| :--- | :--- | :--- |
| `common:\data\version.txt` | Engine version string | Intercepted by VFS |
| `platform:\data\gameconfig.zmt` | Core engine configuration table | Intercepted by VFS |
| `platform:\data\language_sheets.zmt` | Localization & string databases | Intercepted by VFS |
| `platform:\shaders\v2\fxdb\sga_xbsx_final_init.fxdb` | Initial shader cache database | Intercepted by VFS |
| `platform:\shaders\v2\fxdb\sga_xbsx_final.fxdb` | Master graphics shader database | Intercepted by VFS |
| `platform:\shaders\v2\sga_xbsx_final_aco.d3d12PipelineCache` | RDNA 2 D3D12 pipeline state cache | Intercepted by VFS |

---

## 5. Current Frontier & Next Steps

1. **CRT String Conversion (`api-ms-win-crt-convert-l1-1-0.dll`):**
   - Provide HLE implementations for `atoi`, `strtol`, `strtoul`, `atof`, and `strtod` to parse the embedded debug font descriptors (`HelveticaNeue LT 67 MdCn`).
2. **Safe Destructor Trampoline:**
   - Add null-check guards (`if (!rcx) return;`) for scalar deleting destructor thunks.
3. **VFS Asset Mocking / Full Package Streaming:**
   - Provide mock metadata descriptors or mount extracted `.rpf` archive hierarchies as external assets become available.
