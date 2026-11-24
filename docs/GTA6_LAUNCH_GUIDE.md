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

### 2.2 Place the Binary
Place the master executable directly into the root directory of the emulator repository:
```
scarlett-emu/
├── build/
├── docs/
│   └── GTA6_LAUNCH_GUIDE.md
├── game_scarlett_master.exe    <-- [120 MB Xbox Series S binary]
├── src/
└── README.md
```

### 2.3 Run Execution (Batch Mode)
Execute the binary through the AMD Zen 2 CPU interpreter:
```bash
# Run up to 100,000,000 instructions in batch mode
./build/scarlett_emu game_scarlett_master.exe --batch 100000000
```

---

## 3. Current Emulation Milestone: 91.5M+ Instructions

ScarlettEmu has cleanly executed **91,519,789 instructions** from cold boot, completing entire core engine bootstrap phases:

```
[INFO] [Core] ScarlettEmu subsystems initialized on Apple Silicon ARM64
[INFO] [Memory] Unified GDDR6 Virtual Memory initialized: 128 GB allocated
[INFO] [Loader] Ingesting 'game_scarlett_master.exe' (ImageBase: 0x140000000, Size: 0x7655000)
[INFO] [Loader] Resolving PE TLS Directory (RVA: 0x6e08b00, Size: 0x28)
[INFO] [Kernel] Registered HLE Hooks for DirectStorage, D3D12, CRT, and Synchronization
...
[INFO] [Interpreter] Executed 91,519,789 instructions cleanly
```

### Key Subsystems Implemented:

1. **PE Thread Local Storage (TLS) Handling:**
   - The RAGE engine heavily utilizes static thread-local variables (`__declspec(thread)`).
   - `PeLoader` parses `IMAGE_TLS_DIRECTORY64`, clears `AddressOfIndex` (`*0x146e08b2c = 0`), and deploys `.tls` raw template data into guest TEB structures (`gs:[0x58]`).
2. **Extended AVX / AVX2 CPU Instructions:**
   - Added Zen 2 vector instruction decoding and execution in `src/cpu/interpreter.cpp`:
     * `VPERMILPS` (VEX 0F 3A 04 /r ib)
     * `VPBLENDW` (VEX 0F 3A 0E /r ib)
     * `VPBLENDD` (VEX 0F 3A 02 /r ib)
     * `VMOVMSKPS` (256-bit YMM mask extraction)
3. **DirectStorage & XCRDAPI HLE:**
   - Intercepted `xcrdapi.dll!DStorageGetFactory` creating an `IDStorageFactory` COM bridge with 64 method slots.
4. **Xbox Direct3D 12 Device & Buffer Allocations:**
   - Intercepted `d3d12_xs.dll!D3D12XboxCreateDevice` provisioning an `ID3D12Device` interface.
   - Handled `ID3D12Device::CreateCommittedResource` (slot 73) reading arguments at `RSP + 0x30` and returning an `ID3D12Resource` proxy with virtual GPU memory buffers.

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
