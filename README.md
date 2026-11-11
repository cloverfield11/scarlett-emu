# ScarlettEmu: An Experimental High-Level Emulation (HLE) Framework for 9th-Generation Xbox Architecture on Apple Silicon

[![Platform](https://img.shields.io/badge/Platform-macOS%20ARM64-black.svg)]()
[![Target](https://img.shields.io/badge/Target-AMD%20Zen%202%20%7C%20RDNA2-green.svg)]()
[![Backend](https://img.shields.io/badge/Graphics-Apple%20Metal-orange.svg)]()
[![Language](https://img.shields.io/badge/Standard-C%2B%2B20%20%2F%20ObjC%2B%2B-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

---

## Abstract

**ScarlettEmu** is an experimental systems-research project and compatibility runtime designed to explore the feasibility of High-Level Emulation (HLE) for the 9th-generation Microsoft Xbox console architecture (codenamed *Project Scarlett* / *Xbox Series S*) on host Unix platforms powered by ARM64-based Apple Silicon.

The project investigates four core architectural paradigms:
1. **Unified Memory Virtualization:** Simulating the 10 GB GDDR6 unified address space of the Series S with 48-bit virtual addressing and POSIX page-table controls.
2. **Dynamic PE32+ (AMD64) Ingestion & IAT Trapping:** Clean-room parsing of 64-bit Windows GameOS PE binaries, resolving imported runtime libraries (`kernel32.dll`, `d3d12_x.dll`), and generating runtime trampoline traps (`UD2` / `0x0F 0x0B`).
3. **Cross-ISA Execution Semantics:** Emulating AMD Zen 2 (x86-64) register files, stack semantics, and the Microsoft x64 Fastcall ABI on Apple Silicon.
4. **Console Graphics Interception:** Intercepting console-extended Direct3D 12.X interfaces and mapping hardware command queues directly to native **Apple Metal** pipelines (`MTLDevice`, `CAMetalLayer`) with embedded Metal Shading Language (MSL) compilation.

---

## Academic Disclaimer & Research Scope

> ⚠️ **RESEARCH & FEASIBILITY NOTICE:**  
> This project is strictly an **educational systems-research implementation**. It is **not** a plug-and-play emulator capable of running commercial, DRM-protected retail titles. 
> 
> Retail Xbox Series packages (`.msixvc`) are cryptographically sealed with hardware-bound AES-XTS keys governed by the AMD Platform Security Processor (PSP) root-of-trust and Microsoft's Type-1 *NanoVisor* hypervisor. As these hardware security boundaries have not been compromised publicly, commercial titles (e.g., *Grand Theft Auto VI*) cannot be decrypted or executed. 
> 
> The purpose of this repository is to demonstrate how modern HLE compatibility layers (comparable to *shadPS4*, *Wine*, and *Box64*) can bridge guest console operating system abstractions to macOS hardware.

---

## Architectural Taxonomy

```
+-----------------------------------------------------------------+
|                   Guest Game Binary (PE32+ / x86-64)            |
+-----------------------------------------------------------------+
               |                                     |
               | (Syscalls / API calls)              | (Draw calls)
               v                                     v
+-------------------------------+   +-----------------------------+
|    HLE GameOS Kernel Hook     |   |    Direct3D 12.X (Scarlett) |
|   (VirtualAlloc, Timers, etc) |   |    Hook & Interface Proxy   |
+-------------------------------+   +-----------------------------+
               |                                     |
               | (Host Dispatch)                     | (Pipeline Translation)
               v                                     v
+-------------------------------+   +-----------------------------+
| Memory Manager (10 GB GDDR6)  |   | Apple Metal Graphics Backend|
|  POSIX mmap Virtual Space     |   |  CAMetalLayer + Cocoa Window|
+-------------------------------+   +-----------------------------+
                               |
                               v
               +-------------------------------+
               |   Host Hardware (Apple Silicon)|
               |    M-Series Unified RAM & GPU |
               +-------------------------------+
```

### 1. Memory Subsystem (`src/cpu/memory_manager.cpp`)
The Xbox Series S features a 10 GB GDDR6 unified memory pool shared symmetrically between CPU and GPU partitions (8 GB high-bandwidth game partition + 2 GB system partition).
* ScarlettEmu reserves a contiguous 10 GB (0x280000000 bytes) virtual address space using anonymous private virtual memory allocations (`mmap`).
* Memory granularities adhere to standard 64 KB Windows/GameOS allocation boundaries, providing fine-grained page protection translation (`mprotect`) compatible with guest expectations.

### 2. Binary Loader & IAT Trampolines (`src/loader/pe_loader.cpp`)
Xbox executables packaged in development environments follow the PE32+ (64-bit Portable Executable) specification.
* The loader parses DOS (`MZ`), COFF, and Optional Headers, verifying the `0x8664` (AMD64) machine signature.
* Sections (`.text`, `.rdata`, `.pdata`, `.idata`) are projected into the guest virtual memory space according to their Relative Virtual Addresses (RVA).
* **Import Address Table (IAT) Hooking:** The loader traverses the `IMAGE_DIRECTORY_ENTRY_IMPORT` descriptors for target modules (`KERNEL32.dll`, `d3d12_x.dll`). It generates in-memory stub trampolines using the `0x0F 0x0B` (`UD2`) undefined instruction followed by a 32-bit Hook Identifier, dynamically rewriting IAT entries to point to these trampolines.

### 3. CPU Execution & HLE Trapping (`src/cpu/interpreter.cpp`)
* Implements a scalar x86-64 instruction decoder supporting REX prefixes (`0x40-0x4F`), operand-size overrides (`0x66`), segment overrides (`0x2E`), and standard integer arithmetic, jumps, and stack manipulations.
* When execution reaches an IAT trampoline, the engine traps `0x0F 0x0B`, reads the hook ID, dispatches the registered C++ handler (e.g., allocating memory or initializing a graphics device), pushes the return address, and transparently resumes guest execution.

### 4. Direct3D 12.X to Apple Metal Bridge (`src/gpu/metal_renderer.mm`)
* Intercepts `d3d12_x.dll!D3D12CreateDevice`.
* Instantiates an active macOS Cocoa rendering surface (`NSWindow` + `CAMetalLayer`) on Apple Silicon.
* Initializes the host `MTLDevice`, creates command queues, and dynamically compiles embedded **Metal Shading Language (MSL)** shader pipelines to render hardware frames at 60 FPS.

---

## Verification & Empirical Results

To validate the emulation pipeline, a clean-room AMD64 test harness (`samples/demo_game.c`) was authored, cross-compiled with `x86_64-w64-mingw32-gcc`, and linked against custom Scarlett GDK import definitions (`samples/libd3d12_x.a`):

```bash
# Compilation of guest target binary
x86_64-w64-mingw32-gcc -O1 -nostartfiles -e EntryPoint \
    -o samples/demo_game.exe samples/demo_game.c \
    -Lsamples -ld3d12_x -lkernel32
```

### Execution Trace:

```
========================================================
    ScarlettEmu - Xbox Series S Emulator / HLE (macOS)  
    Target: AMD Zen 2 (x86_64) + RDNA2 -> Apple Metal   
    Version: 0.1.0-indev                        
========================================================

[INFO] [Core] Starting ScarlettEmu subsystems on macOS ARM64...
[INFO] [Memory] Unified GDDR6 Virtual Memory initialized: 10 GB allocated at host address 0x7000000000
[INFO] [GPU] Metal Hardware initialized: Apple M5
[INFO] [GPU] Target Render Surface: 1920x1080
[INFO] [Kernel] Initializing Xbox GameOS HLE subsystem...
[INFO] [Core] Loading Scarlett target binary: samples/demo_game.exe
[INFO] [Loader] Valid Scarlett PE32+ binary detected:
  Image Base: 0x140000000
  Entry Point RVA: 0x1000 (Virt: 0x140001000)
  Size of Image: 0x6000 (18 KB)
  Number of Sections: 5

[INFO] [Loader] Resolving Scarlett GameOS Import Address Table (IAT)...
[DEBUG] [Loader]   [IAT 0x140005068] -> KERNEL32.dll!ExitProcess (Trampoline: 0x150000000)
[DEBUG] [Loader]   [IAT 0x140005070] -> KERNEL32.dll!VirtualAlloc (Trampoline: 0x150000010)
[DEBUG] [Loader]   [IAT 0x140005080] -> d3d12_x.dll!D3D12CreateDevice (Trampoline: 0x150000020)
[INFO] [Loader] Successfully resolved 3 IAT import functions.

[INFO] [Interpreter] Entering x86-64 Zen 2 execution loop...
[DEBUG] [Interpreter] CallIndirect: reading IAT from 0x140005070 -> target: 0x150000010
[DEBUG] [Interpreter] HLE Trap triggered! HookID = 2
[INFO] [HLE] Dispatching GameOS Call: KERNEL32.dll!VirtualAlloc
[DEBUG] [Memory] Allocated 0x100000 bytes at GuestAddr 0x2000000

[DEBUG] [Interpreter] CallIndirect: reading IAT from 0x140005080 -> target: 0x150000020
[DEBUG] [Interpreter] HLE Trap triggered! HookID = 3
[INFO] [HLE] Dispatching GameOS Call: d3d12_x.dll!D3D12CreateDevice
[INFO] [GPU] Cocoa Window & Metal Render Pipeline successfully activated on screen!
[DEBUG] [Memory] Allocated 0x10000 bytes at GuestAddr 0x2100000
[INFO] [D3D12X] Bridged D3D12 Device allocated to Metal translation layer

[DEBUG] [Interpreter] CallIndirect: reading IAT from 0x140005068 -> target: 0x150000000
[DEBUG] [Interpreter] HLE Trap triggered! HookID = 1
[INFO] [HLE] Dispatching GameOS Call: KERNEL32.dll!ExitProcess
[INFO] [Kernel32] Game requested ExitProcess with code: 0
[INFO] [Core] Entering Metal graphics presentation loop (Close window or press ESC to exit)...
```

---

## Building and Running

### Prerequisites:
* Host: Apple Silicon Mac (M1 through M5) running macOS 13+
* Toolchain: Xcode Command Line Tools (`clang++`), CMake 3.20+
* (Optional) `mingw-w64` for compiling test guest executables: `brew install mingw-w64`

### Build Pipeline:
```bash
# Clone the repository
git clone https://github.com/cloverfield11/useless-xbox-emulator.git
cd useless-xbox-emulator

# Configure and compile
cmake -B build -S .
cmake --build build -j$(sysctl -n hw.ncpu)
```

### Execution:
```bash
# Run verification test payload
./build/scarlett_emu

# Run compiled guest binary with active Metal rendering window
./build/scarlett_emu samples/demo_game.exe
```

---

## Future Research Directions

1. **JIT Compilation (Dynamic Binary Translation):** Transitioning from the scalar interpreter to an LLVM-based JIT or AsmJit backend to emit native ARM64 instructions with Rosetta-comparable throughput.
2. **DXIL to Metal Intermediate Representation Translation:** Developing a bytecode parser for DirectX Intermediate Language (DXIL / LLVM bitcode derivative) to transpile guest compute and pixel shaders into MSL.
3. **XBFS & Container Storage Exploration:** Researching the Xbox Boot File System (XBFS) and decrypting unencrypted Developer Mode side-loaded packages.

---

## License

This software is released under the **MIT License**. Created strictly for academic curiosity and systems research.
