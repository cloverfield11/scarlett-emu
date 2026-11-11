# ScarlettEmu: An Architectural Whitepaper and High-Level Emulation Framework for 9th-Generation Xbox (Project Scarlett) on Apple Silicon

[![Target Architecture](https://img.shields.io/badge/Target-Xbox%20Series%20S%20(Project%20Scarlett)-0e7a0d.svg)]()
[![Host Architecture](https://img.shields.io/badge/Host-Apple%20Silicon%20(ARM64)-000000.svg)]()
[![Graphics Backend](https://img.shields.io/badge/Graphics-Apple%20Metal%203-orange.svg)]()
[![Standard](https://img.shields.io/badge/Standard-ISO%20C%2B%2B20%20%2F%20Objective--C%2B%2B-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

---

## Abstract

**ScarlettEmu** is an experimental, clean-room systems-research runtime and high-level execution framework designed to investigate the feasibility of executing 9th-generation Xbox console binaries (specifically targeting the *Xbox Series S*, codenamed *Project Scarlett*) on Unix host platforms powered by Apple Silicon (ARM64). 

Modern 9th-generation video game consoles represent a convergence of specialized commodity hardware: an x86-64 AMD Zen 2 multicore central processing unit, an AMD RDNA 2 graphics processing unit, high-bandwidth unified GDDR6 memory, and a custom microkernel operating under a Type-1 hardware-enforced hypervisor. Bridging this execution environment to Apple Silicon requires synthesizing several disparate systems-level domains:

1. **Memory Virtualization:** Allocating and managing a 10 GB GDDR6 unified address space via POSIX memory primitives while enforcing guest 64 KB page-allocation granularities.
2. **Binary Parsing and Import Hooking:** Ingesting 64-bit Portable Executable (PE32+) binaries, decomposing section headers, and rewriting the guest Import Address Table (IAT) with dynamic machine-code trap stubs (`0x0F 0x0B` / `UD2`).
3. **Cross-ISA Dynamic Instruction Emulation:** Emulating an AMD Zen 2 CPU core, including general-purpose registers, RFLAGS condition code tracking, Microsoft x64 Fastcall calling conventions, and stack alignment semantics.
4. **Console Graphics API Translation:** Intercepting console-extended Direct3D 12.X interfaces (`d3d12_x.dll`) and translating graphics command queues to native Apple Metal pipelines (`MTLDevice`, `CAMetalLayer`) utilizing dynamically compiled Metal Shading Language (MSL) programs.

This whitepaper details the architectural design, formal mathematical and system models, kernel interception mechanics, graphics translation pathways, empirical verification, and current cryptographic boundaries of the project.

---

## Table of Contents

1. [Architectural Overview & Motivation](#1-architectural-overview--motivation)
2. [Target Hardware & System Architecture (Xbox Series S)](#2-target-hardware--system-architecture-xbox-series-s)
   - [2.1 CPU Topology: AMD Zen 2](#21-cpu-topology-amd-zen-2)
   - [2.2 Memory Topology: 10 GB GDDR6 Unified Bus](#22-memory-topology-10-gb-gddr6-unified-bus)
   - [2.3 Graphics Topology: AMD RDNA 2 & Direct3D 12.X](#23-graphics-topology-amd-rdna-2--direct3d-12x)
   - [2.4 Operating System Topology: NanoVisor & GameOS](#24-operating-system-topology-nanovisor--gameos)
3. [Host Hardware Architecture (Apple Silicon ARM64)](#3-host-hardware-architecture-apple-silicon-arm64)
   - [3.1 Host Memory Hierarchy](#31-host-memory-hierarchy)
   - [3.2 ISA Incompatibilities & Memory Consistency](#32-isa-incompatibilities--memory-consistency)
4. [ScarlettEmu System Implementation](#4-scarlettemu-system-implementation)
   - [4.1 Virtual Memory Manager (`MemoryManager`)](#41-virtual-memory-manager-memorymanager)
   - [4.2 PE32+ Binary Ingestion & IAT Trapping (`PeLoader`)](#42-pe32-binary-ingestion--iat-trapping-peloader)
   - [4.3 CPU Context & Instruction Interpreter (`Interpreter`)](#43-cpu-context--instruction-interpreter-interpreter)
   - [4.4 High-Level Operating System Emulation (`HleKernel`)](#44-high-level-operating-system-emulation-hlekernel)
   - [4.5 Direct3D 12.X to Apple Metal Bridge (`MetalRenderer`)](#45-direct3d-12x-to-apple-metal-bridge-metalrenderer)
5. [Empirical Verification: End-to-End Bootstrapping](#5-empirical-verification-end-to-end-bootstrapping)
   - [5.1 Guest Test Binary Authoring](#51-guest-test-binary-authoring)
   - [5.2 Execution Trace & State Dumps](#52-execution-trace--state-dumps)
6. [Security Architecture & Cryptographic Boundaries](#6-security-architecture--cryptographic-boundaries)
   - [6.1 The AMD Platform Security Processor (PSP)](#61-the-amd-platform-security-processor-psp)
   - [6.2 The MSIXVC Container Encryption Hierarchy](#62-the-msixvc-container-encryption-hierarchy)
7. [Future Research Directions](#7-future-research-directions)
8. [Building & Running](#8-building--running)
9. [License](#9-license)

---

## 1. Architectural Overview & Motivation

Modern console hardware has diverged from custom esoteric silicon (such as heterogeneous multi-core Cell architectures or vector-dominated coprocessors) toward customized desktop-adjacent system-on-chips (SoCs). While this convergence seemingly simplifies software emulation, modern 9th-generation systems introduce immense complexity at the hypervisor, operating system, and hardware-security layers.

```
+-----------------------------------------------------------------------------------+
|                           Target Binary (PE32+ / AMD64)                           |
+-----------------------------------------------------------------------------------+
        | (Memory Requests)                 | (System Calls)         | (GPU Pipelines)
        v                                   v                        v
+-----------------------+       +------------------------+  +-----------------------+
|  Memory Manager       |       |  HLE GameOS Kernel     |  |  Direct3D 12.X Hook   |
|  10 GB GDDR6 Address  |       |  - kernel32.dll        |  |  - d3d12_x.dll        |
|  Virtual Space        |       |  - ntdll / Durango     |  |  Interface Proxy      |
+-----------------------+       +------------------------+  +-----------------------+
        |                                   |                        |
        | (Pointer Translation)             | (C++ Fastcall Dispatch)| (Draw Commands)
        v                                   v                        v
+-----------------------------------------------------------------------------------+
|                        ScarlettEmu Core Dispatch Engine                           |
+-----------------------------------------------------------------------------------+
        |                                                            |
        v                                                            v
+-----------------------------------------------+   +-------------------------------+
|         Host POSIX Memory Subsystem           |   |   Apple Metal 3 Graphics      |
|    - Contiguous Virtual Pages                 |   |   - CAMetalLayer Render Target|
|    - 64 KB Granularity Bounds                 |   |   - MSL Pipeline State Objects|
+-----------------------------------------------+   +-------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
|                         Host Hardware: Apple Silicon (ARM64)                      |
|                  Unified Memory Architecture (UMA) + Apple GPU                    |
+-----------------------------------------------------------------------------------+
```

The objective of **ScarlettEmu** is to construct an execution vehicle capable of running unencrypted native Scarlett executables on Apple Silicon. Rather than simulating transistors or gate-level hardware (Low-Level Emulation, LLE), ScarlettEmu utilizes **High-Level Emulation (HLE)**: it intercepts the guest binary's operating system requests, graphics commands, and hardware allocations, translating them directly into equivalent host macOS primitives.

---

## 2. Target Hardware & System Architecture (Xbox Series S)

### 2.1 CPU Topology: AMD Zen 2
The computing core of the Xbox Series S is an AMD Zen 2 semi-custom processor fabricated on a 7nm node:
* **Cores / Threads:** 8 physical cores, 16 threads (running at 3.6 GHz nominal, or 3.4 GHz with Simultaneous Multi-Threading enabled).
* **Instruction Set:** x86-64 (AMD64) with architectural extensions: AVX, AVX2, SSE4.2, FMA3, BMI1, BMI2, and AES-NI.
* **Cache Hierarchy:** 32 KB L1 Instruction / 32 KB L1 Data cache per core; 512 KB dedicated L2 cache per core; 2x 4 MB shared L3 cache clusters.
* **Memory Consistency Model:** x86 Total Store Order (TSO), enforcing strong write ordering across memory buses.

### 2.2 Memory Topology: 10 GB GDDR6 Unified Bus
Unlike conventional personal computers featuring discrete pools of system DDR4/DDR5 RAM and dedicated graphics VRAM, the Series S utilizes a Unified Memory Architecture (UMA) over a 128-bit wide memory bus:
* **Physical Capacity:** 10 GB GDDR6 SDRAM.
* **Split Bandwidth Allocation:**
  * **Game Partition:** 8 GB running over the full bus delivering **224 GB/s** peak bandwidth (allocated for graphics buffers, assets, and engine state).
  * **System Partition:** 2 GB running over a reduced bus delivering **56 GB/s** peak bandwidth (reserved for the system OS, hypervisor, and background telemetry).
* **Address Space:** Unified 48-bit physical address map accessible concurrently by the CPU compute units and the GPU command processor without explicit PCIe bus transfers.

### 2.3 Graphics Topology: AMD RDNA 2 & Direct3D 12.X
Graphics rendering is performed by a customized AMD RDNA 2 engine:
* **Compute Units:** 20 CUs active (1280 stream processors) clocked at 1.565 GHz, generating approximately 4.0 TFLOPS of FP32 throughput.
* **Hardware Capabilities:** DirectX 12 Ultimate hardware feature set:
  * DirectX Raytracing (DXR Tier 1.1) via dedicated hardware Ray Accelerators.
  * Mesh Shading pipelines replacing traditional input assembler and geometry shader stages.
  * Variable Rate Shading (VRS Tier 2).
  * Sampler Feedback and DirectStorage high-throughput NVMe I/O streaming.
* **Driver Runtime:** **Direct3D 12.X** (`d3d12_x.dll`), a console-exclusive low-overhead variant of Direct3D 12 that bypasses consumer desktop Windows driver layers, providing direct push-buffer submission to GPU ring buffers.

### 2.4 Operating System Topology: NanoVisor & GameOS
The console operating environment is built upon a layered virtualization structure:
1. **NanoVisor (Type-1 Hypervisor):** Boots directly from secure ROM. Uses hardware SLAT (Second Level Address Translation) and IOMMU hardware isolation to enforce rigid separation between memory spaces.
2. **SystemOS (Shared Partition):** A stripped-down Windows 10/11 environment managing the dashboard, networking, media decoding, and peripheral telemetry.
3. **GameOS (Exclusive Partition):** A dedicated, zero-overhead OS instance loaded dynamically when a game is launched. It possesses exclusive ownership of the 8 GB GDDR6 partition and direct hardware access to GPU command processors.

---

## 3. Host Hardware Architecture (Apple Silicon ARM64)

### 3.1 Host Memory Hierarchy
Apple Silicon processors (M-series) share an essential design philosophy with modern consoles: **Unified Memory Architecture (UMA)**.
* On an Apple Silicon SoC, CPU performance cores, efficiency cores, the Apple GPU, and the Neural Engine all interface with a unified LPDDR5/LPDDR5X memory pool over an ultra-wide bus (ranging from 100 GB/s to over 800 GB/s depending on processor tier).
* This architectural similarity eliminates the need to mirror memory buffers across discrete host PCIe buses during emulation.

### 3.2 ISA Incompatibilities & Memory Consistency
Despite the shared unified memory concept, translating AMD Zen 2 to Apple Silicon presents fundamental microarchitectural divergence:
1. **Instruction Set Architecture (ISA):** x86-64 uses variable-length CISC instructions (1 to 15 bytes) with complex addressing modes; ARM64 uses fixed 32-bit RISC instructions.
2. **Memory Consistency:** x86-64 enforces **Total Store Order (TSO)**, where memory stores cannot pass previous stores or loads. ARM64 enforces a **Weak Memory Ordering** model, permitting out-of-order store and load coalescing unless explicit memory barriers (`DMB`, `DSB`) or acquire-release semantics are applied. Apple Silicon includes hardware TSO modes, which can be leveraged by translation software to maintain strict x86 synchronization.

---

## 4. ScarlettEmu System Implementation

### 4.1 Virtual Memory Manager (`MemoryManager`)
The memory subsystem is responsible for creating an emulation environment that satisfies the address requirements of GameOS.

```cpp
constexpr u64 GUEST_MEMORY_BASE = 0x0000000100000000ULL; // 4 GB Base Offset
constexpr u64 GUEST_MEMORY_SIZE = 0x0000000280000000ULL; // 10 GB Total Allocation
```

```
[Host Virtual Address Space]
+---------------------------------------------------------------------------+
| Host Address Space Base: 0x7000000000                                     |
+---------------------------------------------------------------------------+
  |
  +--> [Guest Offset 0x000000000] - 0x0001000000 : System Reserved (16 MB)
  |
  +--> [Guest Offset 0x0001000000] - 0x0002000000 : HLE Trampoline Pool (16 MB)
  |
  +--> [Guest Offset 0x0002000000] - 0x0040000000 : Dynamic Allocations (VirtualAlloc)
  |
  +--> [Guest Offset 0x0040000000] - 0x0140000000 : Game Partition Space
  |
  +--> [Guest Offset 0x0140000000] - 0x0140006000 : Mapped Executable Sections (.text, .rdata, .idata)
  |
  +--> [Guest Offset 0x0280000000] : 10 GB Boundary Limit
```

#### Key Implementation Characteristics:
* **Anonymous Virtual Allocation:** Allocates the full 10 GB unified block via `mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)`.
* **Granular Sub-allocations:** Sub-allocations (requested via the guest `VirtualAlloc` API) are managed with 64 KB alignment granularity matching the Windows memory manager specification.
* **Fast Translation Primitive:** Guest addresses are translated to host pointers via pointer arithmetic:
  $$\text{HostPointer} = \text{HostBase} + \text{GuestAddress}$$
  Bounds checks guarantee that requests outside the 10 GB address space trigger controlled fatal access violations rather than undefined host segmentation faults.

---

### 4.2 PE32+ Binary Ingestion & IAT Trapping (`PeLoader`)

In modern console software development kits, guest binaries are compiled into 64-bit Portable Executables (PE32+). The loader must parse and project this binary structure into the guest memory map.

#### Data Structures Parsed:
* **`DosHeader`:** Validates the initial `0x5A4D` (`MZ`) signature and extracts the relative offset `e_lfanew` pointing to the NT Header.
* **`FileHeader`:** Verifies the target machine specification: `0x8664` (`IMAGE_FILE_MACHINE_AMD64`).
* **`OptionalHeader64`:** Extracts the guest `ImageBase`, `AddressOfEntryPoint`, `SizeOfImage`, and the sixteen standard data directories.
* **`SectionHeaders`:** Iterates through every discrete section record, reading raw bytes from the file and projecting them to their target Relative Virtual Address (RVA):
  * `.text`: Guest machine code (mapped with executable attributes).
  * `.rdata`: Read-only constants, string tables, and runtime descriptors.
  * `.pdata` / `.xdata`: Structured exception handling tables and stack unwind specifications.
  * `.idata`: Import tables detailing external module references.

#### The Dynamic Trampoline Injection Mechanism
To achieve clean-room High-Level Emulation without requiring private Microsoft source headers or libraries, ScarlettEmu uses an **Import Address Table (IAT) Trampoline Engine**:

```
[Guest Machine Code]
      |
      | call *0x403c(%rip)  --> Reads IAT Table Entry at 0x140005080
      v
[Patched IAT Table]
  0x140005080 : Points to Guest Address 0x150000020
      |
      v
[Dynamically Injected Trampoline at 0x150000020]
  +--------+--------+-------------------+--------+
  |  0x0F  |  0x0B  |  Hook ID (4 Bytes)|  0xC3  |
  +--------+--------+-------------------+--------+
   [   UD2 Trap   ]  [  0x00000003     ]  [ RET  ]
      |
      v
[Interpreter Trap Handler]
  1. Identifies Hook ID = 3
  2. Resolves Symbol: "d3d12_x.dll!D3D12CreateDevice"
  3. Executes Native C++ Handler: Scarlett::Modules::D3D12CreateDevice()
  4. Stores Return Value in RAX
  5. Pops Return Address from Guest Stack
  6. Resumes Guest Instruction Stream
```

---

### 4.3 CPU Context & Instruction Interpreter (`Interpreter`)

Execution of the guest binary's initial instructions is conducted by an instruction decoder and interpreter designed around the AMD Zen 2 CPU architecture.

```cpp
struct alignas(16) CpuContext {
    u64 rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    u64 r8, r9, r10, r11, r12, r13, r14, r15;
    u64 rip, rflags;
    struct { u64 qwords[4]; } ymm[16]; // 256-bit AVX2 Registers
};
```

#### Instruction Decoder Logic:
The decoder accepts raw byte sequences from guest memory and decodes the variable-length x86-64 format:
1. **Legacy & Prefix Decoding:**
   * Tracks and consumes `0x66` (Operand-size override).
   * Consumes `0x2E` (Segment CS override / branch hint).
   * Detects REX prefixes (`0x40` through `0x4F`):
     * $\text{REX.W} = (\text{Byte} \ \& \ 0x08) \neq 0$ (Signals 64-bit operand sizes).
     * $\text{REX.R} = (\text{Byte} \ \& \ 0x04) \ ? \ 8 : 0$ (Modifies ModR/M `reg` field).
     * $\text{REX.B} = (\text{Byte} \ \& \ 0x01) \ ? \ 8 : 0$ (Modifies ModR/M `r/m` field).
2. **Opcode Classification:**
   * `0x31`: Register-to-register `XOR` (sets Zero Flag in `RFLAGS` when destination is zeroed).
   * `0x89` / `0x8B`: General register moves.
   * `0xB8 - 0xBF`: Immediate moves into 32-bit or 64-bit registers.
   * `0xC7`: Immediate moves into memory addresses:
     $$\text{TargetAddress} = \text{BaseRegister} + \text{Displacement}$$
   * `0x85`: Bitwise `TEST` operations configuring `RFLAGS.ZF`.
   * `0x74` / `0x75`: Relative 8-bit conditional branches (`JE` / `JNE`).
   * `0x0F 0x84` / `0x0F 0x85`: Relative 32-bit conditional branches.
   * `0xE8` / `0xC3`: Direct subroutine `CALL` and `RET`.
   * `0xFF /2`: Indirect near call (`CALL [rip + displacement]`).
   * `0x0F 0x0B`: **HLE Trap Stub (`UD2`)**.

---

### 4.4 High-Level Operating System Emulation (`HleKernel`)

The HLE subsystem captures guest operating system interactions, executing them as native host operations without executing guest kernel code.

#### Key Trapped Function Implementations:

| Module | Function Name | Guest Signature | Implemented Host Action |
| :--- | :--- | :--- | :--- |
| `kernel32.dll` | `VirtualAlloc` | `(lpAddress, dwSize, flAllocType, flProtect)` | Allocates aligned blocks in the 10 GB GDDR6 virtual space; returns guest base pointer in `RAX`. |
| `kernel32.dll` | `ExitProcess` | `(uExitCode)` | Logs terminal guest telemetry and terminates interpreter execution cleanly. |
| `kernel32.dll` | `QueryPerformanceCounter` | `(lpPerformanceCount)` | Bridges to macOS `mach_absolute_time()` to provide monotonic guest timing. |
| `kernel32.dll` | `QueryPerformanceFrequency`| `(lpFrequency)` | Returns standardized 10 MHz Xbox hardware timer frequency. |
| `d3d12_x.dll` | `D3D12CreateDevice` | `(pAdapter, FeatureLevel, riid, ppDevice)` | Initializes the Metal graphics renderer, spawns the Cocoa window, creates device proxies. |

---

### 4.5 Direct3D 12.X to Apple Metal Bridge (`MetalRenderer`)

Direct3D 12 and Apple Metal share low-level architectural paradigms: explicit memory management, precompiled pipeline state objects (PSOs), and command list encoding into command queues.

#### Presentation Architecture:
1. **Window Host Lifecycle:** When `D3D12CreateDevice` is triggered, the graphics subsystem initializes the `NSApplication` runloop, creates a 1280x720 centered `NSWindow`, and attaches an active `CAMetalLayer`.
2. **Dynamic Shader Compilation:** The runtime compiles an embedded Metal Shading Language (MSL) shader program through `newLibraryWithSource:options:error:`.
3. **Pipeline State Object (PSO):** Connects the vertex stage (`vertex_main`) and the fragment stage (`fragment_main`) with standard `MTLPixelFormatBGRA8Unorm` surface targets.
4. **Command Buffer Encoding:** Every frame acquires the next `CAMetalDrawable`, constructs an `MTLRenderPassDescriptor`, and records the draw primitives:

$$\text{DrawPrimitives}(\text{MTLPrimitiveTypeTriangle}, \text{Start}: 0, \text{Count}: 3)$$

```metal
#include <metal_stdlib>
using namespace metal;

struct VertexOut {
    float4 position [[position]];
    float4 color;
};

vertex VertexOut vertex_main(uint vid [[vertex_id]]) {
    const float2 positions[3] = {
        float2( 0.0,  0.65),
        float2(-0.65, -0.65),
        float2( 0.65, -0.65)
    };
    const float4 colors[3] = {
        float4(0.06f, 0.85f, 0.22f, 1.0f), // Signature Xbox Green
        float4(0.20f, 0.60f, 1.00f, 1.0f), // Neon Blue
        float4(1.00f, 0.20f, 0.40f, 1.0f)  // Cyber Pink
    };
    VertexOut out;
    out.position = float4(positions[vid], 0.0, 1.0);
    out.color = colors[vid];
    return out;
}

fragment float4 fragment_main(VertexOut in [[stage_in]]) {
    return in.color;
}
```

---

## 5. Empirical Verification: End-to-End Bootstrapping

### 5.1 Guest Test Binary Authoring
To prove execution through all layers, a standalone C executable was authored (`samples/demo_game.c`), compiled targeting AMD64 without standard C runtime bloat (`-nostartfiles`):

```c
#include <windows.h>

__declspec(dllimport) long D3D12CreateDevice(void* pAdapter, int minFeatureLevel, void* riid, void** ppDevice);

void EntryPoint() {
    // 1. Request 1 MB from the 10 GB GDDR6 Unified RAM
    void* buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 2. Initialize Direct3D 12.X Console Device & Display Surface
    void* pD3DDevice = NULL;
    D3D12CreateDevice(NULL, 0x12000, NULL, &pD3DDevice);

    // 3. Terminate GameOS session gracefully
    ExitProcess(0);
}
```

Import libraries for the custom console driver were synthesized using `dlltool`:

```bash
# Generate import library for custom Scarlett graphics runtime
x86_64-w64-mingw32-dlltool -d samples/d3d12_x.def -l samples/libd3d12_x.a

# Compile guest PE32+ AMD64 binary
x86_64-w64-mingw32-gcc -O1 -nostartfiles -e EntryPoint \
    -o samples/demo_game.exe samples/demo_game.c \
    -Lsamples -ld3d12_x -lkernel32
```

### 5.2 Execution Trace & State Dumps

Running `./build/scarlett_emu samples/demo_game.exe` outputs the execution trace:

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
[DEBUG] [Memory] Allocated 0x1000000 bytes at GuestAddr 0x1000000
[DEBUG] [Kernel] Registered HLE Hook: kernel32.dll -> ExitProcess
[DEBUG] [Kernel] Registered HLE Hook: kernel32.dll -> VirtualAlloc
[DEBUG] [Kernel] Registered HLE Hook: d3d12_x.dll -> D3D12CreateDevice
[INFO] [Core] Loading Scarlett target binary: samples/demo_game.exe
[INFO] [Loader] Loaded file size: 7154 bytes
[INFO] [Loader] Valid Scarlett PE32+ binary detected:
  Image Base: 0x140000000
  Entry Point RVA: 0x1000 (Virt: 0x140001000)
  Size of Image: 0x6000 (18 KB)
  Number of Sections: 5

[INFO] [Loader] Mapping PE sections into guest virtual memory space...
[DEBUG] [Memory] Allocated 0x10000 bytes at GuestAddr 0x140000000
[DEBUG] [Loader]   Mapped section '.text' at 0x140001000 (Size: 0x70, Prot: 3)
[DEBUG] [Loader]   Mapped section '.rdata' at 0x140002000 (Size: 0x40, Prot: 1)
[DEBUG] [Loader]   Mapped section '.pdata' at 0x140003000 (Size: 0xc, Prot: 1)
[DEBUG] [Loader]   Mapped section '.xdata' at 0x140004000 (Size: 0x8, Prot: 1)
[DEBUG] [Loader]   Mapped section '.idata' at 0x140005000 (Size: 0xec, Prot: 1)

[INFO] [Loader] Resolving Scarlett GameOS Import Address Table (IAT)...
[DEBUG] [Memory] Allocated 0x10000 bytes at GuestAddr 0x150000000
[INFO] [Loader]   Importing module: KERNEL32.dll
[DEBUG] [Loader]     [IAT 0x140005068] -> KERNEL32.dll!ExitProcess (Trampoline: 0x150000000)
[DEBUG] [Loader]     [IAT 0x140005070] -> KERNEL32.dll!VirtualAlloc (Trampoline: 0x150000010)
[INFO] [Loader]   Importing module: d3d12_x.dll
[DEBUG] [Loader]     [IAT 0x140005080] -> d3d12_x.dll!D3D12CreateDevice (Trampoline: 0x150000020)
[INFO] [Loader] Successfully resolved 3 IAT import functions.

[INFO] [Core] Dispatching to Entry Point: 0x140001000
[DEBUG] [CPU] 
--- CPU State (Zen 2 x86_64) ---
RIP: 0x0000000140001000  RFLAGS: 0x00000000
RAX: 0x0000000000000000  RBX: 0x0000000000000000
RCX: 0x0000000000000000  RDX: 0x0000000000000000
RBP: 0x0000000000000000  RSP: 0x0000000100800000

[INFO] [Interpreter] Entering x86-64 Zen 2 execution loop...
[DEBUG] [Interpreter] CallIndirect: reading IAT from 0x140005070 -> target: 0x150000010
[DEBUG] [Interpreter] HLE Trap triggered! HookID = 2
[INFO] [HLE] Dispatching GameOS Call: KERNEL32.dll!VirtualAlloc
[DEBUG] [Memory] Allocated 0x100000 bytes at GuestAddr 0x2000000
[DEBUG] [Kernel32] VirtualAlloc called: Size=0x1048576 -> 0x33554432

[DEBUG] [Interpreter] CallIndirect: reading IAT from 0x140005080 -> target: 0x150000020
[DEBUG] [Interpreter] HLE Trap triggered! HookID = 3
[INFO] [HLE] Dispatching GameOS Call: d3d12_x.dll!D3D12CreateDevice
[INFO] [D3D12X] D3D12CreateDevice called! Requested Feature Level: 0x12000
[INFO] [GPU] Cocoa Window & Metal Render Pipeline successfully activated on screen!
[DEBUG] [Memory] Allocated 0x10000 bytes at GuestAddr 0x2100000
[INFO] [D3D12X] Bridged D3D12 Device allocated to Metal translation layer

[DEBUG] [Interpreter] CallIndirect: reading IAT from 0x140005068 -> target: 0x150000000
[DEBUG] [Interpreter] HLE Trap triggered! HookID = 1
[INFO] [HLE] Dispatching GameOS Call: KERNEL32.dll!ExitProcess
[INFO] [Kernel32] Game requested ExitProcess with code: 0
[INFO] [Interpreter] Execution halted after 22 instructions.
[INFO] [Core] Entering Metal graphics presentation loop (Close window or press ESC to exit)...
```

---

## 6. Security Architecture & Cryptographic Boundaries

A rigorous evaluation of console emulation requires analyzing the security boundaries that prevent arbitrary binary execution.

```
+-----------------------------------------------------------------------------------+
|                        Physical Security Boundary (AMD SoC)                       |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                 AMD Platform Security Processor (PSP / Cortex-A5)           |  |
|  |  - Immutable On-Die BootROM                                                 |  |
|  |  - Fused Master Root Key (HMAC / RSA-4096 / AES-256)                        |  |
|  |  - Cryptographic Signature Verification of Bootloaders & OS Images          |  |
|  +-----------------------------------------------------------------------------+  |
|                                         | (Validates Hash Chain)                  |
|                                         v                                         |
|  +-----------------------------------------------------------------------------+  |
|  |                 Microsoft NanoVisor (Type-1 Hypervisor)                     |  |
|  |  - Hardware Memory Encryption (AES-XTS Engine)                              |  |
|  |  - Virtual Machine Protection (SLAT / IOMMU Partition Isolation)            |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
                                          |
                                          | (Enforces Package Decryption)
                                          v
+-----------------------------------------------------------------------------------+
|                        Container Distribution Boundary (.msixvc)                  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Package Root Block: SHA256 Block Tree Hash                                  |  |
|  +-----------------------------------------------------------------------------+  |
|  | Virtual Hard Disk Volume (XBFS - Xbox Boot File System)                     |  |
|  | - Encrypted with Per-Content AES-XTS-128 Keys                               |  |
|  | - Dynamic License Blocks Delivered via Ephemeral Xbox Live Tickets          |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

### 6.1 The AMD Platform Security Processor (PSP)
The hardware root-of-trust in the Series S is anchored by an integrated AMD PSP (an isolated ARM Cortex-A5 secure coprocessor embedded directly into the central silicon die). The PSP executes immutable microcode from an internal read-only mask ROM upon cold boot, validating the cryptographic integrity of early-stage bootloaders before release from reset. 

Because master cryptographic certificates are fused permanently into non-volatile on-die registers, public extraction of root decryption keys has never been achieved across the 8th or 9th console generations.

### 6.2 The MSIXVC Container Encryption Hierarchy
Commercial games distributed through digital endpoints are delivered within encrypted virtual container files (`.msixvc`). 
* The container acts as a virtual block device governed by the Xbox Boot File System (XBFS).
* Every individual 64 KB cluster is encrypted using AES-XTS-128.
* The keys required to derive the sector key are not stored on local disks; they are negotiated on-demand during license acquisition through authenticated Xbox Live security protocols.
* **Conclusion:** Outside of unencrypted homebrew or developer binaries compiled with standard Microsoft Game Development Kit (GDK) test suites, commercial retail binaries cannot be decrypted without physical console compromise.

---

## 7. Future Research Directions

1. **Dynamic Binary Translation (JIT):** Replacing the scalar instruction interpreter with an optimizing Just-In-Time (JIT) compiler emitting native ARM64 instructions directly into executable memory pages, utilizing `pthread_jit_write_protect` on macOS.
2. **DXIL Shader Intermediate Translation:** Parsing the LLVM-derived DirectX Intermediate Language (DXIL) byte-streams present in Scarlett Direct3D 12 pipelines and decompiling them into Metal Shading Language (MSL) intermediate representations.
3. **Multithreaded Fiber Scheduling:** Modeling the Durango/Scarlett asynchronous task scheduler via POSIX user threads (`pthreads`) mapped directly to Apple Silicon efficiency and performance clusters.

---

## 8. Building & Running

### System Requirements:
* **Host Hardware:** Apple Silicon Mac (M1, M2, M3, M4, M5 series).
* **Operating System:** macOS Ventura (13.0) or higher.
* **Build System:** CMake 3.20+ and Apple Clang (supporting C++20 and Objective-C++20).
* **Cross-Compiler (Optional):** `mingw-w64` for assembling test guest targets (`brew install mingw-w64`).

### Build Instructions:
```bash
# 1. Clone the project repository
git clone https://github.com/cloverfield11/useless-xbox-emulator.git
cd useless-xbox-emulator

# 2. Configure build environment with CMake
cmake -B build -S .

# 3. Compile the emulator
cmake --build build -j$(sysctl -n hw.ncpu)
```

### Running Test Harnesses:
```bash
# Execute internal processor and memory simulation
./build/scarlett_emu

# Launch the compiled AMD64 guest harness with Apple Metal graphics output
./build/scarlett_emu samples/demo_game.exe
```

---

## 9. License

This research framework is distributed under the terms of the **MIT License**.

```
Copyright (c) 2026 ScarlettEmu Systems Research Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```
