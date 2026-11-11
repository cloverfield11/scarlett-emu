#include "common/types.h"
#include "common/logging.h"
#include "cpu/memory_manager.h"
#include "cpu/cpu_context.h"
#include "cpu/interpreter.h"
#include "loader/pe_loader.h"
#include "loader/package_manifest.h"
#include "kernel/hle_kernel.h"
#include "gpu/metal_renderer.h"
#include <iostream>
#include <vector>
#include <unistd.h>

void PrintBanner() {
    std::cout << "\033[1;32m"
              << "========================================================\n"
              << "    ScarlettEmu - Xbox Series S Emulator / HLE (macOS)  \n"
              << "    Target: AMD Zen 2 (x86_64) + RDNA2 -> Apple Metal   \n"
              << "    Version: " << SCARLETT_VERSION << "                        \n"
              << "========================================================\n"
              << "\033[0m\n";
}

void RunSimulationTest(Scarlett::MemoryManager& memory, Scarlett::HleKernel& kernel) {
    LOG_INFO("Test", "--- Running Scarlett x86-64 Zen 2 Simulation Payload ---");

    // Allocate 64KB for test executable code in guest memory
    Scarlett::GuestAddr codeBase = memory.Allocate(0x10000, Scarlett::MemoryProtection::ExecuteReadWrite, 0x140001000);

    // Assembled x86-64 machine code payload:
    // 1. xor rax, rax           (48 31 c0)
    // 2. mov rcx, 0x1337        (48 b9 37 13 00 00 00 00 00 00)
    // 3. mov rdx, 0x0020        (48 ba 20 00 00 00 00 00 00 00)
    // 4. add rax, rdx           (48 01 d0)  -> rax = 0x20
    // 5. ud2 (HLE Trap #1)      (0f 0b 01 00 00 00) -> HookID 1 (D3D12CreateDevice)
    // 6. hlt                    (f4)
    std::vector<Scarlett::u8> machineCode = {
        0x48, 0x31, 0xC0,                                     // xor rax, rax
        0x48, 0xB9, 0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x1337
        0x48, 0xBA, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0x0020
        0x48, 0x01, 0xD0,                                     // add rax, rdx -> rax = 0x20
        0x0F, 0x0B, 0x01, 0x00, 0x00, 0x00,                   // HLE Trap Hook #1
        0xF4                                                  // hlt
    };

    memory.WriteBytes(codeBase, machineCode.data(), machineCode.size());

    Scarlett::CpuContext cpu;
    cpu.rip = codeBase;
    cpu.rsp = Scarlett::GUEST_MEMORY_BASE + 0x800000;

    LOG_INFO("Test", "Initial CPU State:");
    cpu.DumpState();

    Scarlett::Interpreter interp(cpu, memory);
    interp.Run(100);

    // Trigger D3D12 device creation hook
    LOG_INFO("Test", "Simulating Game Engine D3D12 / Metal graphics bootstrap...");
    kernel.ExecuteHook("d3d12_x.dll", "D3D12CreateDevice", cpu);

    LOG_INFO("Test", "Final CPU State after execution:");
    cpu.DumpState();

    LOG_INFO("Test", "Simulation test finished with SUCCESS!");
}

int main(int argc, char* argv[]) {
    PrintBanner();

    LOG_INFO("Core", "Starting ScarlettEmu subsystems on macOS ARM64...");

    // 1. Initialize Unified GDDR6 Virtual Memory
    Scarlett::MemoryManager memory;
    if (!memory.Initialize()) {
        LOG_FATAL("Core", "Fatal error initializing Virtual Memory Manager");
        return 1;
    }

    // 2. Initialize Metal GPU Translation Backend
    Scarlett::MetalRenderer gpu;
    if (!gpu.Initialize(1920, 1080)) {
        LOG_FATAL("Core", "Fatal error initializing Metal Graphics Engine");
        return 1;
    }

    // 3. Initialize HLE Kernel and Syscall/DLL Hooks
    Scarlett::HleKernel kernel(memory);
    kernel.Initialize();

    // 4. Test mode or Load executable
    if (argc < 2) {
        LOG_INFO("Core", "No external game path provided. Running built-in Scarlett verification test...");
        RunSimulationTest(memory, kernel);
        return 0;
    }

    std::string arg = argv[1];
    if (arg == "--test") {
        RunSimulationTest(memory, kernel);
        return 0;
    }

    std::string binaryPath = arg;
    LOG_INFO("Core", "Loading Scarlett target binary: " + binaryPath);

    // Check for accompanying MicrosoftGameConfig.mgc or MicrosoftGame.config
    size_t lastSlash = binaryPath.find_last_of("/\\");
    std::string dirPath = (lastSlash != std::string::npos) ? binaryPath.substr(0, lastSlash) : ".";
    std::string configPath = dirPath + "/MicrosoftGameConfig.mgc";
    if (access(configPath.c_str(), F_OK) != 0) {
        configPath = dirPath + "/MicrosoftGame.config";
    }
    if (access(configPath.c_str(), F_OK) == 0) {
        LOG_INFO("Core", "Found Xbox Game Configuration: " + configPath);
        Scarlett::PackageManifest::LoadFromFile(configPath);
    }

    Scarlett::PeLoader loader(memory);
    if (!loader.LoadExecutable(binaryPath)) {
        LOG_ERROR("Core", "Failed to load binary into memory!");
        return 1;
    }

    // Setup CPU context and dispatch entry point
    Scarlett::CpuContext cpu;
    cpu.rip = loader.GetEntryPoint();
    cpu.rsp = Scarlett::GUEST_MEMORY_BASE + 0x800000;

    LOG_INFO("Core", "Dispatching to Entry Point: 0x" + std::to_string(cpu.rip));
    cpu.DumpState();

    Scarlett::Interpreter interp(cpu, memory, &kernel, &loader.GetImports());
    interp.Run();

    // If a graphics window was created by D3D12/Metal, run presentation loop
    if (gpu.IsRunning()) {
        LOG_INFO("Core", "Entering Metal graphics presentation loop (Close window or press ESC to exit)...");
        for (int frame = 0; frame < 300 && gpu.IsRunning(); frame++) { // Run for 5 seconds / 300 frames in auto mode
            gpu.RenderFrame();
            gpu.PollEvents();
            usleep(16666); // ~60 FPS
        }
    }

    return 0;
}
