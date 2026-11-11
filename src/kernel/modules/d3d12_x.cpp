#include "kernel/modules/d3d12_x.h"
#include "gpu/metal_renderer.h"
#include "common/logging.h"

namespace Scarlett::Modules {

void RegisterD3D12X(HleKernel& kernel) {
    auto createDeviceHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr pAdapter = ctx.rcx;
        u32 featureLevel = static_cast<u32>(ctx.rdx);
        GuestAddr riid = ctx.r8;
        GuestAddr ppDevice = ctx.r9;

        LOG_INFO("D3D12X", "D3D12CreateDevice called! Requested Feature Level: 0x" + std::to_string(featureLevel));

        // Connect and activate the Metal GPU rendering window on macOS
        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->CreateWindowAndPipeline();
            // Render initial boot frame
            renderer->RenderFrame();
            renderer->PollEvents();
        }

        // Return a mock D3D12 Device interface handle
        if (ppDevice) {
            GuestAddr mockDevice = mem.Allocate(0x1000, MemoryProtection::ReadWrite);
            mem.Write<GuestAddr>(ppDevice, mockDevice);
            LOG_INFO("D3D12X", "Bridged D3D12 Device allocated to Metal translation layer at 0x" + std::to_string(mockDevice));
        }

        return 0; // S_OK
    };

    kernel.RegisterHook("d3d12_x.dll", "D3D12CreateDevice", createDeviceHandler);
    kernel.RegisterHook("d3d12.dll", "D3D12CreateDevice", createDeviceHandler);

    // D3D12GetDebugInterface
    auto debugInterfaceHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        LOG_INFO("D3D12X", "D3D12GetDebugInterface stubbed (Returning S_OK)");
        return 0; // S_OK
    };
    kernel.RegisterHook("d3d12_x.dll", "D3D12GetDebugInterface", debugInterfaceHandler);
    kernel.RegisterHook("d3d12.dll", "D3D12GetDebugInterface", debugInterfaceHandler);

    // DXGI Factory
    auto createDxgiFactoryHandler = [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr ppFactory = ctx.rdx ? ctx.rdx : ctx.rcx;
        if (ppFactory) {
            GuestAddr mockFactory = mem.Allocate(0x1000, MemoryProtection::ReadWrite);
            mem.Write<GuestAddr>(ppFactory, mockFactory);
            LOG_INFO("DXGI", "Bridged DXGI Factory allocated at 0x" + std::to_string(mockFactory));
        }
        return 0; // S_OK
    };
    kernel.RegisterHook("dxgi.dll", "CreateDXGIFactory", createDxgiFactoryHandler);
    kernel.RegisterHook("dxgi.dll", "CreateDXGIFactory1", createDxgiFactoryHandler);
    kernel.RegisterHook("dxgi.dll", "CreateDXGIFactory2", createDxgiFactoryHandler);
}

} // namespace Scarlett::Modules
