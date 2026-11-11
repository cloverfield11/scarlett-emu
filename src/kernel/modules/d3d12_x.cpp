#include "kernel/modules/d3d12_x.h"
#include "gpu/metal_renderer.h"
#include "common/logging.h"

namespace Scarlett::Modules {

void RegisterD3D12X(HleKernel& kernel) {
    // D3D12CreateDevice(IUnknown* pAdapter, D3D_FEATURE_LEVEL MinimumFeatureLevel, REFIID riid, void** ppDevice)
    kernel.RegisterHook("d3d12_x.dll", "D3D12CreateDevice", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
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
    });

    // D3D12GetDebugInterface
    kernel.RegisterHook("d3d12_x.dll", "D3D12GetDebugInterface", [](CpuContext& ctx, MemoryManager& mem) -> u64 {
        LOG_INFO("D3D12X", "D3D12GetDebugInterface stubbed (Returning S_OK)");
        return 0; // S_OK
    });
}

} // namespace Scarlett::Modules
