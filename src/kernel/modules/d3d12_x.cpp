#include "kernel/modules/d3d12_x.h"
#include "kernel/modules/kernel32.h"
#include "gpu/metal_renderer.h"
#include "common/logging.h"
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <iomanip>
#include <sstream>

namespace Scarlett::Modules {

namespace {

static u64 s_d3dFenceValue = 1;
static std::vector<std::pair<u64, u64>> s_d3dPendingFenceEvents; // value, hEvent

static void CheckFenceEvents(u64 currentVal) {
    for (auto it = s_d3dPendingFenceEvents.begin(); it != s_d3dPendingFenceEvents.end(); ) {
        if (currentVal >= it->first) {
            LOG_INFO("D3D12X", "Fulfilling fence event on completion: handle=0x" + std::to_string(it->second) + " val=" + std::to_string(it->first));
            SignalEventHandle(it->second);
            it = s_d3dPendingFenceEvents.erase(it);
        } else {
            ++it;
        }
    }
}

std::string FormatGuid(MemoryManager& mem, GuestAddr guidAddr) {
    if (!guidAddr) return "NULL";
    u32 d1 = mem.Read<u32>(guidAddr);
    u16 d2 = mem.Read<u16>(guidAddr + 4);
    u16 d3 = mem.Read<u16>(guidAddr + 6);
    u8 d4[8];
    mem.ReadBytes(guidAddr + 8, d4, 8);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << d1 << "-" << std::setw(4) << d2 << "-" << std::setw(4) << d3 << "-"
        << std::setw(2) << (int)d4[0] << std::setw(2) << (int)d4[1] << "-";
    for (int i = 2; i < 8; i++) oss << std::setw(2) << (int)d4[i];
    return oss.str();
}

GuestAddr GetOrCreateSharedVTable(
    HleKernel& kernel,
    MemoryManager& mem,
    const std::string& ifaceName,
    size_t numSlots,
    const std::unordered_map<size_t, HleFunction>& overrides)
{
    static std::unordered_map<std::string, GuestAddr> s_vtables;
    GuestAddr vtableAddr = 0;
    auto found = s_vtables.find(ifaceName);
    if (found != s_vtables.end()) {
        vtableAddr = found->second;
    } else {
        vtableAddr = mem.Allocate(numSlots * 8, MemoryProtection::ReadWrite);
        for (size_t i = 0; i < numSlots; ++i) {
            std::string methodName = ifaceName + "::Slot_" + std::to_string(i);
            std::stringstream ss;
            ss << std::hex << (i * 8);
            kernel.RegisterHook("com_vtable", methodName, [ifaceName, i, offsetHex = ss.str()](CpuContext&, MemoryManager&) -> u64 {
                LOG_WARN("COM", ifaceName + "::Slot_" + std::to_string(i) + " (offset 0x" +
                         offsetHex + ") unimplemented! Returning S_OK (0)");
                return 0;
            });
            GuestAddr tramp = kernel.GetOrCreateHookTrampoline("com_vtable", methodName);
            mem.Write<GuestAddr>(vtableAddr + i * 8, tramp);
        }
        s_vtables[ifaceName] = vtableAddr;
    }

    // Apply any explicit overrides
    for (const auto& [slotIdx, handler] : overrides) {
        if (slotIdx < numSlots) {
            std::string methodName = ifaceName + "::Slot_" + std::to_string(slotIdx);
            kernel.RegisterHook("com_vtable", methodName, handler);
            GuestAddr tramp = kernel.GetOrCreateHookTrampoline("com_vtable", methodName);
            mem.Write<GuestAddr>(vtableAddr + slotIdx * 8, tramp);
        }
    }
    return vtableAddr;
}

GuestAddr CreateComObject(
    HleKernel& kernel,
    MemoryManager& mem,
    const std::string& ifaceName,
    size_t numSlots,
    const std::unordered_map<size_t, HleFunction>& overrides,
    size_t extraDataSize = 0x100)
{
    GuestAddr vtableAddr = GetOrCreateSharedVTable(kernel, mem, ifaceName, numSlots, overrides);
    GuestAddr objAddr = mem.Allocate(8 + extraDataSize, MemoryProtection::ReadWrite);
    mem.Write<GuestAddr>(objAddr, vtableAddr);
    return objAddr;
}

GuestAddr CreateSimpleChildObject(
    HleKernel& kernel,
    MemoryManager& mem,
    const std::string& ifaceName,
    size_t backingBytes = 0,
    u32 rowPitch = 0,
    u32 width = 0,
    u32 height = 0,
    u32 format = 0)
{
    GuestAddr vtableAddr = GetOrCreateSharedVTable(kernel, mem, ifaceName, 16, {
        {0, [](CpuContext& c, MemoryManager& mm) -> u64 { if (c.r8) mm.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
        // 3..6: GetDevice, GetPrivateData, SetPrivateData, SetPrivateDataInterface
        {4, [](CpuContext& c, MemoryManager& mm) -> u64 { if (c.r8) mm.Write<u32>(c.r8, 0); return 0x887A0002ULL; }}, // GetPrivateData -> DXGI_ERROR_NOT_FOUND
        {5, [](CpuContext&, MemoryManager&) -> u64 { return 0; }}, // SetPrivateData
        {6, [](CpuContext&, MemoryManager&) -> u64 { return 0; }}, // SetPrivateDataInterface
    });
    GuestAddr objAddr = mem.Allocate(48, MemoryProtection::ReadWrite);
    mem.Write<GuestAddr>(objAddr, vtableAddr);
    mem.Write<GuestAddr>(objAddr + 8, 0);
    mem.Write<u64>(objAddr + 16, 0);
    mem.Write<u32>(objAddr + 24, rowPitch);
    mem.Write<u32>(objAddr + 28, width);
    mem.Write<u32>(objAddr + 32, height);
    mem.Write<u32>(objAddr + 36, format);
    mem.Write<u32>(objAddr + 40, 0);
    if (backingBytes > 0) {
        GuestAddr data = mem.Allocate(backingBytes, MemoryProtection::ReadWrite);
        mem.Write<GuestAddr>(objAddr + 8, data);
        mem.Write<u64>(objAddr + 16, backingBytes);
    }
    return objAddr;
}

GuestAddr g_dxgiFactoryObj = 0;
GuestAddr g_dxgiAdapterObj = 0;
GuestAddr g_dxgiOutputObj = 0;
GuestAddr g_dxgiDeviceObj = 0;
GuestAddr g_dxgiSwapChainObj = 0;
GuestAddr g_d3d11DeviceObj = 0;
GuestAddr g_d3d11ContextObj = 0;
GuestAddr g_d3d12DeviceObj = 0;
GuestAddr g_d3d12ResourceObj = 0;
GuestAddr g_backbufferTex = 0;

struct D3D11ContextState {
    GuestAddr currentRTVs[8]{};
    u32 numRTVs = 0;
    GuestAddr currentDSV = 0;
    float clearColor[4]{0.05f, 0.06f, 0.08f, 1.0f};
    bool hasClearColor = false;
    u32 clearCount = 0;
    u32 drawCount = 0;
    u32 presentCount = 0;
    u32 updateSubresourceCount = 0;
    u32 copySubresourceCount = 0;
    GuestAddr currentIB = 0;
    u32 ibFormat = 0;
    u32 ibOffset = 0;
    GuestAddr currentVB[8]{};
    u32 vbStrides[8]{};
    u32 vbOffsets[8]{};
    u32 topology = 4; // D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST
    float vpX = 0.0f, vpY = 0.0f, vpW = 1280.0f, vpH = 720.0f, vpMinZ = 0.0f, vpMaxZ = 1.0f;
} g_d3dState;

static void PresentFrameToMetal(MemoryManager& m) {
    MetalRenderer* renderer = GetMetalRenderer();
    if (!renderer) return;
    renderer->SetGameFrameActive(true);
    if (g_d3dState.hasClearColor) {
        renderer->SetClearColor(g_d3dState.clearColor[0], g_d3dState.clearColor[1],
                                g_d3dState.clearColor[2], g_d3dState.clearColor[3]);
    }
    if (g_backbufferTex) {
        GuestAddr fbData = m.Read<GuestAddr>(g_backbufferTex + 8);
        u32 pitch = m.Read<u32>(g_backbufferTex + 24);
        u32 w = m.Read<u32>(g_backbufferTex + 28);
        u32 h = m.Read<u32>(g_backbufferTex + 32);
        if (const u8* hostFb = static_cast<const u8*>(m.Translate(fbData))) {
            renderer->SubmitFramebufferRGBA8(hostFb, w, h, pitch);
        }
    }
    renderer->CreateWindowAndPipeline();
    renderer->RenderFrame();
    renderer->PollEvents();
}

static void CopyResourceBacking(MemoryManager& m, GuestAddr pDst, GuestAddr pSrc) {
    if (!pDst || !pSrc) return;
    GuestAddr dstBacking = m.Read<GuestAddr>(pDst + 8);
    u64 dstSize = m.Read<u64>(pDst + 16);
    GuestAddr srcBacking = m.Read<GuestAddr>(pSrc + 8);
    u64 srcSize = m.Read<u64>(pSrc + 16);
    u64 bytes = std::min(dstSize, srcSize);
    if (!dstBacking || !srcBacking || bytes == 0) return;
    void* dstPtr = m.Translate(dstBacking);
    void* srcPtr = m.Translate(srcBacking);
    if (dstPtr && srcPtr && m.Translate(dstBacking + bytes - 1) && m.Translate(srcBacking + bytes - 1)) {
        std::memcpy(dstPtr, srcPtr, bytes);
    }
}

void EnsureDxgiAndD3D11Objects(HleKernel& kernel, MemoryManager& mem) {
    if (g_dxgiOutputObj == 0) {
        g_dxgiOutputObj = CreateComObject(kernel, mem, "IDXGIOutput", 32, {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 7 (0x38): IDXGIOutput::GetDesc(DXGI_OUTPUT_DESC*)
            {7, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                if (!pDesc) return 0x80070057ULL; // E_INVALIDARG
                std::vector<u8> zeros(0x60, 0);
                m.WriteBytes(pDesc, zeros.data(), zeros.size());
                const char* devName = "\\\\.\\DISPLAY1";
                for (size_t i = 0; devName[i]; i++) {
                    m.Write<u16>(pDesc + i * 2, static_cast<u16>(devName[i]));
                }
                m.Write<s32>(pDesc + 0x40, 0);
                m.Write<s32>(pDesc + 0x44, 0);
                m.Write<s32>(pDesc + 0x48, 1920);
                m.Write<s32>(pDesc + 0x4C, 1080);
                m.Write<u32>(pDesc + 0x50, 1); // AttachedToDesktop
                m.Write<u32>(pDesc + 0x54, 1); // DXGI_MODE_ROTATION_IDENTITY
                m.Write<u64>(pDesc + 0x58, 0x10001); // HMONITOR
                return 0;
            }},
            // 8 (0x40): IDXGIOutput::GetDisplayModeList(EnumFormat, Flags, pNumModes, pDesc)
            {8, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 enumFormat = static_cast<u32>(ctx.rdx);
                GuestAddr pNumModes = ctx.r9;
                GuestAddr pDesc = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (!pNumModes) return 0x80070057ULL;
                const u32 numAvailable = 2;
                if (!pDesc) {
                    m.Write<u32>(pNumModes, numAvailable);
                    return 0;
                }
                u32 requested = m.Read<u32>(pNumModes);
                u32 count = (requested < numAvailable) ? requested : numAvailable;
                struct Mode { u32 w, h; } modes[2] = { {1280, 720}, {1920, 1080} };
                for (u32 i = 0; i < count; i++) {
                    GuestAddr dst = pDesc + i * 28;
                    m.Write<u32>(dst + 0, modes[i].w);
                    m.Write<u32>(dst + 4, modes[i].h);
                    m.Write<u32>(dst + 8, 60);  // RefreshRate.Numerator
                    m.Write<u32>(dst + 12, 1);  // RefreshRate.Denominator
                    m.Write<u32>(dst + 16, enumFormat);
                    m.Write<u32>(dst + 20, 0);  // ScanlineOrdering
                    m.Write<u32>(dst + 24, 0);  // Scaling
                }
                m.Write<u32>(pNumModes, count);
                return 0;
            }},
            // 9 (0x48): FindClosestMatchingMode
            {9, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pModeToMatch = ctx.rdx;
                GuestAddr pClosestMatch = ctx.r8;
                if (!pModeToMatch || !pClosestMatch) return 0x80070057ULL;
                u8 buf[28];
                m.ReadBytes(pModeToMatch, buf, 28);
                m.WriteBytes(pClosestMatch, buf, 28);
                if (m.Read<u32>(pClosestMatch + 0) == 0) m.Write<u32>(pClosestMatch + 0, 1280);
                if (m.Read<u32>(pClosestMatch + 4) == 0) m.Write<u32>(pClosestMatch + 4, 720);
                if (m.Read<u32>(pClosestMatch + 8) == 0) {
                    m.Write<u32>(pClosestMatch + 8, 60);
                    m.Write<u32>(pClosestMatch + 12, 1);
                }
                return 0;
            }},
            // 19 (0x98): GetFrameStatistics
            {19, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.rdx) {
                    std::vector<u8> zeros(32, 0);
                    m.WriteBytes(ctx.rdx, zeros.data(), zeros.size());
                }
                return 0;
            }},
        });
    }

    if (g_dxgiAdapterObj == 0) {
        g_dxgiAdapterObj = CreateComObject(kernel, mem, "IDXGIAdapter", 32, {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                LOG_INFO("DXGI", "IDXGIAdapter::QueryInterface(" + FormatGuid(m, ctx.rdx) + ")");
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 6 (0x30): IDXGIObject::GetParent
            {6, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, g_dxgiFactoryObj);
                return 0;
            }},
            // 7 (0x38): EnumOutputs(Output, ppOutput)
            {7, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 outputIdx = static_cast<u32>(ctx.rdx);
                GuestAddr ppOutput = ctx.r8;
                if (outputIdx == 0 && ppOutput) {
                    m.Write<GuestAddr>(ppOutput, g_dxgiOutputObj);
                    return 0; // S_OK
                }
                if (ppOutput) m.Write<GuestAddr>(ppOutput, 0);
                return 0x887A0002ULL; // DXGI_ERROR_NOT_FOUND
            }},
            // 8 (0x40): GetDesc(DXGI_ADAPTER_DESC*)
            {8, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                if (!pDesc) return 0x80070057ULL;
                std::vector<u8> zeros(0x130, 0);
                m.WriteBytes(pDesc, zeros.data(), zeros.size());
                const char* gpuName = "Apple Silicon Metal GPU (ScarlettEmu)";
                for (size_t i = 0; gpuName[i]; i++) {
                    m.Write<u16>(pDesc + i * 2, static_cast<u16>(gpuName[i]));
                }
                m.Write<u32>(pDesc + 0x100, 0x1002); // VendorId (AMD RDNA compatible)
                m.Write<u32>(pDesc + 0x104, 0x13FE); // DeviceId
                m.Write<u32>(pDesc + 0x108, 0x0001); // SubSysId
                m.Write<u32>(pDesc + 0x10C, 0x0001); // Revision
                m.Write<u64>(pDesc + 0x110, 4ULL * 1024 * 1024 * 1024); // DedicatedVideoMemory (4GB)
                m.Write<u64>(pDesc + 0x118, 0);                         // DedicatedSystemMemory
                m.Write<u64>(pDesc + 0x120, 4ULL * 1024 * 1024 * 1024); // SharedSystemMemory (4GB)
                m.Write<u64>(pDesc + 0x128, 0x0000000000012345ULL);     // AdapterLuid
                return 0;
            }},
            // 9 (0x48): CheckInterfaceSupport
            {9, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<u64>(ctx.r8, 0x001E000000010000ULL);
                return 0;
            }},
            // 10 (0x50): GetDesc1(DXGI_ADAPTER_DESC1*)
            {10, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                if (!pDesc) return 0x80070057ULL;
                std::vector<u8> zeros(0x138, 0);
                m.WriteBytes(pDesc, zeros.data(), zeros.size());
                const char* gpuName = "Apple Silicon Metal GPU (ScarlettEmu)";
                for (size_t i = 0; gpuName[i]; i++) {
                    m.Write<u16>(pDesc + i * 2, static_cast<u16>(gpuName[i]));
                }
                m.Write<u32>(pDesc + 0x100, 0x1002);
                m.Write<u32>(pDesc + 0x104, 0x13FE);
                m.Write<u32>(pDesc + 0x108, 0x0001);
                m.Write<u32>(pDesc + 0x10C, 0x0001);
                m.Write<u64>(pDesc + 0x110, 4ULL * 1024 * 1024 * 1024);
                m.Write<u64>(pDesc + 0x118, 0);
                m.Write<u64>(pDesc + 0x120, 4ULL * 1024 * 1024 * 1024);
                m.Write<u64>(pDesc + 0x128, 0x0000000000012345ULL);
                m.Write<u32>(pDesc + 0x130, 0); // Flags = DXGI_ADAPTER_FLAG_NONE
                return 0;
            }},
        });
    }

    if (g_dxgiSwapChainObj == 0) {
        g_dxgiSwapChainObj = CreateComObject(kernel, mem, "IDXGISwapChain", 48, {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                LOG_INFO("DXGI", "IDXGISwapChain::QueryInterface(" + FormatGuid(m, ctx.rdx) + ")");
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 8 (0x40): Present(SyncInterval, Flags)
            {8, [](CpuContext&, MemoryManager& m) -> u64 {
                ++g_d3dState.presentCount;
                if (g_d3dState.presentCount <= 5) {
                    LOG_INFO("DXGI", "IDXGISwapChain::Present #" + std::to_string(g_d3dState.presentCount) +
                        " (clears=" + std::to_string(g_d3dState.clearCount) +
                        ", draws=" + std::to_string(g_d3dState.drawCount) + ")");
                }
                PresentFrameToMetal(m);
                return 0;
            }},
            // 9 (0x48): GetBuffer(UINT Buffer, REFIID riid, void** ppSurface)
            {9, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr ppSurface = ctx.r9;
                if (!g_backbufferTex) {
                    g_backbufferTex = CreateComObject(kernel, m, "ID3D11Texture2D_BackBuffer", 24, {
                        {0, [](CpuContext& c, MemoryManager& mm) -> u64 {
                            if (c.r8) mm.Write<GuestAddr>(c.r8, c.rcx);
                            return 0;
                        }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        // 10 (0x50): ID3D11Texture2D::GetDesc(D3D11_TEXTURE2D_DESC*)
                        {10, [](CpuContext& c, MemoryManager& mm) -> u64 {
                            GuestAddr pDesc = c.rdx;
                            if (pDesc) {
                                mm.Write<u32>(pDesc + 0, 1280); // Width
                                mm.Write<u32>(pDesc + 4, 720);  // Height
                                mm.Write<u32>(pDesc + 8, 1);    // MipLevels
                                mm.Write<u32>(pDesc + 12, 1);   // ArraySize
                                mm.Write<u32>(pDesc + 16, 28);  // DXGI_FORMAT_R8G8B8A8_UNORM
                                mm.Write<u32>(pDesc + 20, 1);   // SampleDesc.Count
                                mm.Write<u32>(pDesc + 24, 0);   // SampleDesc.Quality
                                mm.Write<u32>(pDesc + 28, 0);   // Usage
                                mm.Write<u32>(pDesc + 32, 0x20);// BindFlags (RENDER_TARGET)
                                mm.Write<u32>(pDesc + 36, 0);   // CPUAccessFlags
                                mm.Write<u32>(pDesc + 40, 0);   // MiscFlags
                            }
                            return 0;
                        }},
                    }, 48);
                    constexpr size_t fbBytes = 1280ULL * 720ULL * 4ULL;
                    GuestAddr fbData = m.Allocate(fbBytes, MemoryProtection::ReadWrite);
                    m.Write<GuestAddr>(g_backbufferTex + 8, fbData);
                    m.Write<u64>(g_backbufferTex + 16, fbBytes);
                    m.Write<u32>(g_backbufferTex + 24, 1280 * 4);
                    m.Write<u32>(g_backbufferTex + 28, 1280);
                    m.Write<u32>(g_backbufferTex + 32, 720);
                    m.Write<u32>(g_backbufferTex + 36, 28);
                }
                if (ppSurface) m.Write<GuestAddr>(ppSurface, g_backbufferTex);
                return 0;
            }},
            // 12 (0x60): GetDesc(DXGI_SWAP_CHAIN_DESC*)
            {12, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                if (pDesc) {
                    std::vector<u8> zeros(72, 0);
                    m.WriteBytes(pDesc, zeros.data(), zeros.size());
                    m.Write<u32>(pDesc + 0, 1280);
                    m.Write<u32>(pDesc + 4, 720);
                    m.Write<u32>(pDesc + 8, 60);
                    m.Write<u32>(pDesc + 12, 1);
                    m.Write<u32>(pDesc + 16, 28);
                    m.Write<u32>(pDesc + 28, 1); // SampleDesc.Count
                    m.Write<u32>(pDesc + 36, 0x20); // BufferUsage
                    m.Write<u32>(pDesc + 40, 2); // BufferCount
                    m.Write<u64>(pDesc + 48, 0x788); // OutputWindow
                    m.Write<u32>(pDesc + 56, 1); // Windowed = TRUE
                }
                return 0;
            }},
            // 18 (0x90): GetDesc1(DXGI_SWAP_CHAIN_DESC1*)
            {18, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                if (pDesc) {
                    std::vector<u8> zeros(48, 0);
                    m.WriteBytes(pDesc, zeros.data(), zeros.size());
                    m.Write<u32>(pDesc + 0, 1280);
                    m.Write<u32>(pDesc + 4, 720);
                    m.Write<u32>(pDesc + 8, 28);
                    m.Write<u32>(pDesc + 16, 1); // SampleDesc.Count
                    m.Write<u32>(pDesc + 24, 0x20); // BufferUsage
                    m.Write<u32>(pDesc + 28, 2); // BufferCount
                }
                return 0;
            }},
            // 22 (0xB0): Present1
            {22, [](CpuContext&, MemoryManager& m) -> u64 {
                ++g_d3dState.presentCount;
                if (g_d3dState.presentCount <= 5) {
                    LOG_INFO("DXGI", "IDXGISwapChain::Present1 #" + std::to_string(g_d3dState.presentCount) +
                        " (clears=" + std::to_string(g_d3dState.clearCount) +
                        ", draws=" + std::to_string(g_d3dState.drawCount) + ")");
                }
                PresentFrameToMetal(m);
                return 0;
            }},
        });
    }

    if (g_dxgiFactoryObj == 0) {
        g_dxgiFactoryObj = CreateComObject(kernel, mem, "IDXGIFactory", 36, {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                LOG_INFO("DXGI", "IDXGIFactory::QueryInterface(" + FormatGuid(m, ctx.rdx) + ")");
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 7 (0x38): EnumAdapters
            {7, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 adapterIdx = static_cast<u32>(ctx.rdx);
                GuestAddr ppAdapter = ctx.r8;
                if (adapterIdx == 0 && ppAdapter) {
                    m.Write<GuestAddr>(ppAdapter, g_dxgiAdapterObj);
                    return 0;
                }
                if (ppAdapter) m.Write<GuestAddr>(ppAdapter, 0);
                return 0x887A0002ULL; // DXGI_ERROR_NOT_FOUND
            }},
            // 8 (0x40): MakeWindowAssociation
            {8, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
            // 10 (0x50): CreateSwapChain(pDevice, pDesc, ppSwapChain)
            {10, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr ppSwapChain = ctx.r9;
                if (ppSwapChain) m.Write<GuestAddr>(ppSwapChain, g_dxgiSwapChainObj);
                LOG_INFO("DXGI", "IDXGIFactory::CreateSwapChain -> SwapChain=0x" + std::to_string(g_dxgiSwapChainObj));
                return 0;
            }},
            // 12 (0x60): EnumAdapters1
            {12, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 adapterIdx = static_cast<u32>(ctx.rdx);
                GuestAddr ppAdapter = ctx.r8;
                if (adapterIdx == 0 && ppAdapter) {
                    m.Write<GuestAddr>(ppAdapter, g_dxgiAdapterObj);
                    return 0;
                }
                if (ppAdapter) m.Write<GuestAddr>(ppAdapter, 0);
                return 0x887A0002ULL;
            }},
            // 13 (0x68): IsCurrent
            {13, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 14 (0x70): IsWindowedStereoEnabled
            {14, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
            // 15 (0x78): CreateSwapChainForHwnd
            {15, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr ppSwapChain = m.Read<GuestAddr>(ctx.rsp + 0x38);
                if (ppSwapChain) m.Write<GuestAddr>(ppSwapChain, g_dxgiSwapChainObj);
                LOG_INFO("DXGI", "IDXGIFactory2::CreateSwapChainForHwnd -> SwapChain=0x" + std::to_string(g_dxgiSwapChainObj));
                return 0;
            }},
            // 26 (0xD0): EnumAdapterByLuid
            {26, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr ppAdapter = ctx.r9;
                if (ppAdapter) m.Write<GuestAddr>(ppAdapter, g_dxgiAdapterObj);
                return 0;
            }},
            // 28 (0xE0): CheckFeatureSupport
            {28, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pData = ctx.r8;
                u32 dataSize = static_cast<u32>(ctx.r9);
                if (pData && dataSize >= 4) m.Write<u32>(pData, 0);
                return 0;
            }},
        });
    }

    if (g_dxgiDeviceObj == 0) {
        g_dxgiDeviceObj = CreateComObject(kernel, mem, "IDXGIDevice", 24, {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                LOG_INFO("DXGI", "IDXGIDevice::QueryInterface(" + FormatGuid(m, ctx.rdx) + ")");
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 7 (0x38): GetAdapter
            {7, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.rdx) m.Write<GuestAddr>(ctx.rdx, g_dxgiAdapterObj);
                return 0;
            }},
        });
    }

    if (g_d3d11ContextObj == 0) {
        std::unordered_map<size_t, HleFunction> ctxOverrides = {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                std::string guid = FormatGuid(m, ctx.rdx);
                if (guid.rfind("b2daad8b", 0) == 0 || guid.rfind("a04bfb29", 0) == 0) { // Multithread / UserDefinedAnnotation
                    if (ctx.r8) m.Write<GuestAddr>(ctx.r8, 0);
                    return 0x80004002ULL; // E_NOINTERFACE
                }
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 3 (0x18): GetDevice(ID3D11Device** ppDevice)
            {3, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.rdx) m.Write<GuestAddr>(ctx.rdx, g_d3d11DeviceObj);
                return 0;
            }},
            // 12 (0x60): DrawIndexed(IndexCount, StartIndexLocation, BaseVertexLocation)
            {12, [](CpuContext& ctx, MemoryManager&) -> u64 {
                ++g_d3dState.drawCount;
                if (g_d3dState.drawCount <= 10) {
                    LOG_INFO("D3D11", "DrawIndexed #" + std::to_string(g_d3dState.drawCount) +
                        " (indices=" + std::to_string(static_cast<u32>(ctx.rdx)) + ")");
                }
                return 0;
            }},
            // 13 (0x68): Draw(VertexCount, StartVertexLocation)
            {13, [](CpuContext& ctx, MemoryManager&) -> u64 {
                ++g_d3dState.drawCount;
                if (g_d3dState.drawCount <= 10) {
                    LOG_INFO("D3D11", "Draw #" + std::to_string(g_d3dState.drawCount) +
                        " (vertices=" + std::to_string(static_cast<u32>(ctx.rdx)) + ")");
                }
                return 0;
            }},
            // 14 (0x70): Map(This, pResource, Subresource, MapType, MapFlags, pMappedResource)
            {14, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pResource = ctx.rdx;
                GuestAddr pMapped = m.Read<GuestAddr>(ctx.rsp + 0x30);
                if (pMapped) {
                    GuestAddr backing = pResource ? m.Read<GuestAddr>(pResource + 8) : 0;
                    u32 rowPitch = pResource ? m.Read<u32>(pResource + 24) : 0;
                    if (!backing) {
                        backing = m.Allocate(0x100000, MemoryProtection::ReadWrite);
                        if (pResource) {
                            m.Write<GuestAddr>(pResource + 8, backing);
                            m.Write<u64>(pResource + 16, 0x100000);
                        }
                    }
                    if (!rowPitch) rowPitch = 4096;
                    m.Write<GuestAddr>(pMapped + 0, backing);
                    m.Write<u32>(pMapped + 8, rowPitch);
                    m.Write<u32>(pMapped + 12, rowPitch * 256);
                }
                return 0; // S_OK
            }},
            // 15 (0x78): Unmap
            {15, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
            // 18 (0x90): IASetVertexBuffers(StartSlot, NumBuffers, ppVBs, pStrides, pOffsets)
            {18, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 start = static_cast<u32>(ctx.rdx);
                u32 count = static_cast<u32>(ctx.r8);
                GuestAddr ppVBs = ctx.r9;
                GuestAddr pStrides = m.Read<GuestAddr>(ctx.rsp + 0x28);
                GuestAddr pOffsets = m.Read<GuestAddr>(ctx.rsp + 0x30);
                for (u32 i = 0; i < count && (start + i) < 8; ++i) {
                    u32 slot = start + i;
                    g_d3dState.currentVB[slot] = ppVBs ? m.Read<GuestAddr>(ppVBs + i * 8) : 0;
                    g_d3dState.vbStrides[slot] = pStrides ? m.Read<u32>(pStrides + i * 4) : 0;
                    g_d3dState.vbOffsets[slot] = pOffsets ? m.Read<u32>(pOffsets + i * 4) : 0;
                }
                return 0;
            }},
            // 19 (0x98): IASetIndexBuffer(pIndexBuffer, Format, Offset)
            {19, [](CpuContext& ctx, MemoryManager&) -> u64 {
                g_d3dState.currentIB = ctx.rdx;
                g_d3dState.ibFormat = static_cast<u32>(ctx.r8);
                g_d3dState.ibOffset = static_cast<u32>(ctx.r9);
                return 0;
            }},
            // 20 (0xA0): DrawIndexedInstanced
            {20, [](CpuContext&, MemoryManager&) -> u64 { ++g_d3dState.drawCount; return 0; }},
            // 21 (0xA8): DrawInstanced
            {21, [](CpuContext&, MemoryManager&) -> u64 { ++g_d3dState.drawCount; return 0; }},
            // 24 (0xC0): IASetPrimitiveTopology
            {24, [](CpuContext& ctx, MemoryManager&) -> u64 {
                g_d3dState.topology = static_cast<u32>(ctx.rdx);
                return 0;
            }},
            // 29 (0xE8): GetData(This, pAsync, pData, DataSize, GetDataFlags)
            {29, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pData = ctx.r8;
                u32 dataSize = static_cast<u32>(ctx.r9);
                if (pData && dataSize > 0) {
                    std::vector<u8> zeros(dataSize, 0);
                    if (dataSize == 8) {
                        // e.g. D3D11_QUERY_DATA_TIMESTAMP_DISJOINT or UINT64 timestamp
                        zeros[0] = 1;
                    }
                    m.WriteBytes(pData, zeros.data(), dataSize);
                }
                return 0; // S_OK (ready)
            }},
            // 33 (0x108): OMSetRenderTargets(NumViews, ppRenderTargetViews, pDepthStencilView)
            {33, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 numViews = static_cast<u32>(ctx.rdx);
                GuestAddr ppRTVs = ctx.r8;
                g_d3dState.numRTVs = std::min<u32>(numViews, 8);
                for (u32 i = 0; i < g_d3dState.numRTVs; ++i) {
                    g_d3dState.currentRTVs[i] = ppRTVs ? m.Read<GuestAddr>(ppRTVs + i * 8) : 0;
                }
                g_d3dState.currentDSV = ctx.r9;
                return 0;
            }},
            // 39, 40: Draw*Indirect
            {39, [](CpuContext&, MemoryManager&) -> u64 { ++g_d3dState.drawCount; return 0; }},
            {40, [](CpuContext&, MemoryManager&) -> u64 { ++g_d3dState.drawCount; return 0; }},
            // 44 (0x160): RSSetViewports(NumViewports, pViewports)
            {44, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                u32 num = static_cast<u32>(ctx.rdx);
                GuestAddr pVP = ctx.r8;
                if (num > 0 && pVP) {
                    g_d3dState.vpX = m.Read<float>(pVP + 0);
                    g_d3dState.vpY = m.Read<float>(pVP + 4);
                    g_d3dState.vpW = m.Read<float>(pVP + 8);
                    g_d3dState.vpH = m.Read<float>(pVP + 12);
                    g_d3dState.vpMinZ = m.Read<float>(pVP + 16);
                    g_d3dState.vpMaxZ = m.Read<float>(pVP + 20);
                }
                return 0;
            }},
            // 46 (0x170): CopySubresourceRegion(pDst, DstSub, DstX, DstY, DstZ, pSrc, SrcSub, pSrcBox)
            {46, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                ++g_d3dState.copySubresourceCount;
                GuestAddr pDst = ctx.rdx;
                u32 dstSub = static_cast<u32>(ctx.r8);
                GuestAddr pSrc = m.Read<GuestAddr>(ctx.rsp + 0x38);
                u32 srcSub = m.Read<u32>(ctx.rsp + 0x40);
                if (dstSub == 0 && srcSub == 0) {
                    CopyResourceBacking(m, pDst, pSrc);
                }
                return 0;
            }},
            // 47 (0x178): CopyResource(pDst, pSrc)
            {47, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                CopyResourceBacking(m, ctx.rdx, ctx.r8);
                return 0;
            }},
            // 48 (0x180): UpdateSubresource(pDst, DstSub, pDstBox, pSrcData, SrcRowPitch, SrcDepthPitch)
            {48, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                ++g_d3dState.updateSubresourceCount;
                GuestAddr pDst = ctx.rdx;
                u32 dstSub = static_cast<u32>(ctx.r8);
                GuestAddr pDstBox = ctx.r9;
                GuestAddr pSrcData = m.Read<GuestAddr>(ctx.rsp + 0x28);
                u32 srcRowPitch = m.Read<u32>(ctx.rsp + 0x30);
                u32 srcDepthPitch = m.Read<u32>(ctx.rsp + 0x38);
                if (pDst && pSrcData && dstSub == 0 && pDstBox == 0) {
                    GuestAddr dstBacking = m.Read<GuestAddr>(pDst + 8);
                    u64 dstSize = m.Read<u64>(pDst + 16);
                    u32 dstHeight = m.Read<u32>(pDst + 32);
                    if (dstBacking && dstSize > 0) {
                        u64 copyBytes = dstSize;
                        if (srcDepthPitch > 0 && srcDepthPitch < copyBytes) {
                            copyBytes = srcDepthPitch;
                        } else if (srcRowPitch > 0 && dstHeight > 0) {
                            u64 rowTotal = static_cast<u64>(srcRowPitch) * dstHeight;
                            if (rowTotal < copyBytes) copyBytes = rowTotal;
                        }
                        void* dstPtr = m.Translate(dstBacking);
                        void* srcPtr = m.Translate(pSrcData);
                        if (dstPtr && srcPtr && m.Translate(dstBacking + copyBytes - 1) && m.Translate(pSrcData + copyBytes - 1)) {
                            std::memcpy(dstPtr, srcPtr, copyBytes);
                        }
                    }
                }
                return 0;
            }},
            // 50 (0x190): ClearRenderTargetView(pRenderTargetView, ColorRGBA)
            {50, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                ++g_d3dState.clearCount;
                GuestAddr pRTV = ctx.rdx;
                GuestAddr pColor = ctx.r8;
                if (pColor) {
                    for (int i = 0; i < 4; ++i) {
                        g_d3dState.clearColor[i] = m.Read<float>(pColor + i * 4);
                    }
                    g_d3dState.hasClearColor = true;
                    if (MetalRenderer* renderer = GetMetalRenderer()) {
                        renderer->SetClearColor(g_d3dState.clearColor[0], g_d3dState.clearColor[1],
                                                g_d3dState.clearColor[2], g_d3dState.clearColor[3]);
                    }
                }
                if (g_d3dState.clearCount <= 10) {
                    LOG_INFO("D3D11", "ClearRenderTargetView #" + std::to_string(g_d3dState.clearCount) +
                        " rgba=(" + std::to_string(g_d3dState.clearColor[0]) + ", " +
                        std::to_string(g_d3dState.clearColor[1]) + ", " +
                        std::to_string(g_d3dState.clearColor[2]) + ", " +
                        std::to_string(g_d3dState.clearColor[3]) + ")");
                }
                GuestAddr targetRes = pRTV ? m.Read<GuestAddr>(pRTV + 8) : 0;
                if (targetRes && targetRes == g_backbufferTex) {
                    GuestAddr fbData = m.Read<GuestAddr>(g_backbufferTex + 8);
                    u64 fbBytes = m.Read<u64>(g_backbufferTex + 16);
                    if (fbData && fbBytes >= 4) {
                        auto clamp8 = [](float v) -> u8 {
                            if (v <= 0.0f) return 0;
                            if (v >= 1.0f) return 255;
                            return static_cast<u8>(v * 255.0f + 0.5f);
                        };
                        u32 px = static_cast<u32>(clamp8(g_d3dState.clearColor[0])) |
                                 (static_cast<u32>(clamp8(g_d3dState.clearColor[1])) << 8) |
                                 (static_cast<u32>(clamp8(g_d3dState.clearColor[2])) << 16) |
                                 (static_cast<u32>(clamp8(g_d3dState.clearColor[3])) << 24);
                        u32* dst = static_cast<u32*>(m.Translate(fbData));
                        if (dst) {
                            std::fill_n(dst, fbBytes / 4, px);
                        }
                    }
                }
                return 0;
            }},
        };
        // Quiet no-op stubs for common D3D11DeviceContext state/clear/compute/get slots
        constexpr size_t quietSlots[] = {
            4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 22, 23, 25, 26, 27, 28, 30, 31, 32,
            34, 35, 36, 37, 38, 41, 42, 43, 45, 49, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120
        };
        for (size_t s : quietSlots) {
            ctxOverrides.emplace(s, [](CpuContext&, MemoryManager&) -> u64 { return 0; });
        }
        g_d3d11ContextObj = CreateComObject(kernel, mem, "ID3D11DeviceContext", 140, ctxOverrides);
    }

    if (g_d3d11DeviceObj == 0) {
        g_d3d11DeviceObj = CreateComObject(kernel, mem, "ID3D11Device", 64, {
            {0, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                std::string guid = FormatGuid(m, ctx.rdx);
                LOG_INFO("D3D11", "ID3D11Device::QueryInterface(" + guid + ")");
                // ID3D11Debug (79cf2233...) or ID3D11InfoQueue (6543dbb6...) -> E_NOINTERFACE
                if (guid.rfind("79cf2233", 0) == 0 || guid.rfind("6543dbb6", 0) == 0) {
                    if (ctx.r8) m.Write<GuestAddr>(ctx.r8, 0);
                    return 0x80004002ULL;
                }
                // IDXGIDevice* -> 54ec77fa / 77db970f / 05008617 / 3d3e0379 / 6007896c (IDXGIDevice3) / 95b4f95f (IDXGIDevice4)
                if (guid.rfind("54ec77fa", 0) == 0 || guid.rfind("77db970f", 0) == 0 ||
                    guid.rfind("05008617", 0) == 0 || guid.rfind("3d3e0379", 0) == 0 ||
                    guid.rfind("6007896c", 0) == 0 || guid.rfind("95b4f95f", 0) == 0) {
                    if (ctx.r8) m.Write<GuestAddr>(ctx.r8, g_dxgiDeviceObj);
                    return 0;
                }
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, ctx.rcx);
                return 0;
            }},
            {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
            {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
            // 3 (0x18): CreateBuffer(This, pDesc, pInitialData, ppBuffer)
            {3, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                GuestAddr pInit = ctx.r8;
                GuestAddr ppBuf = ctx.r9;
                u32 byteWidth = pDesc ? m.Read<u32>(pDesc) : 4096;
                if (byteWidth == 0) byteWidth = 4096;
                if (ppBuf) {
                    GuestAddr obj = CreateSimpleChildObject(kernel, m, "ID3D11Buffer", byteWidth, byteWidth);
                    if (pInit) {
                        GuestAddr sysMem = m.Read<GuestAddr>(pInit);
                        if (sysMem) {
                            std::vector<u8> tmp(byteWidth);
                            m.ReadBytes(sysMem, tmp.data(), byteWidth);
                            m.WriteBytes(m.Read<GuestAddr>(obj + 8), tmp.data(), byteWidth);
                        }
                    }
                    m.Write<GuestAddr>(ppBuf, obj);
                }
                return 0;
            }},
            // 4 (0x20): CreateTexture1D
            {4, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) m.Write<GuestAddr>(ctx.r9, CreateSimpleChildObject(kernel, m, "ID3D11Texture1D", 4096, 4096));
                return 0;
            }},
            // 5 (0x28): CreateTexture2D(This, pDesc, pInitialData, ppTexture2D)
            {5, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pDesc = ctx.rdx;
                GuestAddr pInit = ctx.r8;
                u32 w = pDesc ? m.Read<u32>(pDesc + 0) : 256;
                u32 h = pDesc ? m.Read<u32>(pDesc + 4) : 256;
                u32 fmt = pDesc ? m.Read<u32>(pDesc + 16) : 28;
                if (w == 0) w = 256;
                if (h == 0) h = 256;
                size_t sz = std::min<size_t>(static_cast<size_t>(w) * h * 4, 16 * 1024 * 1024);
                if (ctx.r9) {
                    GuestAddr obj = CreateSimpleChildObject(kernel, m, "ID3D11Texture2D", sz, w * 4, w, h, fmt);
                    if (pInit) {
                        GuestAddr sysMem = m.Read<GuestAddr>(pInit);
                        u32 sysPitch = m.Read<u32>(pInit + 8);
                        u64 initBytes = (sysPitch > 0) ? std::min<u64>(sz, static_cast<u64>(sysPitch) * h) : sz;
                        GuestAddr backing = m.Read<GuestAddr>(obj + 8);
                        if (sysMem && backing && initBytes > 0) {
                            void* dstPtr = m.Translate(backing);
                            void* srcPtr = m.Translate(sysMem);
                            if (dstPtr && srcPtr && m.Translate(backing + initBytes - 1) && m.Translate(sysMem + initBytes - 1)) {
                                std::memcpy(dstPtr, srcPtr, initBytes);
                            }
                        }
                    }
                    m.Write<GuestAddr>(ctx.r9, obj);
                }
                return 0;
            }},
            // 6 (0x30): CreateTexture3D
            {6, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) m.Write<GuestAddr>(ctx.r9, CreateSimpleChildObject(kernel, m, "ID3D11Texture3D", 65536, 1024));
                return 0;
            }},
            // 7..10: CreateShaderResourceView, CreateUnorderedAccessView, CreateRenderTargetView, CreateDepthStencilView
            {7, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) { GuestAddr v = CreateSimpleChildObject(kernel, m, "ID3D11ShaderResourceView"); m.Write<GuestAddr>(v + 8, ctx.rdx); m.Write<GuestAddr>(ctx.r9, v); }
                return 0;
            }},
            {8, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) { GuestAddr v = CreateSimpleChildObject(kernel, m, "ID3D11UnorderedAccessView"); m.Write<GuestAddr>(v + 8, ctx.rdx); m.Write<GuestAddr>(ctx.r9, v); }
                return 0;
            }},
            {9, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) { GuestAddr v = CreateSimpleChildObject(kernel, m, "ID3D11RenderTargetView"); m.Write<GuestAddr>(v + 8, ctx.rdx); m.Write<GuestAddr>(ctx.r9, v); }
                return 0;
            }},
            {10, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) { GuestAddr v = CreateSimpleChildObject(kernel, m, "ID3D11DepthStencilView"); m.Write<GuestAddr>(v + 8, ctx.rdx); m.Write<GuestAddr>(ctx.r9, v); }
                return 0;
            }},
            // 11: CreateInputLayout(This, pInputElementDescs, NumElements, pBytecode, BytecodeLen, ppInputLayout)
            {11, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x30);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11InputLayout"));
                return 0;
            }},
            // 12,13,15,16,17,18: CreateVertex/Geometry/Pixel/Hull/Domain/ComputeShader(This, pBytecode, Len, pLinkage, ppShader)
            {12, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11VertexShader"));
                return 0;
            }},
            {13, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11GeometryShader"));
                return 0;
            }},
            {15, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11PixelShader"));
                return 0;
            }},
            {16, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11HullShader"));
                return 0;
            }},
            {17, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11DomainShader"));
                return 0;
            }},
            {18, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pp = m.Read<GuestAddr>(ctx.rsp + 0x28);
                if (pp) m.Write<GuestAddr>(pp, CreateSimpleChildObject(kernel, m, "ID3D11ComputeShader"));
                return 0;
            }},
            // 19: CreateClassLinkage(This, ppLinkage)
            {19, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.rdx) m.Write<GuestAddr>(ctx.rdx, CreateSimpleChildObject(kernel, m, "ID3D11ClassLinkage"));
                return 0;
            }},
            // 20..26: Blend, DepthStencil, Rasterizer, Sampler, Query, Predicate, Counter (This, pDesc, ppOut -> r8)
            {20, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11BlendState"));
                return 0;
            }},
            {21, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11DepthStencilState"));
                return 0;
            }},
            {22, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11RasterizerState"));
                return 0;
            }},
            {23, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11SamplerState"));
                return 0;
            }},
            {24, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11Query"));
                return 0;
            }},
            {25, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11Predicate"));
                return 0;
            }},
            {26, [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, CreateSimpleChildObject(kernel, m, "ID3D11Counter"));
                return 0;
            }},
            // 27: CreateDeferredContext(This, ContextFlags, ppDeferredContext)
            {27, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<GuestAddr>(ctx.r8, g_d3d11ContextObj);
                return 0;
            }},
            // 29 (0xE8): CheckFormatSupport
            {29, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r8) m.Write<u32>(ctx.r8, 0x00FFFFFF); // All format support flags
                return 0;
            }},
            // 30 (0xF0): CheckMultisampleQualityLevels
            {30, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.r9) m.Write<u32>(ctx.r9, 1);
                return 0;
            }},
            // 33 (0x108): CheckFeatureSupport
            {33, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                GuestAddr pData = ctx.r8;
                u32 size = static_cast<u32>(ctx.r9);
                if (pData && size > 0) {
                    std::vector<u8> zeros(size, 0);
                    m.WriteBytes(pData, zeros.data(), size);
                }
                return 0;
            }},
            // 37 (0x128): GetFeatureLevel
            {37, [](CpuContext&, MemoryManager&) -> u64 { return 0xB100; }}, // D3D_FEATURE_LEVEL_11_1
            // 40 (0x140): GetImmediateContext
            {40, [](CpuContext& ctx, MemoryManager& m) -> u64 {
                if (ctx.rdx) m.Write<GuestAddr>(ctx.rdx, g_d3d11ContextObj);
                return 0;
            }},
        });
    }
}

} // namespace

void RegisterD3D12X(HleKernel& kernel) {
    auto createDevice12Handler = [&kernel](CpuContext& ctx, MemoryManager& mem) -> u64 {
        u32 featureLevel = static_cast<u32>(ctx.rdx);
        GuestAddr ppDevice = ctx.r9;

        LOG_INFO("D3D12X", "D3D12CreateDevice called! Requested Feature Level: 0x" + std::to_string(featureLevel));

        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->CreateWindowAndPipeline();
            renderer->RenderFrame();
            renderer->PollEvents();
        }

        if (ppDevice) {
            if (!g_d3d12DeviceObj) {
                g_d3d12DeviceObj = CreateComObject(kernel, mem, "ID3D12Device", 256, {
                    {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                    {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                    {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                });
            }
            mem.Write<GuestAddr>(ppDevice, g_d3d12DeviceObj);
            LOG_INFO("D3D12X", "Bridged D3D12 Device at 0x" + std::to_string(g_d3d12DeviceObj));
        }

        return 0; // S_OK
    };

    kernel.RegisterHook("d3d12_x.dll", "D3D12CreateDevice", createDevice12Handler);
    kernel.RegisterHook("d3d12.dll", "D3D12CreateDevice", createDevice12Handler);

    auto debugInterfaceHandler = [](CpuContext&, MemoryManager&) -> u64 {
        LOG_INFO("D3D12X", "D3D12GetDebugInterface -> E_NOINTERFACE");
        return 0x80004002ULL;
    };
    kernel.RegisterHook("d3d12_x.dll", "D3D12GetDebugInterface", debugInterfaceHandler);
    kernel.RegisterHook("d3d12.dll", "D3D12GetDebugInterface", debugInterfaceHandler);

    // DXGI Factory (0/1 take (riid, ppFactory); 2 takes (Flags, riid, ppFactory))
    auto createDxgiFactoryHandler = [&kernel](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureDxgiAndD3D11Objects(kernel, mem);
        GuestAddr ppFactory = ctx.rdx;
        if (ppFactory) {
            mem.Write<GuestAddr>(ppFactory, g_dxgiFactoryObj);
            LOG_INFO("DXGI", "CreateDXGIFactory/1 -> Factory=0x" + std::to_string(g_dxgiFactoryObj));
        }
        return 0; // S_OK
    };
    auto createDxgiFactory2Handler = [&kernel](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureDxgiAndD3D11Objects(kernel, mem);
        GuestAddr ppFactory = ctx.r8;
        if (ppFactory) {
            mem.Write<GuestAddr>(ppFactory, g_dxgiFactoryObj);
            LOG_INFO("DXGI", "CreateDXGIFactory2 -> Factory=0x" + std::to_string(g_dxgiFactoryObj));
        }
        return 0; // S_OK
    };
    kernel.RegisterHook("dxgi.dll", "CreateDXGIFactory", createDxgiFactoryHandler);
    kernel.RegisterHook("dxgi.dll", "CreateDXGIFactory1", createDxgiFactoryHandler);
    kernel.RegisterHook("dxgi.dll", "CreateDXGIFactory2", createDxgiFactory2Handler);

    // D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext)
    kernel.RegisterHook("d3d11.dll", "D3D11CreateDevice", [&kernel](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureDxgiAndD3D11Objects(kernel, mem);
        GuestAddr pFeatureLevels = mem.Read<GuestAddr>(ctx.rsp + 0x28);
        u32 numFeatureLevels = mem.Read<u32>(ctx.rsp + 0x30);
        GuestAddr ppDevice = mem.Read<GuestAddr>(ctx.rsp + 0x40);
        GuestAddr pFeatureLevel = mem.Read<GuestAddr>(ctx.rsp + 0x48);
        GuestAddr ppImmediateContext = mem.Read<GuestAddr>(ctx.rsp + 0x50);

        u32 chosenLevel = 0xB000; // D3D_FEATURE_LEVEL_11_0
        if (pFeatureLevels && numFeatureLevels > 0) {
            chosenLevel = mem.Read<u32>(pFeatureLevels);
        }
        if (pFeatureLevel) mem.Write<u32>(pFeatureLevel, chosenLevel);
        if (ppDevice) mem.Write<GuestAddr>(ppDevice, g_d3d11DeviceObj);
        if (ppImmediateContext) mem.Write<GuestAddr>(ppImmediateContext, g_d3d11ContextObj);

        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->CreateWindowAndPipeline();
            renderer->PollEvents();
        }
        LOG_INFO("D3D11", "D3D11CreateDevice succeeded! FeatureLevel=0x" + std::to_string(chosenLevel));
        return 0; // S_OK
    });

    kernel.RegisterHook("d3d11.dll", "D3D11CreateDeviceAndSwapChain", [&kernel](CpuContext& ctx, MemoryManager& mem) -> u64 {
        EnsureDxgiAndD3D11Objects(kernel, mem);
        GuestAddr pFeatureLevels = mem.Read<GuestAddr>(ctx.rsp + 0x28);
        u32 numFeatureLevels = mem.Read<u32>(ctx.rsp + 0x30);
        GuestAddr ppSwapChain = mem.Read<GuestAddr>(ctx.rsp + 0x48);
        GuestAddr ppDevice = mem.Read<GuestAddr>(ctx.rsp + 0x50);
        GuestAddr pFeatureLevel = mem.Read<GuestAddr>(ctx.rsp + 0x58);
        GuestAddr ppImmediateContext = mem.Read<GuestAddr>(ctx.rsp + 0x60);

        u32 chosenLevel = 0xB000;
        if (pFeatureLevels && numFeatureLevels > 0) {
            chosenLevel = mem.Read<u32>(pFeatureLevels);
        }
        if (pFeatureLevel) mem.Write<u32>(pFeatureLevel, chosenLevel);
        if (ppSwapChain) mem.Write<GuestAddr>(ppSwapChain, g_dxgiSwapChainObj);
        if (ppDevice) mem.Write<GuestAddr>(ppDevice, g_d3d11DeviceObj);
        if (ppImmediateContext) mem.Write<GuestAddr>(ppImmediateContext, g_d3d11ContextObj);

        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->CreateWindowAndPipeline();
            renderer->PollEvents();
        }
        LOG_INFO("D3D11", "D3D11CreateDeviceAndSwapChain succeeded!");
        return 0; // S_OK
    });

    kernel.RegisterHook("d3d12_xs.dll", "D3D12ConfigureVirtualMemoryX", [](CpuContext&, MemoryManager&) -> u64 {
        LOG_INFO("D3D12X", "D3D12ConfigureVirtualMemoryX called -> S_OK");
        return 0; // S_OK
    });
    kernel.RegisterHook("d3d12_x.dll", "D3D12ConfigureVirtualMemoryX", [](CpuContext&, MemoryManager&) -> u64 {
        LOG_INFO("D3D12X", "D3D12ConfigureVirtualMemoryX called -> S_OK");
        return 0; // S_OK
    });

    auto xboxCreateDeviceHandler = [&kernel](CpuContext& ctx, MemoryManager& mem) -> u64 {
        GuestAddr ppDevice = ctx.r9;
        LOG_INFO("D3D12X", "D3D12XboxCreateDevice called! ppDevice=0x" + std::to_string(ppDevice));

        MetalRenderer* renderer = GetMetalRenderer();
        if (renderer) {
            renderer->CreateWindowAndPipeline();
            renderer->RenderFrame();
            renderer->PollEvents();
        }

        if (ppDevice) {
            if (!g_d3d12DeviceObj) {
                if (!g_d3d12ResourceObj) {
                    static GuestAddr s_resourceBuffer = 0;
                    if (!s_resourceBuffer) {
                        s_resourceBuffer = mem.Allocate(0x2000000, MemoryProtection::ReadWrite); // 32MB buffer
                    }
                    g_d3d12ResourceObj = CreateComObject(kernel, mem, "ID3D12Resource", 256, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        // 7 (0x38): Return resource object itself or buffer
                        {7, [](CpuContext& c, MemoryManager& m) -> u64 {
                            if (c.r8) {
                                m.Write<GuestAddr>(c.r8, g_d3d12ResourceObj);
                            }
                            if (c.rdx && !c.r8) {
                                m.Write<GuestAddr>(c.rdx, g_d3d12ResourceObj);
                            }
                            return 0; // S_OK
                        }},
                        // 8 (0x40): ID3D12Resource::Unmap
                        {8, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                        // 9 (0x48): ID3D12Resource::GetGPUVirtualAddress
                        {9, [](CpuContext&, MemoryManager&) -> u64 { return s_resourceBuffer; }},
                        // 21 (0xa8): ID3D12Resource::WriteToSubresource / Xbox extension
                        {21, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                        // 131 (0x418): Xbox Series X/S GpuPlacement / SubresourceInfo
                        {131, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                        // 132 (0x420): Xbox Series X/S TextureDescriptor / Layout
                        {132, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    });
                }
                static GuestAddr s_d3d12CommandQueueObj = 0;
                if (!s_d3d12CommandQueueObj) {
                    s_d3d12CommandQueueObj = CreateComObject(kernel, mem, "ID3D12CommandQueue", 64, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        // 10 (0x50): ExecuteCommandLists(NumCommandLists, ppCommandLists)
                        {10, [](CpuContext&, MemoryManager& m) -> u64 {
                            // Any submitted GPU command list advances fence values and presents
                            s_d3dFenceValue++;
                            CheckFenceEvents(s_d3dFenceValue);
                            ++g_d3dState.presentCount;
                            if (g_d3dState.presentCount <= 10 || (g_d3dState.presentCount % 60 == 0)) {
                                LOG_INFO("D3D12X", "ID3D12CommandQueue::ExecuteCommandLists/Present #" + std::to_string(g_d3dState.presentCount) +
                                         " -> Presenting frame to Metal surface!");
                            }
                            PresentFrameToMetal(m);
                            return 0;
                        }},
                        // 14 (0x70): Signal(pFence, Value)
                        {14, [](CpuContext& c, MemoryManager&) -> u64 {
                            u64 val = c.r8 ? c.r8 : c.rdx;
                            if (val > s_d3dFenceValue) s_d3dFenceValue = val;
                            CheckFenceEvents(s_d3dFenceValue);
                            return 0; // S_OK
                        }},
                        // 15 (0x78): Wait(pFence, Value)
                        {15, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                        // 16 (0x80): GetTimestampFrequency (standard D3D12)
                        {16, [](CpuContext& c, MemoryManager& m) -> u64 {
                            if (c.rdx) {
                                m.Write<u64>(c.rdx, 100000000ULL); // 100 MHz GPU clock frequency
                            }
                            return 0; // S_OK
                        }},
                        // 18 (0x90): GetTimestampFrequency (Scarlett layout)
                        {18, [](CpuContext& c, MemoryManager& m) -> u64 {
                            if (c.rdx) {
                                m.Write<u64>(c.rdx, 100000000ULL); // 100 MHz GPU clock frequency
                            }
                            return 0; // S_OK
                        }},
                        // 23 (0xb8): PresentX preparation / Flush
                        {23, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                        // 24 (0xc0): PresentX(SyncInterval, Flags, ...)
                        {24, [](CpuContext&, MemoryManager& m) -> u64 {
                            ++g_d3dState.presentCount;
                            if (g_d3dState.presentCount <= 10 || (g_d3dState.presentCount % 60 == 0)) {
                                LOG_INFO("D3D12X", "ID3D12CommandQueue::PresentX #" + std::to_string(g_d3dState.presentCount) +
                                         " -> Presenting frame to Metal surface!");
                            }
                            PresentFrameToMetal(m);
                            return 0; // S_OK
                        }},
                    });
                }
                static GuestAddr s_cmdAlloc = 0;
                if (!s_cmdAlloc) {
                    s_cmdAlloc = CreateComObject(kernel, mem, "ID3D12CommandAllocator", 32, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        {8, [](CpuContext&, MemoryManager&) -> u64 { return 0; }}, // Reset
                    });
                }
                static GuestAddr s_cmdList = 0;
                if (!s_cmdList) {
                    s_cmdList = CreateComObject(kernel, mem, "ID3D12GraphicsCommandList", 128, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        {9, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},  // Close
                        {10, [](CpuContext&, MemoryManager&) -> u64 { return 0; }}, // Reset
                    });
                }
                static GuestAddr s_descHeap = 0;
                if (!s_descHeap) {
                    s_descHeap = CreateComObject(kernel, mem, "ID3D12DescriptorHeap", 32, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        {8, [](CpuContext&, MemoryManager&) -> u64 { return 0x20000000; }},
                        {9, [](CpuContext&, MemoryManager&) -> u64 { return 0x20000000; }},
                    });
                }
                static GuestAddr s_rootSig = 0;
                if (!s_rootSig) {
                    s_rootSig = CreateComObject(kernel, mem, "ID3D12RootSignature", 32, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                    });
                }
                static GuestAddr s_fenceObj = 0;
                if (!s_fenceObj) {
                    s_fenceObj = CreateComObject(kernel, mem, "ID3D12Fence", 32, {
                        {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                        {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                        {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                        // 8 (0x40): GetCompletedValue
                        {8, [](CpuContext&, MemoryManager&) -> u64 { return s_d3dFenceValue; }},
                        // 9 (0x48): SetEventOnCompletion(Value, hEvent)
                        {9, [](CpuContext& c, MemoryManager&) -> u64 {
                            u64 val = c.rdx;
                            u64 hEvent = c.r8;
                            LOG_INFO("D3D12X", "ID3D12Fence::SetEventOnCompletion: val=" + std::to_string(val) + " hEvent=0x" + std::to_string(hEvent));
                            if (s_d3dFenceValue >= val) {
                                SignalEventHandle(hEvent);
                            } else {
                                s_d3dPendingFenceEvents.push_back({val, hEvent});
                                // Immediately signal since Scarlett GPU execution is synchronous
                                SignalEventHandle(hEvent);
                            }
                            return 0; // S_OK
                        }},
                        // 10 (0x50): Signal(Value)
                        {10, [](CpuContext& c, MemoryManager&) -> u64 {
                            u64 val = c.rdx;
                            if (val > s_d3dFenceValue) s_d3dFenceValue = val;
                            CheckFenceEvents(s_d3dFenceValue);
                            return 0; // S_OK
                        }},
                    });
                }
                g_d3d12DeviceObj = CreateComObject(kernel, mem, "ID3D12Device", 256, {
                    {0, [](CpuContext& c, MemoryManager& m) -> u64 { if (c.r8) m.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                    {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                    {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                    // 7 (0x38): GetNodeCount
                    {7, [](CpuContext& c, MemoryManager& m) -> u64 {
                        if (c.rdx) m.Write<GuestAddr>(c.rdx, g_d3d12ResourceObj);
                        return 1;
                    }},
                    // 8 (0x40): CreateCommandQueue(pDesc, riid, ppCommandQueue)
                    {8, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppCommandQueue = c.r9;
                        LOG_INFO("D3D12X", "ID3D12Device::CreateCommandQueue(slot 8): ppCommandQueue=0x" + std::to_string(ppCommandQueue));
                        if (ppCommandQueue) {
                            m.Write<GuestAddr>(ppCommandQueue, s_d3d12CommandQueueObj);
                        }
                        return 0; // S_OK
                    }},
                    // 9 (0x48): CreateCommandAllocator(type, riid, ppCommandAllocator)
                    {9, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppAlloc = c.r9;
                        LOG_INFO("D3D12X", "ID3D12Device::CreateCommandAllocator(slot 9): ppAlloc=0x" + std::to_string(ppAlloc));
                        if (ppAlloc) {
                            m.Write<GuestAddr>(ppAlloc, s_cmdAlloc);
                        }
                        return 0; // S_OK
                    }},
                    // 12 (0x60): CreateCommandList(nodeMask, type, pAllocator, pInitialState, riid, ppCommandList)
                    {12, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppList = m.Read<GuestAddr>(c.rsp + 0x38);
                        if (!ppList) ppList = m.Read<GuestAddr>(c.rsp + 0x30);
                        LOG_INFO("D3D12X", "ID3D12Device::CreateCommandList(slot 12): ppList=0x" + std::to_string(ppList));
                        if (ppList) {
                            m.Write<GuestAddr>(ppList, s_cmdList);
                        }
                        return 0; // S_OK
                    }},
                    // 14 (0x70): CreateDescriptorHeap(pDesc, riid, ppvHeap)
                    {14, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppHeap = c.r9;
                        if (ppHeap) {
                            m.Write<GuestAddr>(ppHeap, s_descHeap);
                        }
                        return 0; // S_OK
                    }},
                    // 15 (0x78): GetDescriptorHandleIncrementSize(DescriptorHeapType)
                    {15, [](CpuContext&, MemoryManager&) -> u64 {
                        return 32; // Standard descriptor increment
                    }},
                    // 16 (0x80): CreateRootSignature(nodeMask, pBlob, len, riid, ppvRootSig)
                    {16, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppRootSig = m.Read<GuestAddr>(c.rsp + 0x28);
                        if (!ppRootSig) ppRootSig = c.r9;
                        if (ppRootSig) {
                            m.Write<GuestAddr>(ppRootSig, s_rootSig);
                        }
                        return 0; // S_OK
                    }},
                    // 17 (0x88): CreateConstantBufferView
                    {17, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    // 18 (0x90): CreateShaderResourceView
                    {18, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    // 19 (0x98): CreateUnorderedAccessView
                    {19, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    // 20 (0xa0): CreateRenderTargetView(pResource, pDesc, DestDescriptor)
                    {20, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    // 21 (0xa8): CreateDepthStencilView(pResource, pDesc, DestDescriptor)
                    {21, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    // 22 (0xb0): CreateSampler
                    {22, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                    // 24 (0xc0): CreateCommandQueue (legacy slot alias)
                    {24, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppCommandQueue = c.r9;
                        LOG_INFO("D3D12X", "ID3D12Device::CreateCommandQueue(slot 24): ppCommandQueue=0x" + std::to_string(ppCommandQueue));
                        if (ppCommandQueue) {
                            m.Write<GuestAddr>(ppCommandQueue, s_d3d12CommandQueueObj);
                        }
                        return 0; // S_OK
                    }},
                    // 25 (0xc8): GetResourceAllocationInfo(visibleMask, numDescs, pDescs)
                    {25, [](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr pInfo = (c.rcx != g_d3d12DeviceObj && c.rcx != 0) ? c.rcx : c.rdx;
                        if (pInfo) {
                            m.Write<u64>(pInfo, 0x100000ULL);  // SizeInBytes = 1 MB
                            m.Write<u64>(pInfo + 8, 65536ULL); // Alignment = 64 KB
                        }
                        return pInfo;
                    }},
                    // 26 (0xd0): GetCustomHeapProperties(nodeIndex, heapType)
                    {26, [](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr pProps = c.r8 ? c.r8 : c.rdx;
                        if (pProps) {
                            m.Write<u32>(pProps + 0, 1); // D3D12_HEAP_TYPE_DEFAULT
                            m.Write<u32>(pProps + 4, 1); // D3D12_CPU_PAGE_PROPERTY_NOT_AVAILABLE
                            m.Write<u32>(pProps + 8, 1); // D3D12_MEMORY_POOL_L1
                            m.Write<u32>(pProps + 12, 1);
                            m.Write<u32>(pProps + 16, 1);
                        }
                        return pProps;
                    }},
                    // 27 (0xd8): CreateCommandAllocator (legacy slot alias) / CreateCommittedResource
                    {27, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppAlloc = c.r9;
                        if (ppAlloc) {
                            m.Write<GuestAddr>(ppAlloc, s_cmdAlloc);
                        }
                        return 0; // S_OK
                    }},
                    // 36 (0x120): CreateFence(InitialValue, Flags, riid, ppFence)
                    {36, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppFence = c.r9;
                        if (ppFence) {
                            m.Write<GuestAddr>(ppFence, s_fenceObj);
                        }
                        return 0; // S_OK
                    }},
                    // 39 (0x138): CreateDescriptorHeap(pDesc, riid, ppvHeap) (legacy alias)
                    {39, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppHeap = c.r9;
                        if (ppHeap) {
                            m.Write<GuestAddr>(ppHeap, s_descHeap);
                        }
                        return 0; // S_OK
                    }},
                    // 48 (0x180): SetStablePowerState / DeviceExtension
                    {48, [](CpuContext&, MemoryManager&) -> u64 {
                        return 0; // S_OK
                    }},
                    // 61 (0x1e8): CreateRootSignature (legacy alias)
                    {61, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr ppRootSig = m.Read<GuestAddr>(c.rsp + 0x28);
                        if (ppRootSig) {
                            m.Write<GuestAddr>(ppRootSig, s_rootSig);
                        }
                        return 0; // S_OK
                    }},
                    // 70 (0x230): ID3D12Device::Slot_70
                    {70, [](CpuContext&, MemoryManager&) -> u64 {
                        return 0; // S_OK
                    }},
                    // 73 (0x248): CreateCommittedResource(pHeapProps, HeapFlags, pDesc, InitialState, pClearValue, riid, ppvResource)
                    {73, [&kernel, &mem](CpuContext& c, MemoryManager& m) -> u64 {
                        GuestAddr pRiid = m.Read<GuestAddr>(c.rsp + 0x28);
                        GuestAddr ppvResource = m.Read<GuestAddr>(c.rsp + 0x30);
                        LOG_INFO("D3D12X", "ID3D12Device::CreateCommittedResource: riid=0x" + std::to_string(pRiid) +
                                 ", ppvResource=0x" + std::to_string(ppvResource));
                        if (ppvResource) {
                            m.Write<GuestAddr>(ppvResource, g_d3d12ResourceObj);
                        }
                        if (pRiid && !ppvResource) {
                            m.Write<GuestAddr>(pRiid, g_d3d12ResourceObj);
                        }
                        return 0; // S_OK
                    }},
                    // 78 (0x270): SetResidencyPriority / WaitFrameEvent companion
                    {78, [](CpuContext&, MemoryManager&) -> u64 {
                        return 0; // S_OK
                    }},
                    // 79 (0x278): WaitFrameEventX / FramePacing
                    {79, [](CpuContext&, MemoryManager&) -> u64 {
                        return 0; // S_OK
                    }},
                    // 86 (0x2b0): Xbox Series Extension / FramePacing info
                    {86, [](CpuContext&, MemoryManager&) -> u64 {
                        return 0; // S_OK
                    }},
                    // 108 (0x360): SetFramePacingX / Enable
                    {108, [](CpuContext&, MemoryManager&) -> u64 {
                        return 0; // S_OK
                    }},
                });
            }
            mem.Write<GuestAddr>(ppDevice, g_d3d12DeviceObj);
            LOG_INFO("D3D12X", "Bridged Xbox D3D12 Device at 0x" + std::to_string(g_d3d12DeviceObj));

            MetalRenderer* renderer = GetMetalRenderer();
            if (renderer) {
                renderer->SetGameFrameActive(true);
                renderer->SetClearColor(0.08f, 0.09f, 0.12f, 1.0f); // RAGE dark blue-gray presentation frame
                renderer->CreateWindowAndPipeline();
                renderer->RenderFrame();
                renderer->PollEvents();
            }

            // Set video/graphics subsystem ready flag for RAGE render thread (0x147bc7f93)
            static GuestAddr s_rageRenderContext = 0;
            if (!s_rageRenderContext) {
                s_rageRenderContext = mem.Allocate(0x100000, MemoryProtection::ReadWrite);
                if (s_rageRenderContext) {
                    // Frame sync event handle at [rsi + 0xa41a0]
                    u64 frameEvent = CreateEventHandle(false, true); // initially signaled
                    mem.Write<u64>(s_rageRenderContext + 0xa41a0ULL, frameEvent);
                    // Active render loop flag at [rsi + 0xa41a8] = 1 (keep running frame pump)
                    mem.Write<u8>(s_rageRenderContext + 0xa41a8ULL, 1);
                }
            }
            if (s_rageRenderContext) {
                mem.Write<GuestAddr>(0x147bc7f88ULL, s_rageRenderContext);
                mem.Write<GuestAddr>(0x147bc7f80ULL, s_rageRenderContext);
            }
            mem.Write<u8>(0x147bc7f93ULL, 1);
            mem.Write<u8>(0x147bc7f90ULL, 1);
            LOG_INFO("D3D12X", "Initialized RAGE graphics context at 0x147bc7f88 and readiness flag at 0x147bc7f90 = 1");
        }

        return 0; // S_OK
    };
    kernel.RegisterHook("d3d12_xs.dll", "D3D12XboxCreateDevice", xboxCreateDeviceHandler);
    kernel.RegisterHook("d3d12_x.dll", "D3D12XboxCreateDevice", xboxCreateDeviceHandler);

    // Xbox Graphics Library (xg_xs.dll / xg_x.dll)
    auto xgCreateTextureComputerHandler = [&kernel](CpuContext& ctx, MemoryManager& m) -> u64 {
        GuestAddr pDesc = ctx.rcx;
        GuestAddr ppComputer = ctx.rdx;
        LOG_INFO("XG", "XGCreateTextureComputer called: pDesc=0x" + std::to_string(pDesc) +
                 ", ppComputer=0x" + std::to_string(ppComputer));
        if (ppComputer) {
            static GuestAddr s_xgTextureComputerObj = 0;
            if (!s_xgTextureComputerObj) {
                s_xgTextureComputerObj = CreateComObject(kernel, m, "IXGTextureComputer", 64, {
                    {0, [](CpuContext& c, MemoryManager& mem) -> u64 { if (c.r8) mem.Write<GuestAddr>(c.r8, c.rcx); return 0; }},
                    {1, [](CpuContext&, MemoryManager&) -> u64 { return 2; }},
                    {2, [](CpuContext&, MemoryManager&) -> u64 { return 1; }},
                    // Slot 8 (0x40): CopyIntoSubresource / ComputeSubresourceLayout
                    {8, [](CpuContext&, MemoryManager&) -> u64 { return 0; }},
                });
            }
            m.Write<GuestAddr>(ppComputer, s_xgTextureComputerObj);
            LOG_INFO("XG", "Bridged IXGTextureComputer at 0x" + std::to_string(s_xgTextureComputerObj));
        }
        return 0; // S_OK
    };
    kernel.RegisterHook("xg_xs.dll", "XGCreateTextureComputer", xgCreateTextureComputerHandler);
    kernel.RegisterHook("xg_x.dll", "XGCreateTextureComputer", xgCreateTextureComputerHandler);
    kernel.RegisterHook("xg_xs.dll", "XGSuggestSwizzleMode", [](CpuContext&, MemoryManager&) -> u64 { return 0; });
    kernel.RegisterHook("xg_x.dll", "XGSuggestSwizzleMode", [](CpuContext&, MemoryManager&) -> u64 { return 0; });
}

} // namespace Scarlett::Modules
