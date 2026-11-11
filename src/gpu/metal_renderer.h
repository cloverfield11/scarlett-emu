#pragma once

#include "common/types.h"
#include <string>

namespace Scarlett {

class MetalRenderer {
public:
    MetalRenderer();
    ~MetalRenderer();

    bool Initialize(u32 width = 1280, u32 height = 720);
    bool CreateWindowAndPipeline();
    void RenderFrame();
    void PollEvents();
    bool IsRunning() const;

    std::string GetGpuName() const;

    void SetHeadless(bool headless);
    void SetGameFrameActive(bool active);
    void SetClearColor(float r, float g, float b, float a);
    void SubmitFramebufferRGBA8(const u8* rgba, u32 width, u32 height, u32 rowPitch);

private:
    struct Impl;
    Impl* m_impl{nullptr};
};

// Global accessor for HLE modules
MetalRenderer* GetMetalRenderer();

} // namespace Scarlett
