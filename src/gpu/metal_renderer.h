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

private:
    struct Impl;
    Impl* m_impl{nullptr};
};

// Global accessor for HLE modules
MetalRenderer* GetMetalRenderer();

} // namespace Scarlett
