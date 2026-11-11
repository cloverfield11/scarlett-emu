#pragma once

#include "common/types.h"
#include <string>

namespace Scarlett {

class MetalRenderer {
public:
    MetalRenderer();
    ~MetalRenderer();

    bool Initialize(u32 width = 1920, u32 height = 1080);
    void BeginFrame();
    void EndFrame();

    std::string GetGpuName() const;

private:
    struct Impl;
    Impl* m_impl{nullptr};
};

} // namespace Scarlett
