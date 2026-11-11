#include "gpu/metal_renderer.h"
#include "common/logging.h"

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>

namespace Scarlett {

struct MetalRenderer::Impl {
    id<MTLDevice> device;
    id<MTLCommandQueue> commandQueue;
};

MetalRenderer::MetalRenderer() : m_impl(new Impl()) {}

MetalRenderer::~MetalRenderer() {
    delete m_impl;
}

bool MetalRenderer::Initialize(u32 width, u32 height) {
    @autoreleasepool {
        m_impl->device = MTLCreateSystemDefaultDevice();
        if (!m_impl->device) {
            LOG_FATAL("GPU", "Apple Silicon Metal device not supported or not found!");
            return false;
        }

        m_impl->commandQueue = [m_impl->device newCommandQueue];
        if (!m_impl->commandQueue) {
            LOG_FATAL("GPU", "Failed to create Metal command queue!");
            return false;
        }

        NSString* name = [m_impl->device name];
        std::string gpuName = [name UTF8String];

        LOG_INFO("GPU", "Metal Hardware initialized: " + gpuName);
        LOG_INFO("GPU", "Target Render Surface: " + std::to_string(width) + "x" + std::to_string(height));
        return true;
    }
}

void MetalRenderer::BeginFrame() {
    // Begin Metal command buffer encoding for Scarlett frame
}

void MetalRenderer::EndFrame() {
    // Commit command buffer and present drawable
}

std::string MetalRenderer::GetGpuName() const {
    if (m_impl && m_impl->device) {
        return [[m_impl->device name] UTF8String];
    }
    return "Unknown Metal Device";
}

} // namespace Scarlett
