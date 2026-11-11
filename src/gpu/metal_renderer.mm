#include "gpu/metal_renderer.h"
#include "common/logging.h"

#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>

namespace Scarlett {

static MetalRenderer* g_metalRendererInstance = nullptr;

MetalRenderer* GetMetalRenderer() {
    return g_metalRendererInstance;
}

// Metal Shading Language source for Scarlett 3D Triangle
static const char* s_shaderSource = R"(
#include <metal_stdlib>
using namespace metal;

struct VertexOut {
    float4 position [[position]];
    float4 color;
};

vertex VertexOut vertex_main(uint vid [[vertex_id]]) {
    const float2 positions[3] = {
        float2( 0.0,  0.65),  // Top vertex
        float2(-0.65, -0.65), // Bottom-left vertex
        float2( 0.65, -0.65)  // Bottom-right vertex
    };

    // Iconic Xbox Scarlett Colors: Cyber Red, Xbox Signature Green, Deep Tech Blue
    const float4 colors[3] = {
        float4(0.06f, 0.85f, 0.22f, 1.0f), // Xbox Green
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
)";

struct MetalRenderer::Impl {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> commandQueue{nil};
    id<MTLRenderPipelineState> pipelineState{nil};
    NSWindow* window{nil};
    CAMetalLayer* metalLayer{nil};
    u32 width{1280};
    u32 height{720};
    bool isRunning{true};
};

MetalRenderer::MetalRenderer() : m_impl(new Impl()) {
    g_metalRendererInstance = this;
}

MetalRenderer::~MetalRenderer() {
    if (g_metalRendererInstance == this) {
        g_metalRendererInstance = nullptr;
    }
    delete m_impl;
}

bool MetalRenderer::Initialize(u32 width, u32 height) {
    m_impl->width = width;
    m_impl->height = height;

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
        LOG_INFO("GPU", "Metal Hardware initialized: " + std::string([name UTF8String]));
        LOG_INFO("GPU", "Target Render Surface: " + std::to_string(width) + "x" + std::to_string(height));
        return true;
    }
}

bool MetalRenderer::CreateWindowAndPipeline() {
    if (m_impl->window != nil) {
        return true;
    }
    @autoreleasepool {
        // 1. Initialize NSApplication
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        // 2. Create Cocoa Window
        NSRect frame = NSMakeRect(0, 0, m_impl->width, m_impl->height);
        NSUInteger styleMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;

        m_impl->window = [[NSWindow alloc] initWithContentRect:frame
                                                     styleMask:styleMask
                                                       backing:NSBackingStoreBuffered
                                                         defer:NO];
        [m_impl->window setTitle:@"ScarlettEmu [Xbox Series S] - Apple Metal Output"];
        [m_impl->window center];

        // 3. Attach CAMetalLayer
        NSView* contentView = [m_impl->window contentView];
        [contentView setWantsLayer:YES];

        m_impl->metalLayer = [CAMetalLayer layer];
        m_impl->metalLayer.device = m_impl->device;
        m_impl->metalLayer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        m_impl->metalLayer.framebufferOnly = YES;
        m_impl->metalLayer.frame = contentView.bounds;
        [contentView setLayer:m_impl->metalLayer];

        // 4. Compile MSL Shader Pipeline
        NSError* error = nil;
        NSString* shaderCode = [NSString stringWithUTF8String:s_shaderSource];
        id<MTLLibrary> library = [m_impl->device newLibraryWithSource:shaderCode options:nil error:&error];
        if (!library) {
            LOG_FATAL("GPU", "Failed to compile Metal Shader: " + std::string([[error localizedDescription] UTF8String]));
            return false;
        }

        id<MTLFunction> vertexFunc = [library newFunctionWithName:@"vertex_main"];
        id<MTLFunction> fragmentFunc = [library newFunctionWithName:@"fragment_main"];

        MTLRenderPipelineDescriptor* desc = [[MTLRenderPipelineDescriptor alloc] init];
        desc.vertexFunction = vertexFunc;
        desc.fragmentFunction = fragmentFunc;
        desc.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;

        m_impl->pipelineState = [m_impl->device newRenderPipelineStateWithDescriptor:desc error:&error];
        if (!m_impl->pipelineState) {
            LOG_FATAL("GPU", "Failed to create Metal Pipeline State: " + std::string([[error localizedDescription] UTF8String]));
            return false;
        }

        [m_impl->window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];

        LOG_INFO("GPU", "Cocoa Window & Metal Render Pipeline successfully activated on screen!");
        return true;
    }
}

void MetalRenderer::RenderFrame() {
    @autoreleasepool {
        if (!m_impl->metalLayer || !m_impl->pipelineState) return;

        id<CAMetalDrawable> drawable = [m_impl->metalLayer nextDrawable];
        if (!drawable) return;

        MTLRenderPassDescriptor* passDesc = [MTLRenderPassDescriptor renderPassDescriptor];
        passDesc.colorAttachments[0].texture = drawable.texture;
        passDesc.colorAttachments[0].loadAction = MTLLoadActionClear;
        passDesc.colorAttachments[0].clearColor = MTLClearColorMake(0.04, 0.05, 0.07, 1.0); // Dark Xbox Dashboard tone
        passDesc.colorAttachments[0].storeAction = MTLStoreActionStore;

        id<MTLCommandBuffer> commandBuffer = [m_impl->commandQueue commandBuffer];
        id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:passDesc];

        [encoder setRenderPipelineState:m_impl->pipelineState];
        [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
        [encoder endEncoding];

        [commandBuffer presentDrawable:drawable];
        [commandBuffer commit];
    }
}

void MetalRenderer::PollEvents() {
    @autoreleasepool {
        NSEvent* event;
        while ((event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                           untilDate:[NSDate distantPast]
                                              inMode:NSDefaultRunLoopMode
                                             dequeue:YES])) {
            if ([event type] == NSEventTypeKeyDown && [event keyCode] == 53) { // ESC key
                m_impl->isRunning = false;
            }
            [NSApp sendEvent:event];
        }

        if (m_impl->window && ![m_impl->window isVisible]) {
            m_impl->isRunning = false;
        }
    }
}

bool MetalRenderer::IsRunning() const {
    return m_impl->isRunning;
}

std::string MetalRenderer::GetGpuName() const {
    if (m_impl && m_impl->device) {
        return [[m_impl->device name] UTF8String];
    }
    return "Unknown Metal Device";
}

} // namespace Scarlett
