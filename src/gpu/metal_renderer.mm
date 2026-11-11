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

// Metal Shading Language source for Scarlett 3D Triangle & Game Framebuffer Quad
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

struct QuadVertexOut {
    float4 position [[position]];
    float2 uv;
};

vertex QuadVertexOut quad_vertex_main(uint vid [[vertex_id]]) {
    // Fullscreen triangle covering [-1, 1] x [-1, 1]
    const float2 pos[3] = {
        float2(-1.0, -1.0),
        float2( 3.0, -1.0),
        float2(-1.0,  3.0)
    };
    const float2 uvs[3] = {
        float2(0.0, 1.0),
        float2(2.0, 1.0),
        float2(0.0, -1.0)
    };
    QuadVertexOut out;
    out.position = float4(pos[vid], 0.0, 1.0);
    out.uv = uvs[vid];
    return out;
}

fragment float4 quad_fragment_main(QuadVertexOut in [[stage_in]],
                                   texture2d<float> fbTex [[texture(0)]]) {
    constexpr sampler s(mag_filter::linear, min_filter::linear, address::clamp_to_edge);
    return fbTex.sample(s, in.uv);
}
)";

struct MetalRenderer::Impl {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> commandQueue{nil};
    id<MTLRenderPipelineState> pipelineState{nil};
    id<MTLRenderPipelineState> quadPipelineState{nil};
    id<MTLTexture> gameTexture{nil};
    u32 texWidth{0};
    u32 texHeight{0};
    NSWindow* window{nil};
    CAMetalLayer* metalLayer{nil};
    u32 width{1280};
    u32 height{720};
    bool isRunning{true};
    bool headless{false};
    bool gameFrameActive{false};
    bool hasTextureData{false};
    float clearR{0.04f};
    float clearG{0.05f};
    float clearB{0.07f};
    float clearA{1.0f};
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
    if (m_impl->headless || m_impl->window != nil) {
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

        id<MTLFunction> quadVert = [library newFunctionWithName:@"quad_vertex_main"];
        id<MTLFunction> quadFrag = [library newFunctionWithName:@"quad_fragment_main"];
        MTLRenderPipelineDescriptor* quadDesc = [[MTLRenderPipelineDescriptor alloc] init];
        quadDesc.vertexFunction = quadVert;
        quadDesc.fragmentFunction = quadFrag;
        quadDesc.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        m_impl->quadPipelineState = [m_impl->device newRenderPipelineStateWithDescriptor:quadDesc error:&error];
        if (!m_impl->quadPipelineState) {
            LOG_FATAL("GPU", "Failed to create Metal Quad Pipeline State: " + std::string([[error localizedDescription] UTF8String]));
            return false;
        }

        [m_impl->window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];

        LOG_INFO("GPU", "Cocoa Window & Metal Render Pipeline successfully activated on screen!");
        return true;
    }
}

void MetalRenderer::SetHeadless(bool headless) {
    m_impl->headless = headless;
}

void MetalRenderer::SetGameFrameActive(bool active) {
    m_impl->gameFrameActive = active;
}

void MetalRenderer::SetClearColor(float r, float g, float b, float a) {
    m_impl->clearR = r;
    m_impl->clearG = g;
    m_impl->clearB = b;
    m_impl->clearA = a;
    m_impl->gameFrameActive = true;
}

void MetalRenderer::SubmitFramebufferRGBA8(const u8* rgba, u32 width, u32 height, u32 rowPitch) {
    if (!rgba || width == 0 || height == 0 || rowPitch == 0) return;
    m_impl->gameFrameActive = true;
    if (m_impl->headless || !m_impl->device) return;

    @autoreleasepool {
        if (!m_impl->gameTexture || m_impl->texWidth != width || m_impl->texHeight != height) {
            MTLTextureDescriptor* texDesc = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                                                               width:width
                                                                                              height:height
                                                                                           mipmapped:NO];
            texDesc.usage = MTLTextureUsageShaderRead;
            m_impl->gameTexture = [m_impl->device newTextureWithDescriptor:texDesc];
            m_impl->texWidth = width;
            m_impl->texHeight = height;
        }
        if (m_impl->gameTexture) {
            MTLRegion region = MTLRegionMake2D(0, 0, width, height);
            [m_impl->gameTexture replaceRegion:region mipmapLevel:0 withBytes:rgba bytesPerRow:rowPitch];
            m_impl->hasTextureData = true;
        }
    }
}

void MetalRenderer::RenderFrame() {
    if (m_impl->headless) return;
    @autoreleasepool {
        if (!m_impl->metalLayer || !m_impl->pipelineState) return;

        id<CAMetalDrawable> drawable = [m_impl->metalLayer nextDrawable];
        if (!drawable) return;

        MTLRenderPassDescriptor* passDesc = [MTLRenderPassDescriptor renderPassDescriptor];
        passDesc.colorAttachments[0].texture = drawable.texture;
        passDesc.colorAttachments[0].loadAction = MTLLoadActionClear;
        if (m_impl->gameFrameActive) {
            passDesc.colorAttachments[0].clearColor = MTLClearColorMake(m_impl->clearR, m_impl->clearG, m_impl->clearB, m_impl->clearA);
        } else {
            passDesc.colorAttachments[0].clearColor = MTLClearColorMake(0.04, 0.05, 0.07, 1.0); // Dark Xbox Dashboard tone
        }
        passDesc.colorAttachments[0].storeAction = MTLStoreActionStore;

        id<MTLCommandBuffer> commandBuffer = [m_impl->commandQueue commandBuffer];
        id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:passDesc];

        if (m_impl->gameFrameActive) {
            if (m_impl->hasTextureData && m_impl->gameTexture && m_impl->quadPipelineState) {
                [encoder setRenderPipelineState:m_impl->quadPipelineState];
                [encoder setFragmentTexture:m_impl->gameTexture atIndex:0];
                [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
            }
        } else {
            [encoder setRenderPipelineState:m_impl->pipelineState];
            [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
        }
        [encoder endEncoding];

        [commandBuffer presentDrawable:drawable];
        [commandBuffer commit];
    }
}

void MetalRenderer::PollEvents() {
    if (m_impl->headless) return;
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
