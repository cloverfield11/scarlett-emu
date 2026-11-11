//--------------------------------------------------------------------------------------
// SimpleTriangle.c
//
// Clean-room port of Microsoft ATG Xbox GDK Sample for ScarlettEmu
// Copyright (C) Microsoft Corporation. All rights reserved.
//--------------------------------------------------------------------------------------

#include <windows.h>

// Direct3D 12.X declaration from Scarlett GDK
__declspec(dllimport) long D3D12CreateDevice(void* pAdapter, int minFeatureLevel, void* riid, void** ppDevice);

struct Vertex {
    float position[4];
    float color[4];
};

void EntryPoint() {
    // 1. Allocate Unified GDDR6 Memory for Vertex Buffer (SimpleTriangle specification)
    void* vertexBuffer = VirtualAlloc(NULL, 64 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!vertexBuffer) {
        ExitProcess(1);
    }

    // 2. Define standard ATG Triangle Vertices
    struct Vertex* vertices = (struct Vertex*)vertexBuffer;
    
    // Top Vertex (Xbox Signature Green)
    vertices[0].position[0] =  0.0f; vertices[0].position[1] =  0.65f; vertices[0].position[2] = 0.0f; vertices[0].position[3] = 1.0f;
    vertices[0].color[0]    = 0.06f; vertices[0].color[1]    =  0.85f; vertices[0].color[2]    = 0.22f; vertices[0].color[3]    = 1.0f;

    // Bottom-Left Vertex (Neon Blue)
    vertices[1].position[0] = -0.65f; vertices[1].position[1] = -0.65f; vertices[1].position[2] = 0.0f; vertices[1].position[3] = 1.0f;
    vertices[1].color[0]    =  0.20f; vertices[1].color[1]    =  0.60f; vertices[1].color[2]    = 1.00f; vertices[1].color[3]    = 1.0f;

    // Bottom-Right Vertex (Cyber Pink)
    vertices[2].position[0] =  0.65f; vertices[2].position[1] = -0.65f; vertices[2].position[2] = 0.0f; vertices[2].position[3] = 1.0f;
    vertices[2].color[0]    =  1.00f; vertices[2].color[1]    =  0.20f; vertices[2].color[2]    = 0.40f; vertices[2].color[3]    = 1.0f;

    // 3. Initialize Direct3D 12.X Device on Scarlett Hardware
    void* pD3DDevice = NULL;
    D3D12CreateDevice(NULL, 0x12000, NULL, &pD3DDevice);

    // 4. Clean exit
    ExitProcess(0);
}
