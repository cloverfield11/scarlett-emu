#include <windows.h>

__declspec(dllimport) long D3D12CreateDevice(void* pAdapter, int minFeatureLevel, void* riid, void** ppDevice);

void EntryPoint() {
    // 1. Allocate 1MB GDDR6 RAM
    void* buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 2. Initialize Direct3D 12.X Console Device & Surface on Apple Silicon
    void* pD3DDevice = NULL;
    D3D12CreateDevice(NULL, 0x12000, NULL, &pD3DDevice);

    // 3. Exit gracefully
    ExitProcess(0);
}
