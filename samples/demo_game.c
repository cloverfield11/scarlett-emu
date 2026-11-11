#include <windows.h>

void EntryPoint() {
    // 1. Request 1MB from Scarlett Unified GDDR6 RAM
    void* buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        ExitProcess(1);
    }

    // 2. Scalar compute workload without SSE vectorization
    int* data = (int*)buffer;
    for (int i = 0; i < 5; i++) {
        data[i] = i * 10;
    }

    // 3. Exit GameOS cleanly
    ExitProcess(0);
}
