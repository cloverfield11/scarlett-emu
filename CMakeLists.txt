cmake_minimum_required(VERSION 3.20)
project(ScarlettEmu LANGUAGES CXX OBJCXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(APPLE)
    enable_language(OBJCXX)
    set(CMAKE_OBJCXX_STANDARD 20)
    set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
    find_library(METAL_LIBRARY Metal REQUIRED)
    find_library(METALKIT_LIBRARY MetalKit REQUIRED)
    find_library(COCOA_LIBRARY Cocoa REQUIRED)
    find_library(QUARTZ_LIBRARY QuartzCore REQUIRED)
endif()

include_directories(
    src
)

set(SOURCES
    src/main.cpp
    src/common/logging.cpp
    src/cpu/memory_manager.cpp
    src/cpu/cpu_context.cpp
    src/cpu/interpreter.cpp
    src/loader/pe_loader.cpp
    src/loader/package_manifest.cpp
    src/kernel/hle_kernel.cpp
    src/kernel/modules/kernel32.cpp
    src/kernel/modules/d3d12_x.cpp
    src/gpu/metal_renderer.mm
)

add_executable(scarlett_emu ${SOURCES})

target_compile_definitions(scarlett_emu PRIVATE
    SCARLETT_VERSION="0.1.0-indev"
)

if(APPLE)
    target_link_libraries(scarlett_emu PRIVATE
        ${METAL_LIBRARY}
        ${METALKIT_LIBRARY}
        ${COCOA_LIBRARY}
        ${QUARTZ_LIBRARY}
    )
endif()
