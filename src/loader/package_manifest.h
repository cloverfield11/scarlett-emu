#pragma once

#include "common/types.h"
#include <string>
#include <vector>

namespace Scarlett {

struct GameConfig {
    std::string titleName{"Unknown Scarlett Game"};
    std::string titleId{"00000000-0000-0000-0000-000000000000"};
    std::string executableName{"default.exe"};
    u64 memoryRequiredMb{8192}; // 8GB for game partition
    bool requiresRayTracing{false};
    bool requiresMeshShaders{false};
};

class PackageManifest {
public:
    static GameConfig ParseMicrosoftGameConfig(const std::string& xmlContent);
    static GameConfig LoadFromFile(const std::string& filePath);
};

} // namespace Scarlett
