#pragma once

#include "kernel/hle_kernel.h"

namespace Scarlett {
class PeLoader;
}

namespace Scarlett::Modules {

void SetPeLoader(PeLoader* loader);
void SetGameRootDir(const std::string& path);
void RegisterKernel32(HleKernel& kernel);

} // namespace Scarlett::Modules
