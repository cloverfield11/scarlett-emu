#include "loader/package_manifest.h"
#include "common/logging.h"
#include <fstream>
#include <sstream>
#include <regex>

namespace Scarlett {

static std::string ExtractAttribute(const std::string& text, const std::string& attr) {
    std::regex re(attr + "=\"([^\"]+)\"");
    std::smatch match;
    if (std::regex_search(text, match, re) && match.size() > 1) {
        return match.str(1);
    }
    return "";
}

GameConfig PackageManifest::ParseMicrosoftGameConfig(const std::string& xmlContent) {
    GameConfig config;

    // Search for Identity Name
    std::regex identityRe("<Identity\\s+([^>]+)/>");
    std::smatch match;
    if (std::regex_search(xmlContent, match, identityRe)) {
        std::string identityAttrs = match.str(1);
        std::string name = ExtractAttribute(identityAttrs, "Name");
        if (!name.empty()) config.titleName = name;
    }

    // Search for Executable Name
    std::regex exeRe("<Executable\\s+([^>]+)/>");
    if (std::regex_search(xmlContent, match, exeRe)) {
        std::string exeAttrs = match.str(1);
        std::string exe = ExtractAttribute(exeAttrs, "Name");
        if (!exe.empty()) config.executableName = exe;
    }

    // Check for advanced Scarlett features
    if (xmlContent.find("Raytracing") != std::string::npos || xmlContent.find("DXR") != std::string::npos) {
        config.requiresRayTracing = true;
    }
    if (xmlContent.find("MeshShaders") != std::string::npos) {
        config.requiresMeshShaders = true;
    }

    std::stringstream ss;
    ss << "Parsed MicrosoftGame.config:\n"
       << "  Title: " << config.titleName << "\n"
       << "  Main Executable: " << config.executableName << "\n"
       << "  Ray Tracing: " << (config.requiresRayTracing ? "YES (DXR 1.1)" : "NO") << "\n"
       << "  Mesh Shaders: " << (config.requiresMeshShaders ? "YES" : "NO");
    LOG_INFO("Manifest", ss.str());

    return config;
}

GameConfig PackageManifest::LoadFromFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        LOG_WARN("Manifest", "Could not open manifest file: " + filePath + ", using defaults.");
        return GameConfig{};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return ParseMicrosoftGameConfig(buffer.str());
}

} // namespace Scarlett
