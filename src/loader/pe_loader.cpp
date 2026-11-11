#include "loader/pe_loader.h"
#include "common/logging.h"
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace Scarlett {

static bool MatchModuleName(const std::string& a, const std::string& b) {
    auto toLowerNoExt = [](const std::string& s) {
        std::string res;
        for (char c : s) res += std::tolower(static_cast<unsigned char>(c));
        if (res.size() > 4 && res.substr(res.size() - 4) == ".dll") {
            res = res.substr(0, res.size() - 4);
        }
        return res;
    };
    return toLowerNoExt(a) == toLowerNoExt(b);
}

#pragma pack(push, 1)
struct ImageExportDirectory {
    u32 characteristics;
    u32 timeDateStamp;
    u16 majorVersion;
    u16 minorVersion;
    u32 name;
    u32 base;
    u32 numberOfFunctions;
    u32 numberOfNames;
    u32 addressOfFunctions;     // RVA from list of Export Address Table
    u32 addressOfNames;         // RVA from list of Name Pointer Table
    u32 addressOfNameOrdinals;  // RVA from list of Ordinal Table
};

struct ImageImportDescriptor {
    u32 originalFirstThunk;
    u32 timeDateStamp;
    u32 forwarderChain;
    u32 name;
    u32 firstThunk;
};
#pragma pack(pop)

PeLoader::PeLoader(MemoryManager& memory) : m_memory(memory) {}

bool PeLoader::LoadExecutable(const std::string& filePath) {
    LoadedModule mainModule{};
    if (!LoadModule(filePath, &mainModule)) {
        return false;
    }

    m_imageBase = mainModule.imageBase;
    m_entryPoint = mainModule.entryPoint;
    m_sizeOfImage = mainModule.sizeOfImage;
    m_optHeader = mainModule.optHeader;
    m_sections = mainModule.sections;

    return true;
}

bool PeLoader::LoadModule(const std::string& filePath, LoadedModule* outModule) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LOG_ERROR("Loader", "Failed to open module: " + filePath);
        return false;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<u8> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        LOG_ERROR("Loader", "Failed to read module contents: " + filePath);
        return false;
    }

    LoadedModule module{};
    size_t lastSlash = filePath.find_last_of("/\\");
    module.name = (lastSlash != std::string::npos) ? filePath.substr(lastSlash + 1) : filePath;
    module.filePath = filePath;

    LOG_INFO("Loader", "Loading PE32+ module '" + module.name + "' (" + std::to_string(fileSize) + " bytes)...");

    if (!ParseHeaders(buffer, module)) return false;
    if (!MapSections(buffer, module)) return false;
    if (!ParseExports(buffer, module)) return false;

    // Register module so subsequent imports can resolve against it
    m_modules.push_back(module);

    // Now parse imports for this module
    if (!ParseImports(buffer, m_modules.back())) return false;

    if (outModule) *outModule = m_modules.back();

    LOG_INFO("Loader", "Module '" + module.name + "' successfully loaded at 0x" + std::to_string(module.imageBase));
    return true;
}

bool PeLoader::ParseHeaders(const std::vector<u8>& rawData, LoadedModule& module) {
    if (rawData.size() < sizeof(DosHeader)) {
        LOG_ERROR("Loader", "File too small to contain DOS Header: " + module.name);
        return false;
    }

    const auto* dos = reinterpret_cast<const DosHeader*>(rawData.data());
    if (dos->e_magic != 0x5A4D) { // "MZ"
        LOG_ERROR("Loader", "Invalid DOS signature in " + module.name);
        return false;
    }

    u32 ntOffset = dos->e_lfanew;
    if (rawData.size() < ntOffset + 4 + sizeof(FileHeader) + sizeof(OptionalHeader64)) {
        LOG_ERROR("Loader", "File truncated before PE NT headers: " + module.name);
        return false;
    }

    u32 peSignature = *reinterpret_cast<const u32*>(rawData.data() + ntOffset);
    if (peSignature != 0x00004550) { // "PE\0\0"
        LOG_ERROR("Loader", "Invalid PE signature in " + module.name);
        return false;
    }

    const auto* fileHdr = reinterpret_cast<const FileHeader*>(rawData.data() + ntOffset + 4);
    if (fileHdr->machine != 0x8664) {
        LOG_WARN("Loader", "Binary machine type is not AMD64 (0x8664) in " + module.name);
    }

    const auto* optHdr = reinterpret_cast<const OptionalHeader64*>(
        rawData.data() + ntOffset + 4 + sizeof(FileHeader));
    
    if (optHdr->magic != 0x20B) { // PE32+ (64-bit)
        LOG_ERROR("Loader", "Binary is not a 64-bit PE32+ executable: " + module.name);
        return false;
    }

    module.optHeader = *optHdr;
    module.imageBase = optHdr->imageBase;
    module.entryPoint = module.imageBase + optHdr->addressOfEntryPoint;
    module.sizeOfImage = optHdr->sizeOfImage;

    std::stringstream ss;
    ss << "Valid PE32+ module detected ('" << module.name << "'):\n"
       << "  Image Base: 0x" << std::hex << module.imageBase << "\n"
       << "  Entry Point RVA: 0x" << optHdr->addressOfEntryPoint << " (Virt: 0x" << module.entryPoint << ")\n"
       << "  Size of Image: 0x" << module.sizeOfImage << " (" << (module.sizeOfImage / 1024) << " KB)\n"
       << "  Number of Sections: " << std::dec << fileHdr->numberOfSections;
    LOG_INFO("Loader", ss.str());

    // Parse sections table
    u32 sectionOffset = ntOffset + 4 + sizeof(FileHeader) + fileHdr->sizeOfOptionalHeader;
    module.sections.clear();
    for (u16 i = 0; i < fileHdr->numberOfSections; ++i) {
        if (sectionOffset + sizeof(SectionHeader) > rawData.size()) break;
        const auto* sec = reinterpret_cast<const SectionHeader*>(rawData.data() + sectionOffset);
        module.sections.push_back(*sec);
        sectionOffset += sizeof(SectionHeader);
    }

    return true;
}

bool PeLoader::MapSections(const std::vector<u8>& rawData, LoadedModule& module) {
    LOG_INFO("Loader", "Mapping sections for '" + module.name + "' into guest memory...");

    GuestAddr preferredBase = module.imageBase;
    bool hasConflict = false;
    for (const auto& mod : m_modules) {
        GuestAddr modStart = mod.imageBase;
        GuestAddr modEnd = mod.imageBase + mod.sizeOfImage;
        GuestAddr newStart = preferredBase;
        GuestAddr newEnd = preferredBase + module.sizeOfImage;
        if (!(newEnd <= modStart || newStart >= modEnd)) {
            hasConflict = true;
            break;
        }
    }

    static GuestAddr s_nextRelocBase = 0x200000000ULL;
    GuestAddr finalBase = preferredBase;
    if (hasConflict) {
        finalBase = s_nextRelocBase;
        s_nextRelocBase = (s_nextRelocBase + module.sizeOfImage + 0xFFFFFFULL) & ~0xFFFFFFULL;
        LOG_INFO("Loader", "Module '" + module.name + "' conflicts with loaded module. Relocating to 0x" + std::to_string(finalBase));
    }

    GuestAddr allocatedBase = m_memory.Allocate(module.sizeOfImage, MemoryProtection::ReadWrite, finalBase);
    if (allocatedBase == 0) {
        LOG_ERROR("Loader", "Failed to allocate guest memory for module: " + module.name);
        return false;
    }

    s64 delta = static_cast<s64>(finalBase) - static_cast<s64>(module.optHeader.imageBase);
    module.imageBase = finalBase;
    module.entryPoint = module.imageBase + module.optHeader.addressOfEntryPoint;

    // Copy PE headers (first page)
    m_memory.WriteBytes(module.imageBase, rawData.data(), module.optHeader.sizeOfHeaders);

    for (const auto& sec : module.sections) {
        char secName[9] = {0};
        std::memcpy(secName, sec.name, 8);

        GuestAddr secDest = module.imageBase + sec.virtualAddress;
        u32 copySize = std::min(sec.sizeOfRawData, sec.virtualSize);

        if (copySize > 0 && (sec.pointerToRawData + copySize <= rawData.size())) {
            m_memory.WriteBytes(secDest, rawData.data() + sec.pointerToRawData, copySize);
        }

        MemoryProtection prot = MemoryProtection::ReadOnly;
        if ((sec.characteristics & 0x20000000) && (sec.characteristics & 0x80000000)) {
            prot = MemoryProtection::ExecuteReadWrite;
        } else if (sec.characteristics & 0x20000000) {
            prot = MemoryProtection::ExecuteRead;
        } else if (sec.characteristics & 0x80000000) {
            prot = MemoryProtection::ReadWrite;
        }

        m_memory.Protect(secDest, sec.virtualSize, prot);

        std::stringstream ss;
        ss << "  ['" << module.name << "'] Mapped section '" << secName << "' at 0x" << std::hex << secDest 
           << " (Size: 0x" << sec.virtualSize << ", Prot: " << static_cast<u32>(prot) << ")";
        LOG_DEBUG("Loader", ss.str());
    }

    if (delta != 0) {
        ApplyRelocations(module, delta);
    }

    return true;
}

bool PeLoader::ApplyRelocations(LoadedModule& module, s64 delta) {
    if (delta == 0) return true;
    const auto& relocDir = module.optHeader.dataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
    if (relocDir.virtualAddress == 0 || relocDir.size == 0) {
        LOG_INFO("Loader", "Module '" + module.name + "' has no base relocation table.");
        return true;
    }

    LOG_INFO("Loader", "Applying base relocations for '" + module.name + "' (delta: " + std::to_string(delta) + ")...");
    GuestAddr relocAddr = module.imageBase + relocDir.virtualAddress;
    u32 bytesProcessed = 0;

    while (bytesProcessed < relocDir.size) {
        u32 pageRva = m_memory.Read<u32>(relocAddr + bytesProcessed);
        u32 blockSize = m_memory.Read<u32>(relocAddr + bytesProcessed + 4);
        if (blockSize < 8) break;

        u32 count = (blockSize - 8) / 2;
        for (u32 i = 0; i < count; i++) {
            u16 entry = m_memory.Read<u16>(relocAddr + bytesProcessed + 8 + i * 2);
            u8 type = (entry >> 12) & 0x0F;
            u16 offset = entry & 0x0FFF;

            GuestAddr patchAddr = module.imageBase + pageRva + offset;
            if (type == 10) { // IMAGE_REL_BASED_DIR64
                u64 val = m_memory.Read<u64>(patchAddr);
                m_memory.Write<u64>(patchAddr, val + delta);
            } else if (type == 3) { // IMAGE_REL_BASED_HIGHLOW
                u32 val = m_memory.Read<u32>(patchAddr);
                m_memory.Write<u32>(patchAddr, static_cast<u32>(val + delta));
            }
        }
        bytesProcessed += blockSize;
    }

    LOG_INFO("Loader", "Successfully applied base relocations for '" + module.name + "'.");
    return true;
}

bool PeLoader::ParseExports(const std::vector<u8>& rawData, LoadedModule& module) {
    const auto& exportDir = module.optHeader.dataDirectory[0]; // IMAGE_DIRECTORY_ENTRY_EXPORT
    if (exportDir.virtualAddress == 0 || exportDir.size == 0) {
        return true;
    }

    GuestAddr exportAddr = module.imageBase + exportDir.virtualAddress;
    ImageExportDirectory exp{};
    m_memory.ReadBytes(exportAddr, &exp, sizeof(exp));

    LOG_INFO("Loader", "Parsing exports for '" + module.name + "' (" + 
             std::to_string(exp.numberOfFunctions) + " functions, " + 
             std::to_string(exp.numberOfNames) + " named)...");

    for (u32 i = 0; i < exp.numberOfNames; ++i) {
        u32 nameRva = m_memory.Read<u32>(module.imageBase + exp.addressOfNames + i * 4);
        char nameBuf[128] = {0};
        m_memory.ReadBytes(module.imageBase + nameRva, nameBuf, sizeof(nameBuf) - 1);
        std::string funcName = nameBuf;

        u16 ordinal = m_memory.Read<u16>(module.imageBase + exp.addressOfNameOrdinals + i * 2);
        u32 funcRva = m_memory.Read<u32>(module.imageBase + exp.addressOfFunctions + ordinal * 4);
        GuestAddr funcAddr = module.imageBase + funcRva;

        ExportedFunction expFunc{};
        expFunc.name = funcName;
        expFunc.ordinal = ordinal;
        expFunc.address = funcAddr;
        module.exports.push_back(expFunc);

        std::string lowerName = funcName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        module.exportMap[lowerName] = funcAddr;

        std::stringstream ss;
        ss << "    Export [" << i << "]: " << funcName << " -> 0x" << std::hex << funcAddr;
        LOG_DEBUG("Loader", ss.str());
    }

    LOG_INFO("Loader", "Successfully resolved " + std::to_string(module.exports.size()) + 
             " exports for '" + module.name + "'");
    return true;
}

GuestAddr PeLoader::FindExport(const std::string& moduleName, const std::string& functionName) const {
    std::string lowerFunc = functionName;
    std::transform(lowerFunc.begin(), lowerFunc.end(), lowerFunc.begin(), ::tolower);

    for (const auto& mod : m_modules) {
        if (MatchModuleName(mod.name, moduleName)) {
            auto it = mod.exportMap.find(lowerFunc);
            if (it != mod.exportMap.end()) {
                return it->second;
            }
        }
    }
    return 0;
}

bool PeLoader::ParseImports(const std::vector<u8>& rawData, LoadedModule& module) {
    const auto& importDir = module.optHeader.dataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if (importDir.virtualAddress == 0 || importDir.size == 0) {
        LOG_INFO("Loader", "No import directory found in " + module.name);
        return true;
    }

    LOG_INFO("Loader", "Resolving Import Address Table (IAT) for '" + module.name + "'...");

    GuestAddr importDescAddr = module.imageBase + importDir.virtualAddress;
    u32 descOffset = 0;

    // Allocate trampoline pool once
    if (m_trampolinePool == 0) {
        m_trampolinePool = m_memory.Allocate(0x100000, MemoryProtection::ExecuteReadWrite, 0x150000000);
        m_trampolineOffset = 0;
    }

    while (true) {
        ImageImportDescriptor desc{};
        m_memory.ReadBytes(importDescAddr + descOffset, &desc, sizeof(desc));

        if (desc.name == 0 && desc.firstThunk == 0) break;

        char dllNameBuf[128] = {0};
        m_memory.ReadBytes(module.imageBase + desc.name, dllNameBuf, sizeof(dllNameBuf) - 1);
        std::string dllName = dllNameBuf;

        LOG_INFO("Loader", "  ['" + module.name + "'] Importing module: " + dllName);

        u32 thunkRva = desc.originalFirstThunk ? desc.originalFirstThunk : desc.firstThunk;
        u32 iatRva = desc.firstThunk;
        u32 index = 0;

        while (true) {
            u64 thunkValue = m_memory.Read<u64>(module.imageBase + thunkRva + index * 8);
            if (thunkValue == 0) break;

            std::string funcName;
            if ((thunkValue & 0x8000000000000000ULL) == 0) {
                u32 nameRva = static_cast<u32>(thunkValue & 0x7FFFFFFF);
                char funcNameBuf[128] = {0};
                m_memory.ReadBytes(module.imageBase + nameRva + 2, funcNameBuf, sizeof(funcNameBuf) - 1);
                funcName = funcNameBuf;
            } else {
                funcName = "Ordinal_" + std::to_string(thunkValue & 0xFFFF);
            }

            GuestAddr iatEntryAddr = module.imageBase + iatRva + index * 8;
            GuestAddr exportAddr = FindExport(dllName, funcName);
            GuestAddr targetAddr = 0;
            u32 hookId = 0;

            if (exportAddr != 0) {
                // Resolved directly to loaded module export!
                targetAddr = exportAddr;
                std::stringstream ss;
                ss << "    [IAT 0x" << std::hex << iatEntryAddr << "] -> " << dllName << "!" << funcName
                   << " (Resolved directly to module export 0x" << targetAddr << ")";
                LOG_INFO("Loader", ss.str());
            } else {
                // Hook via HLE trap trampoline
                hookId = static_cast<u32>(m_imports.size() + 1);
                targetAddr = m_trampolinePool + m_trampolineOffset;

                u8 trampolineCode[7] = {
                    0x0F, 0x0B,
                    static_cast<u8>(hookId & 0xFF),
                    static_cast<u8>((hookId >> 8) & 0xFF),
                    static_cast<u8>((hookId >> 16) & 0xFF),
                    static_cast<u8>((hookId >> 24) & 0xFF),
                    0xC3 // ret
                };
                m_memory.WriteBytes(targetAddr, trampolineCode, sizeof(trampolineCode));
                m_trampolineOffset += 16;

                std::stringstream ss;
                ss << "    [IAT 0x" << std::hex << iatEntryAddr << "] -> " << dllName << "!" << funcName
                   << " (Trampoline: 0x" << targetAddr << ")";
                LOG_DEBUG("Loader", ss.str());
            }

            m_memory.Write<u64>(iatEntryAddr, targetAddr);

            ImportedFunction imp{};
            imp.moduleName = dllName;
            imp.functionName = funcName;
            imp.iatAddress = iatEntryAddr;
            imp.trampolineAddress = targetAddr;
            imp.hookId = hookId;
            m_imports.push_back(imp);

            index++;
        }

        descOffset += sizeof(ImageImportDescriptor);
    }

    LOG_INFO("Loader", "Successfully resolved IAT imports for '" + module.name + 
             "'. Total imports tracked: " + std::to_string(m_imports.size()));
    return true;
}

} // namespace Scarlett
