#include "loader/pe_loader.h"
#include "common/logging.h"
#include <fstream>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace Scarlett {

PeLoader::PeLoader(MemoryManager& memory) : m_memory(memory) {}

bool PeLoader::LoadExecutable(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LOG_ERROR("Loader", "Failed to open executable: " + filePath);
        return false;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<u8> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        LOG_ERROR("Loader", "Failed to read executable contents");
        return false;
    }

    LOG_INFO("Loader", "Loaded file size: " + std::to_string(fileSize) + " bytes");

    if (!ParseHeaders(buffer)) return false;
    if (!MapSections(buffer)) return false;
    if (!ParseImports(buffer)) return false;

    return true;
}

bool PeLoader::ParseHeaders(const std::vector<u8>& rawData) {
    if (rawData.size() < sizeof(DosHeader)) {
        LOG_ERROR("Loader", "File too small to contain DOS Header");
        return false;
    }

    const auto* dos = reinterpret_cast<const DosHeader*>(rawData.data());
    if (dos->e_magic != 0x5A4D) { // "MZ"
        LOG_ERROR("Loader", "Invalid DOS signature (Expected 0x5A4D 'MZ')");
        return false;
    }

    u32 ntOffset = dos->e_lfanew;
    if (rawData.size() < ntOffset + 4 + sizeof(FileHeader) + sizeof(OptionalHeader64)) {
        LOG_ERROR("Loader", "File truncated before PE NT headers");
        return false;
    }

    u32 peSignature = *reinterpret_cast<const u32*>(rawData.data() + ntOffset);
    if (peSignature != 0x00004550) { // "PE\0\0"
        LOG_ERROR("Loader", "Invalid PE signature");
        return false;
    }

    const auto* fileHdr = reinterpret_cast<const FileHeader*>(rawData.data() + ntOffset + 4);
    if (fileHdr->machine != 0x8664) { // AMD64 (Xbox Series S / Zen 2 architecture)
        LOG_WARN("Loader", "Binary machine type is not AMD64 (0x8664)");
    }

    const auto* optHdr = reinterpret_cast<const OptionalHeader64*>(
        rawData.data() + ntOffset + 4 + sizeof(FileHeader));
    
    if (optHdr->magic != 0x20B) { // PE32+ (64-bit)
        LOG_ERROR("Loader", "Binary is not a 64-bit PE32+ executable");
        return false;
    }

    m_optHeader = *optHdr;
    m_imageBase = optHdr->imageBase;
    m_entryPoint = m_imageBase + optHdr->addressOfEntryPoint;
    m_sizeOfImage = optHdr->sizeOfImage;

    std::stringstream ss;
    ss << "Valid Scarlett PE32+ binary detected:\n"
       << "  Image Base: 0x" << std::hex << m_imageBase << "\n"
       << "  Entry Point RVA: 0x" << optHdr->addressOfEntryPoint << " (Virt: 0x" << m_entryPoint << ")\n"
       << "  Size of Image: 0x" << m_sizeOfImage << " (" << (m_sizeOfImage / 1024) << " KB)\n"
       << "  Number of Sections: " << std::dec << fileHdr->numberOfSections;
    LOG_INFO("Loader", ss.str());

    // Parse sections table
    u32 sectionOffset = ntOffset + 4 + sizeof(FileHeader) + fileHdr->sizeOfOptionalHeader;
    m_sections.clear();
    for (u16 i = 0; i < fileHdr->numberOfSections; ++i) {
        if (sectionOffset + sizeof(SectionHeader) > rawData.size()) break;
        const auto* sec = reinterpret_cast<const SectionHeader*>(rawData.data() + sectionOffset);
        m_sections.push_back(*sec);
        sectionOffset += sizeof(SectionHeader);
    }

    return true;
}

bool PeLoader::MapSections(const std::vector<u8>& rawData) {
    LOG_INFO("Loader", "Mapping PE sections into guest virtual memory space...");

    // Reserve memory block for image
    GuestAddr allocatedBase = m_memory.Allocate(m_sizeOfImage, MemoryProtection::ReadWrite, m_imageBase);
    if (allocatedBase == 0) {
        LOG_ERROR("Loader", "Failed to allocate guest memory for PE image");
        return false;
    }

    // Copy PE headers (first page)
    m_memory.WriteBytes(m_imageBase, rawData.data(), m_optHeader.sizeOfHeaders);

    for (const auto& sec : m_sections) {
        char secName[9] = {0};
        std::memcpy(secName, sec.name, 8);

        GuestAddr secDest = m_imageBase + sec.virtualAddress;
        u32 copySize = std::min(sec.sizeOfRawData, sec.virtualSize);

        if (copySize > 0 && (sec.pointerToRawData + copySize <= rawData.size())) {
            m_memory.WriteBytes(secDest, rawData.data() + sec.pointerToRawData, copySize);
        }

        // Set page protections
        MemoryProtection prot = MemoryProtection::ReadOnly;
        if ((sec.characteristics & 0x20000000) && (sec.characteristics & 0x80000000)) { // Exec + Write
            prot = MemoryProtection::ExecuteReadWrite;
        } else if (sec.characteristics & 0x20000000) { // Executable
            prot = MemoryProtection::ExecuteRead;
        } else if (sec.characteristics & 0x80000000) { // Writable
            prot = MemoryProtection::ReadWrite;
        }

        m_memory.Protect(secDest, sec.virtualSize, prot);

        std::stringstream ss;
        ss << "  Mapped section '" << secName << "' at 0x" << std::hex << secDest 
           << " (Size: 0x" << sec.virtualSize << ", Prot: " << static_cast<u32>(prot) << ")";
        LOG_DEBUG("Loader", ss.str());
    }

    return true;
}

bool PeLoader::ParseImports(const std::vector<u8>& rawData) {
    const auto& importDir = m_optHeader.dataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if (importDir.virtualAddress == 0 || importDir.size == 0) {
        LOG_INFO("Loader", "No import directory found");
        return true;
    }

    LOG_INFO("Loader", "Parsing Xbox GameOS / Scarlett import directory...");
    return true;
}

} // namespace Scarlett
