#pragma once

#include "common/types.h"
#include "cpu/memory_manager.h"
#include <string>
#include <vector>

namespace Scarlett {

#pragma pack(push, 1)
struct DosHeader {
    u16 e_magic;    // 0x5A4D ("MZ")
    u16 e_cblp;
    u16 e_cp;
    u16 e_crlc;
    u16 e_cparhdr;
    u16 e_minalloc;
    u16 e_maxalloc;
    u16 e_ss;
    u16 e_sp;
    u16 e_csum;
    u16 e_ip;
    u16 e_cs;
    u16 e_lfarlc;
    u16 e_ovno;
    u16 e_res[4];
    u16 e_oemid;
    u16 e_oeminfo;
    u16 e_res2[10];
    u32 e_lfanew;   // Offset to NT Header
};

struct FileHeader {
    u16 machine;
    u16 numberOfSections;
    u32 timeDateStamp;
    u32 pointerToSymbolTable;
    u32 numberOfSymbols;
    u16 sizeOfOptionalHeader;
    u16 characteristics;
};

struct ImageDataDirectory {
    u32 virtualAddress;
    u32 size;
};

struct OptionalHeader64 {
    u16 magic; // 0x20B for PE32+
    u8  majorLinkerVersion;
    u8  minorLinkerVersion;
    u32 sizeOfCode;
    u32 sizeOfInitializedData;
    u32 sizeOfUninitializedData;
    u32 addressOfEntryPoint;
    u32 baseOfCode;
    u64 imageBase;
    u32 sectionAlignment;
    u32 fileAlignment;
    u16 majorOperatingSystemVersion;
    u16 minorOperatingSystemVersion;
    u16 majorImageVersion;
    u16 minorImageVersion;
    u16 majorSubsystemVersion;
    u16 minorSubsystemVersion;
    u32 win32VersionValue;
    u32 sizeOfImage;
    u32 sizeOfHeaders;
    u32 checkSum;
    u16 subsystem;
    u16 dllCharacteristics;
    u64 sizeOfStackReserve;
    u64 sizeOfStackCommit;
    u64 sizeOfHeapReserve;
    u64 sizeOfHeapCommit;
    u32 loaderFlags;
    u32 numberOfRvaAndSizes;
    ImageDataDirectory dataDirectory[16];
};

struct SectionHeader {
    u8  name[8];
    u32 virtualSize;
    u32 virtualAddress;
    u32 sizeOfRawData;
    u32 pointerToRawData;
    u32 pointerToRelocations;
    u32 pointerToLinenumbers;
    u16 numberOfRelocations;
    u16 numberOfLinenumbers;
    u32 characteristics;
};
#pragma pack(pop)

struct ImportedFunction {
    std::string moduleName;
    std::string functionName;
    u16 ordinal{0};
    GuestAddr iatAddress{0};
    GuestAddr trampolineAddress{0};
    u32 hookId{0};
};

class PeLoader {
public:
    PeLoader(MemoryManager& memory);

    bool LoadExecutable(const std::string& filePath);

    GuestAddr GetEntryPoint() const { return m_entryPoint; }
    GuestAddr GetImageBase() const { return m_imageBase; }
    const std::vector<ImportedFunction>& GetImports() const { return m_imports; }

private:
    bool ParseHeaders(const std::vector<u8>& rawData);
    bool MapSections(const std::vector<u8>& rawData);
    bool ParseImports(const std::vector<u8>& rawData);

    MemoryManager& m_memory;
    GuestAddr m_imageBase{0};
    GuestAddr m_entryPoint{0};
    u32 m_sizeOfImage{0};

    OptionalHeader64 m_optHeader{};
    std::vector<SectionHeader> m_sections;
    std::vector<ImportedFunction> m_imports;
};

} // namespace Scarlett
