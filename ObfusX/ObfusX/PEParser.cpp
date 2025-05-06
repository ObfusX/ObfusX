// PEParser.cpp - PE 섹션/헤더 파싱 유틸리티
#include "PEParser.h"
#include <windows.h>
#include <vector>
#include <cstring>
#include <fstream>

IMAGE_NT_HEADERS* GetNtHeaders(const std::vector<uint8_t>& binary) {
    if (binary.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<uint8_t*>(binary.data()));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (binary.size() < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return nullptr;
    return reinterpret_cast<IMAGE_NT_HEADERS*>(const_cast<uint8_t*>(binary.data()) + dos->e_lfanew);
}

IMAGE_SECTION_HEADER* FindSection(std::vector<uint8_t>& buffer, const char* name) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(buffer);
    if (!nt) return nullptr;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)sections[i].Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return &sections[i];
    }
    return nullptr;
}

IMAGE_SECTION_HEADER* GetSectionHeader(const std::vector<uint8_t>& binary, int index) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    if (!nt) return nullptr;

    IMAGE_SECTION_HEADER* firstSec = IMAGE_FIRST_SECTION(nt);
    if (index < 0 || index >= nt->FileHeader.NumberOfSections)
        return nullptr;

    return &firstSec[index];
}

DWORD RVAToVirtualAddress(std::vector<uint8_t>& buffer, size_t fileOffset) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(buffer);
    if (!nt) return 0;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD rawOffset = sections[i].PointerToRawData;
        DWORD size = sections[i].SizeOfRawData;
        if (fileOffset >= rawOffset && fileOffset < rawOffset + size)
            return sections[i].VirtualAddress + (DWORD)(fileOffset - rawOffset);
    }
    return 0;
}

bool ReadFileToBuffer(const std::wstring& path, std::vector<uint8_t>& out) {
    std::ifstream fin(path, std::ios::binary);
    if (!fin) return false;

    fin.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(fin.tellg());
    fin.seekg(0);
    out.resize(size);
    fin.read(reinterpret_cast<char*>(out.data()), size);
    return true;
}

bool WriteFileFromBuffer(const std::wstring& path, const std::vector<uint8_t>& data) {
    std::ofstream fout(path, std::ios::binary);
    if (!fout) return false;
    fout.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

DWORD Align(DWORD size, DWORD align) {
    return (size + align - 1) & ~(align - 1);
}
