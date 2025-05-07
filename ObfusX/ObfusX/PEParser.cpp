// PEParser.cpp - PE 섹션/헤더 파싱 유틸리티
#include "PEParser.h"
#include <windows.h>
#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>

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

bool AddSection(const char* name, std::vector<uint8_t>& binary, const std::vector<uint8_t>& stub)
{
    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    if (!nt) return false;

    IMAGE_SECTION_HEADER* sectionTable = IMAGE_FIRST_SECTION(nt);
    WORD& sectionCount = nt->FileHeader.NumberOfSections;

    if (sectionCount >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return false;
    }

    IMAGE_SECTION_HEADER* newSec = &sectionTable[sectionCount];
    ++sectionCount;

    memset(newSec->Name, 0, IMAGE_SIZEOF_SHORT_NAME);
    size_t nameLen = strlen(name);
    if (nameLen > IMAGE_SIZEOF_SHORT_NAME) nameLen = IMAGE_SIZEOF_SHORT_NAME;
    memcpy(newSec->Name, name, nameLen);

    DWORD fileAlign = nt->OptionalHeader.FileAlignment;
    DWORD sectionAlign = nt->OptionalHeader.SectionAlignment;

    DWORD rawSize = Align(static_cast<DWORD>(stub.size()), fileAlign);
    DWORD virtSize = Align(static_cast<DWORD>(stub.size()), sectionAlign);
    DWORD rawOffset = Align(static_cast<DWORD>(binary.size()), fileAlign);
    DWORD virtAddress = Align(sectionTable[sectionCount - 2].VirtualAddress +
        sectionTable[sectionCount - 2].Misc.VirtualSize, sectionAlign);

    newSec->PointerToRawData = rawOffset;
    newSec->SizeOfRawData = rawSize;
    newSec->VirtualAddress = virtAddress;
    newSec->Misc.VirtualSize = static_cast<DWORD>(stub.size());
    newSec->Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    binary.resize(rawOffset + rawSize, 0);
    memcpy(&binary[rawOffset], stub.data(), stub.size());

    nt->OptionalHeader.SizeOfImage = Align(virtAddress + virtSize, sectionAlign);

    return true;
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


bool FixRelocSection(std::vector<uint8_t>& binary) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    if (!nt) return false;

    IMAGE_DATA_DIRECTORY& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
        std::wcout << L"[!] Relocation Directory가 존재하지 않습니다." << std::endl;
        return false;
    }

    uint32_t relocRVA = relocDir.VirtualAddress;
    uint32_t relocSize = relocDir.Size;

    IMAGE_SECTION_HEADER* relocSec = FindSection(binary, ".reloc");
    if (!relocSec) {
        std::wcout << L"[!] .reloc 섹션을 찾을 수 없습니다." << std::endl;
        return false;
    }

    uint8_t* relocRaw = binary.data() + relocSec->PointerToRawData;
    size_t processedSize = 0;

    while (processedSize < relocSize) {
        IMAGE_BASE_RELOCATION* baseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocRaw + processedSize);
        if (baseReloc->SizeOfBlock == 0) break;

        DWORD pageRVA = baseReloc->VirtualAddress;
        DWORD entryCount = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = reinterpret_cast<WORD*>(baseReloc + 1);

        for (DWORD i = 0; i < entryCount; ++i) {
            WORD entry = entries[i];
            WORD type = entry >> 12;
            WORD offset = entry & 0x0FFF;

            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                DWORD relocAddrRVA = pageRVA + offset;

                if (relocAddrRVA >= nt->OptionalHeader.SizeOfImage) {
                    std::wcout << L"[!] 잘못된 relocation RVA (0x" << std::hex << relocAddrRVA << L") - 제거 필요" << std::endl;
                    entries[i] = 0;
                }
            }
        }

        processedSize += baseReloc->SizeOfBlock;
    }

    return true;
}


bool StripDynamicBase(IMAGE_NT_HEADERS* nt) {
    std::wcout << L"[*] DllCharacteristics에서 ASLR/NX 제거..." << std::endl;
    nt->OptionalHeader.DllCharacteristics &= ~0x0040; // DYNAMIC_BASE
    nt->OptionalHeader.DllCharacteristics &= ~0x0100; // NX_COMPAT
    return true;
}

bool RecalculateImageSize(std::vector<uint8_t>& binary) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    if (!nt) return false;

    DWORD maxEnd = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER* sec = GetSectionHeader(binary, i);
        DWORD end = sec->VirtualAddress + Align(sec->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
        if (end > maxEnd) maxEnd = end;
    }
    nt->OptionalHeader.SizeOfImage = Align(maxEnd, nt->OptionalHeader.SectionAlignment);
    std::wcout << L"[*] SizeOfImage 재설정 완료: " << nt->OptionalHeader.SizeOfImage << std::endl;
    return true;
}
