#include "Packer.h"
#include "PEParser.h"
#include "StubBlob_x86.h"
#include "StubBlob_x64.h"

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

constexpr uint8_t XOR_KEY = 0x5A;

void EncryptBuffer(std::vector<uint8_t>& buffer, size_t offset, size_t size) {
    for (size_t i = 0; i < size; ++i)
        buffer[offset + i] ^= XOR_KEY;
}

bool PatchMarker(uint8_t* stub, size_t stubSize, uint32_t marker, uint32_t value) {
    for (size_t i = 0; i < stubSize - 4; ++i) {
        if (*(uint32_t*)&stub[i] == marker) {
            *(uint32_t*)&stub[i] = value;
            return true;
        }
    }
    return false;
}

bool RemoveRelocSection(std::vector<uint8_t>& binary) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    IMAGE_SECTION_HEADER* reloc = FindSection(binary, ".reloc");
    if (!reloc) return false;

    std::wcout << L"[*] .reloc 건지 중..." << std::endl;
    memset(&binary[reloc->PointerToRawData], 0, reloc->SizeOfRawData);
    reloc->SizeOfRawData = 0;
    reloc->VirtualAddress = 0;
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

bool PackAndProtect(const std::wstring& inPath, const std::wstring& outPath) {
    std::wcout << L"[*] 파일 로드 중: " << inPath << std::endl;
    std::vector<uint8_t> binary;
    if (!ReadFileToBuffer(inPath, binary)) {
        std::wcerr << L"[!] 파일 열기 실패: " << inPath << std::endl;
        return false;
    }

    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    if (!nt) return false;

    IMAGE_SECTION_HEADER* textSec = FindSection(binary, ".text");
    IMAGE_SECTION_HEADER* rdataSec = FindSection(binary, ".rdata");
    if (!textSec || !rdataSec) return false;

    DWORD textRVA = textSec->VirtualAddress;
    DWORD textRaw = textSec->PointerToRawData;
    DWORD textSize = textSec->SizeOfRawData;
    DWORD rdataRVA = rdataSec->VirtualAddress;
    DWORD rdataRaw = rdataSec->PointerToRawData;
    DWORD rdataSize = rdataSec->SizeOfRawData;
    DWORD epRVA = nt->OptionalHeader.AddressOfEntryPoint;

    std::wcout << L"[*] 세컨 암호화 중..." << std::endl;
    EncryptBuffer(binary, textRaw, textSize);
    EncryptBuffer(binary, rdataRaw, rdataSize);

    const uint8_t* stubCode = nullptr;
    size_t stubSize = 0;
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        std::wcout << L"[*] 대상은 32비트 PE입니다 (x86)" << std::endl;
        stubCode = g_stubCode_x86;
        stubSize = g_stubSize_x86;
    }
    else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::wcout << L"[*] 대상은 64비트 PE입니다 (x64)" << std::endl;
        stubCode = g_stubCode_x64;
        stubSize = g_stubSize_x64;
    }
    else {
        std::wcerr << L"[!] 알 수 없는 PE 아키텍쳐 (Magic: " << std::hex << nt->OptionalHeader.Magic
            << L", Machine: " << nt->FileHeader.Machine << L")" << std::endl;
        return false;
    }

    std::wcout << L"[*] Stub 마커 패치 중..." << std::endl;
    std::vector<uint8_t> stub(stubCode, stubCode + stubSize);
    PatchMarker(stub.data(), stub.size(), 0xAAAAAAAA, epRVA);
    PatchMarker(stub.data(), stub.size(), 0xBBBBBBBB, textRVA);
    PatchMarker(stub.data(), stub.size(), 0xCCCCCCCC, textSize);
    PatchMarker(stub.data(), stub.size(), 0xDDDDDDDD, rdataRVA);
    PatchMarker(stub.data(), stub.size(), 0xEEEEEEEE, rdataSize);

    std::wcout << L"[*] Stub 삽입 중..." << std::endl;
    size_t stubOffset = Align(binary.size(), nt->OptionalHeader.FileAlignment);
    binary.resize(stubOffset + stub.size(), 0);
    memcpy(&binary[stubOffset], stub.data(), stub.size());

    DWORD stubRVA = RVAToVirtualAddress(binary, stubOffset);
    nt->OptionalHeader.AddressOfEntryPoint = stubRVA;

    RemoveRelocSection(binary);
    StripDynamicBase(nt);
    RecalculateImageSize(binary);

    std::wcout << L"[*] 출력 파일 생성 중: " << outPath << std::endl;
    if (!WriteFileFromBuffer(outPath, binary)) {
        std::wcerr << L"[!] 파일 저장 실패" << std::endl;
        return false;
    }

    std::wcout << L"[+] 보호된 실행 파일 생성 완료!" << std::endl;
    return true;
}
