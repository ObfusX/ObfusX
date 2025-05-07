#include "Packer.h"
#include "PEParser.h"
#include "Crypto.h"
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

    // XOR Encrypt Block
    {
        textSec->Characteristics |= IMAGE_SCN_MEM_WRITE;
		rdataSec->Characteristics |= IMAGE_SCN_MEM_WRITE;
    
        DWORD textRVA = textSec->VirtualAddress;
        DWORD textRaw = textSec->PointerToRawData;
        DWORD textSize = textSec->SizeOfRawData;
        DWORD rdataRVA = rdataSec->VirtualAddress;
        DWORD rdataRaw = rdataSec->PointerToRawData;
        DWORD rdataSize = rdataSec->SizeOfRawData;

        std::wcout << L"[*] 세컨 암호화 중..." << std::endl;
        std::vector<uint8_t> textRawData(binary.begin() + textRaw, binary.begin() + textRaw + textSize);
        EncryptBytecode(textRawData);
        memcpy(&binary[textRaw], textRawData.data(), textSize);

		std::vector<uint8_t> rdataRawData(binary.begin() + rdataRaw, binary.begin() + rdataRaw + rdataSize);
		EncryptBytecode(rdataRawData);
		memcpy(&binary[rdataRaw], rdataRawData.data(), rdataSize);

    }


    const uint8_t* stubCode = nullptr;
    size_t stubSize = 0;
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) 
    {
        std::wcout << L"[*] 대상은 32비트 PE입니다 (x86)" << std::endl;
        stubCode = g_stubCode_x86;
        stubSize = g_stubSize_x86;
    }
    else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) 
    {
        std::wcout << L"[*] 대상은 64비트 PE입니다 (x64)" << std::endl;
        stubCode = g_stubCode_x64;
        stubSize = g_stubSize_x64;
    }
    else 
    {
        std::wcerr << L"[!] 알 수 없는 PE 아키텍쳐 (Magic: " << std::hex << nt->OptionalHeader.Magic << L", Machine: " << nt->FileHeader.Machine << L")" << std::endl;
        return false;
    }

    std::wcout << L"[*] Stub 마커 패치 중..." << std::endl;

    DWORD epVA = nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint;
    DWORD textBaseVA = nt->OptionalHeader.ImageBase + textSec->VirtualAddress;
    DWORD textSize = textSec->Misc.VirtualSize;

    std::vector<uint8_t> stub;
    Generate_Stub_Code(textBaseVA, textSize, epVA, stub);

    std::wcout << L"[*] Stub 삽입 중..." << std::endl;
	AddSection(".stub", binary, stub);
    nt = GetNtHeaders(binary);


    IMAGE_SECTION_HEADER* stubSec = FindSection(binary, ".stub");
    if (!stubSec) {
        std::wcerr << L"[!] .stub 섹션을 찾을 수 없습니다!" << std::endl;
        return false;
    }

    DWORD stubRVA = stubSec->VirtualAddress;
    std::wcout << L"[*] EntryPoint를 STUB 주소로 변경 완료: RVA = 0x"
        << std::hex << stubRVA << std::endl;

	FixRelocSection(binary);
    StripDynamicBase(nt);
    RecalculateImageSize(binary);
    
    nt->OptionalHeader.AddressOfEntryPoint = stubRVA;


    std::wcout << L"[*] 출력 파일 생성 중: " << outPath << std::endl;
    if (!WriteFileFromBuffer(outPath, binary)) {
        std::wcerr << L"[!] 파일 저장 실패" << std::endl;
        return false;
    }

    std::wcout << L"[+] 보호된 실행 파일 생성 완료!" << std::endl;
    return true;
}
