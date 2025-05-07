#include "StubBlob_x86.h"
#include <vector>

const unsigned char g_stubCode_x86[] = {
    0xB8, 0xAA, 0xAA, 0xAA, 0xAA,       // mov eax, 0xAAAAAAAA
    0xBB, 0xDD, 0xDD, 0xDD, 0xDD,       // mov ebx, 0xBBBBBBBB
    0xB9, 0xCC, 0xCC, 0xCC, 0xCC,       // mov ecx, 0xCCCCCCCC
    
    0x89, 0xC6,                         // mov esi, eax
    0x89, 0xDA,                         // mov edx, ebx
    0x31, 0xC0,                         // xor eax, eax
    
    0x8A, 0x06,                         // mov al, [esi]
    0x34, 0x5A,                         // xor al, 0x5A
    0x88, 0x06,                         // mov [esi], al
    0x46,                               // inc esi
    0x4A,                               // dec edx
    0x75, 0xF6,                         // jnz decrypt_loop
    
    0xFF, 0xE1                          // jmp ecx
};
const unsigned int g_stubSize_x86 = sizeof(g_stubCode_x86);

bool Patch_Marker(uint8_t* buffer, size_t size, uint32_t marker, uint32_t value)
{
    for (size_t i = 0; i <= size - 4; ++i)
    {
        uint32_t* ptr = reinterpret_cast<uint32_t*>(buffer + i);
        if (*ptr == marker)
        {
            *ptr = value;
            return true;
        }
    }
    return false;
}

bool Generate_Stub_Code(uint32_t textBase, uint32_t textSize, uint32_t oep, std::vector<uint8_t>& output)
{
    std::vector<uint8_t> stub(g_stubCode_x86, g_stubCode_x86 + g_stubSize_x86);

    if (!Patch_Marker(stub.data(), stub.size(), 0xAAAAAAAA, textBase)) {
        return false;
    }
    if (!Patch_Marker(stub.data(), stub.size(), 0xDDDDDDDD, textSize)) {
        return false;
    }
    if (!Patch_Marker(stub.data(), stub.size(), 0xCCCCCCCC, oep)) {
        return false;
    }

    output.insert(output.end(), stub.begin(), stub.end());

    return true;
}








