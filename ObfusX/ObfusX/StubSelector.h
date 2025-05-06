#pragma once

#include "PEParser.h"
#include "StubBlob_x86.h"
#include "StubBlob_x64.h"

inline const uint8_t* SelectStub(const std::vector<uint8_t>& binary, size_t& stubSize) {
    IMAGE_NT_HEADERS* nt = GetNtHeaders(binary);
    if (!nt) return nullptr;

    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        stubSize = g_stubSize_x86;
        return g_stubCode_x86;
    }
    else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        stubSize = g_stubSize_x64;
        return g_stubCode_x64;
    }
    return nullptr;
}
