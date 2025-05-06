#include "ArchDetect.h"
#include <windows.h>
#include <vector>

bool IsPE64Bit(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    if (buffer.size() < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) return false;
    const IMAGE_NT_HEADERS64* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + dos->e_lfanew);
    return nt64->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}
