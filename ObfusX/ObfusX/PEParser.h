#pragma once
#include <vector>
#include <string>
#include <windows.h>

IMAGE_NT_HEADERS* GetNtHeaders(const std::vector<uint8_t>& binary);
IMAGE_SECTION_HEADER* FindSection(std::vector<uint8_t>& buffer, const char* name);
IMAGE_SECTION_HEADER* GetSectionHeader(const std::vector<uint8_t>& binary, int index);
DWORD RVAToVirtualAddress(std::vector<uint8_t>& buffer, size_t fileOffset);
bool ReadFileToBuffer(const std::wstring& path, std::vector<uint8_t>& out);
bool WriteFileFromBuffer(const std::wstring& path, const std::vector<uint8_t>& data);
DWORD Align(DWORD size, DWORD align);