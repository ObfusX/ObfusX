#pragma once
#include <vector>
#include <string>
#include <windows.h>

IMAGE_NT_HEADERS* GetNtHeaders(const std::vector<uint8_t>& binary);
IMAGE_SECTION_HEADER* FindSection(std::vector<uint8_t>& buffer, const char* name);
IMAGE_SECTION_HEADER* GetSectionHeader(const std::vector<uint8_t>& binary, int index);
bool AddSection(const char* name, std::vector<uint8_t>& binary, const std::vector<uint8_t>& stub); // AddSection Function
bool ReadFileToBuffer(const std::wstring& path, std::vector<uint8_t>& out);
bool WriteFileFromBuffer(const std::wstring& path, const std::vector<uint8_t>& data);
DWORD Align(DWORD size, DWORD align);

bool FixRelocSection(std::vector<uint8_t>& binary);
bool StripDynamicBase(IMAGE_NT_HEADERS* nt);
bool RecalculateImageSize(std::vector<uint8_t>& binary);