#pragma once
#include <Windows.h>
#include <vector>
#include <cstdint>

extern const unsigned char g_stubCode_x86[];
extern const unsigned int g_stubSize_x86;

bool Patch_Marker(uint8_t* code, size_t size, uint32_t marker, uint32_t value);
bool Generate_Stub_Code(uint32_t textBase, uint32_t textSize, uint32_t oep, std::vector<uint8_t>& output);
