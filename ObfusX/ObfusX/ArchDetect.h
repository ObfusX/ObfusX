#pragma once
#include <vector>
#include <windows.h>

bool Is64BitPE(const std::vector<uint8_t>& binary);
