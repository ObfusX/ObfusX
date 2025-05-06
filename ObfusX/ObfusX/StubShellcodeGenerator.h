#pragma once
#include <vector>
#include <cstdint>

std::vector<uint8_t> GenerateStubShellcode(bool is64Bit, uint32_t epRVA, uint32_t textRVA, uint32_t textSize, uint32_t rdataRVA, uint32_t rdataSize);