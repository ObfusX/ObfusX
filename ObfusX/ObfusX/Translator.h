#pragma once
#include <vector>
#include <cstdint>

std::vector<uint8_t> TranslateToVM(uint8_t* code, size_t size, bool is64bit);
