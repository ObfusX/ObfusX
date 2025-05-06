#pragma once
#include <vector>
#include <cstdint>

std::vector<uint8_t> BuildStubVM(const std::vector<uint8_t>& encryptedBytecode, bool is64bit);
