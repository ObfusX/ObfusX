#pragma once
#include <vector>
#include <cstdint>
#include "VMOpcode.h"

class VMInterpreter {
public:
    VMInterpreter(const std::vector<uint8_t>& bytecode);
    void run();

private:
    std::vector<uint8_t> code;
    uint64_t registers[8] = { 0 };
    size_t ip = 0;

    uint8_t fetch8();
    uint32_t fetch32();
    uint64_t fetch64();
    void execute(VMOpcode opcode);
};
