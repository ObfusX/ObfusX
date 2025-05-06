#include "VMInterpreter.h"
#include <iostream>

VMInterpreter::VMInterpreter(const std::vector<uint8_t>& bytecode) : code(bytecode) {}

uint8_t VMInterpreter::fetch8() {
    return code[ip++];
}

uint32_t VMInterpreter::fetch32() {
    uint32_t val = *reinterpret_cast<uint32_t*>(&code[ip]);
    ip += 4;
    return val;
}

uint64_t VMInterpreter::fetch64() {
    uint64_t val = *reinterpret_cast<uint64_t*>(&code[ip]);
    ip += 8;
    return val;
}

void VMInterpreter::execute(VMOpcode opcode) {
    switch (opcode) {
    case VMOpcode::NOP:
        break;
    case VMOpcode::MOV_REG_IMM: {
        uint8_t reg = fetch8();
#if defined(_WIN64)
        uint64_t val = fetch64();
#else
        uint32_t val = fetch32();
#endif
        registers[reg] = val;
        break;
    }
    case VMOpcode::ADD_REG_IMM: {
        uint8_t reg = fetch8();
#if defined(_WIN64)
        uint64_t val = fetch64();
#else
        uint32_t val = fetch32();
#endif
        registers[reg] += val;
        break;
    }
    case VMOpcode::SUB_REG_IMM: {
        uint8_t reg = fetch8();
#if defined(_WIN64)
        uint64_t val = fetch64();
#else
        uint32_t val = fetch32();
#endif
        registers[reg] -= val;
        break;
    }
    case VMOpcode::JMP: {
        size_t target = fetch32();
        ip = target;
        break;
    }
    case VMOpcode::CALL: {
        size_t target = fetch32();
        std::cout << "[!] CALL to 0x" << std::hex << target << std::dec << "\n";
        break;
    }
    case VMOpcode::HALT:
        std::cout << "[*] ObfusX VM halted.\n";
        for (int i = 0; i < 4; ++i)
            std::cout << " R" << i << " = " << registers[i] << "\n";
        exit(0);
    }
}

void VMInterpreter::run() {
    while (ip < code.size()) {
        auto opcode = static_cast<VMOpcode>(fetch8());
        execute(opcode);
    }
}
