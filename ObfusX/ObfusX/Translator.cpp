#include "Translator.h"
#include "VMOpcode.h"
#include <capstone/capstone.h>
#include <cstring>
#include <string>
#include <iostream>

std::vector<uint8_t> TranslateToVM(uint8_t* code, size_t size, bool is64bit) {
    csh handle;
    cs_insn* insn;
    std::vector<uint8_t> bytecode;

    if (cs_open(CS_ARCH_X86, is64bit ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK)
        throw std::runtime_error("Capstone open ½ÇÆÐ");

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    size_t count = cs_disasm(handle, code, size, reinterpret_cast<uint64_t>(code), 0, &insn);

    for (size_t i = 0; i < count; ++i) {
        std::string mnem = insn[i].mnemonic;
        std::string ops = insn[i].op_str;

        if (mnem == "mov" && (strstr(ops.c_str(), "eax") || strstr(ops.c_str(), "rax"))) {
            bytecode.push_back((uint8_t)VMOpcode::MOV_REG_IMM);
            bytecode.push_back(0x00); // R0
            uint64_t val = std::stoull(strchr(ops.c_str(), ',') + 1);
            bytecode.insert(bytecode.end(), (uint8_t*)&val, (uint8_t*)&val + (is64bit ? 8 : 4));
        }
        else if (mnem == "add") {
            bytecode.push_back((uint8_t)VMOpcode::ADD_REG_IMM);
            bytecode.push_back(0x00);
            uint64_t val = std::stoull(strchr(ops.c_str(), ',') + 1);
            bytecode.insert(bytecode.end(), (uint8_t*)&val, (uint8_t*)&val + (is64bit ? 8 : 4));
        }
        else if (mnem == "sub") {
            bytecode.push_back((uint8_t)VMOpcode::SUB_REG_IMM);
            bytecode.push_back(0x00);
            uint64_t val = std::stoull(strchr(ops.c_str(), ',') + 1);
            bytecode.insert(bytecode.end(), (uint8_t*)&val, (uint8_t*)&val + (is64bit ? 8 : 4));
        }
        else if (mnem == "jmp") {
            bytecode.push_back((uint8_t)VMOpcode::JMP);
            uint32_t addr = (uint32_t)insn[i].detail->x86.operands[0].imm;
            bytecode.insert(bytecode.end(), (uint8_t*)&addr, (uint8_t*)&addr + 4);
        }
        else if (mnem == "call") {
            bytecode.push_back((uint8_t)VMOpcode::CALL);
            uint32_t addr = (uint32_t)insn[i].detail->x86.operands[0].imm;
            bytecode.insert(bytecode.end(), (uint8_t*)&addr, (uint8_t*)&addr + 4);
        }
    }

    cs_free(insn, count);
    cs_close(&handle);

    bytecode.push_back((uint8_t)VMOpcode::HALT);
    return bytecode;
}
