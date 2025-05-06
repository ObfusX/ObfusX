#pragma once

enum class VMOpcode : uint8_t {
    NOP = 0,
    MOV_REG_IMM,
    ADD_REG_IMM,
    SUB_REG_IMM,
    JMP,
    CALL,
    HALT
};
