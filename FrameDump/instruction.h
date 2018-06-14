#pragma once

#include "../Bin-Capstone/x86.h"

struct x86_operand
{
    x86_op_type type;
    uint64_t value;

    friend std::ofstream& operator<<=(std::ofstream& stream, const x86_operand& value);
    friend std::ifstream& operator>>=(std::ifstream& stream, x86_operand& value);
};

struct x86_instruction
{
    x86_insn id;
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::string representation;

    std::vector<x86_operand> operands;

    friend std::ofstream& operator<<=(std::ofstream& stream, const x86_instruction& value);
    friend std::ifstream& operator>>=(std::ifstream& stream, x86_instruction& value);
};
