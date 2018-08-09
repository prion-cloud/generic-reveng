#pragma once

#include <string>
#include <variant>
#include <vector>

#include <capstone.h>

struct memory_descriptor
{
    unsigned segment;
    unsigned base;
    unsigned index;

    int scale;

    int64_t displacement;

    explicit memory_descriptor(x86_op_mem const& cs_memory_descriptor); // TODO: x86
};

struct operand
{
    unsigned type;
    std::variant<unsigned, int64_t, memory_descriptor, double> value;

    explicit operand(cs_x86_op const& cs_operand); // TODO: x86
};

struct instruction
{

    unsigned id;

    std::vector<uint8_t> code;

    std::vector<operand> operands;

    std::string str_mnemonic;
    std::string str_operands;

    explicit instruction(cs_insn const& cs_instruction);
};
