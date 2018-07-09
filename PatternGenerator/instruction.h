#pragma once

#include <capstone.h>

struct instruction
{
    enum operand_type
    {
        op_register,
        op_immediate,
        op_memory,
        op_float
    };
    struct operand
    {
        operand_type type;
        std::variant<x86_reg, int64_t, x86_op_mem, double> value;

        explicit operand(cs_x86_op cs_operand);
    };

    x86_insn id;

    uint64_t address;

    std::vector<uint8_t> code;

    std::string str_mnemonic;
    std::string str_operands;

    bool flag;

    std::vector<operand> operands;

    explicit instruction(cs_insn cs_instruction);

    bool is_jump() const;
    bool is_conditional() const;

    std::string to_string(bool full) const;
};

class instruction_sequence
{
    std::vector<instruction> instructions_;

public:

    explicit instruction_sequence(std::vector<instruction> instructions);

    std::vector<instruction_sequence> power() const;

    std::vector<instruction> const* operator->() const;

    friend bool operator<(const instruction_sequence& sequence1, const instruction_sequence& sequence2);
};
