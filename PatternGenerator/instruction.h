#pragma once

#include <capstone.h>

struct instruction
{
    enum operand_type
    {
        op_register,
        op_memory,
        op_immediate,
        op_float
    };
    struct operand
    {
        operand_type type;
        std::variant<x86_reg, x86_op_mem, int64_t, double> value;

        operand(cs_x86_op cs_operand);
    };

    x86_insn id;
    
    bool is_jump;
    bool is_conditional;

    bool sets_flags;

    uint64_t address;

    std::vector<uint8_t> code;

    std::vector<operand> operands;

    std::string str_mnemonic;
    std::string str_operands;

    instruction(cs_insn cs_instruction);

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
