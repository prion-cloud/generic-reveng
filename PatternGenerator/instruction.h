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

    std::string to_string(bool full) const;

    std::wstring get_representation() const;
};

struct instruction_sequence_representation
{
    std::vector<std::wstring> value;

    friend bool operator<(const instruction_sequence_representation& seq1, const instruction_sequence_representation& seq2);
};

class instruction_sequence
{
    std::vector<instruction> instructions_;

public:

    instruction_sequence() = default;
    explicit instruction_sequence(std::vector<instruction> instructions);

    instruction_sequence_representation get_representation(std::map<x86_reg, std::wstring>& reg_map, std::map<int64_t, std::wstring>& num_map) const;

    std::vector<instruction_sequence> power() const;

    std::vector<instruction>* operator->();
    std::vector<instruction> const* operator->() const;

    friend bool operator<(const instruction_sequence& sequence1, const instruction_sequence& sequence2);
};
