#pragma once

#include "../Bin-Capstone/capstone.h"

enum operand_type
{
    op_register,
    op_immediate,
    op_memory,
    op_float
};
enum instruction_type
{
    ins_unknown,
    ins_jump,
    ins_move,
    ins_push,
    ins_pop,
    ins_call,
    ins_return,
    ins_conditon,
    ins_arithmetic
};

struct operand_x86
{
    operand_type type { };

    std::variant<x86_reg, int64_t, x86_op_mem, double> value;
    
    operand_x86() = default;
    operand_x86(cs_x86_op cs_op);
};
struct instruction_x86
{
    x86_insn id { };

    instruction_type type { };
    bool is_conditional { };
    bool is_volatile { };

    uint64_t address { };

    std::vector<uint8_t> code;

    std::string str_mnemonic;
    std::string str_operands;

    std::vector<operand_x86> operands;

    instruction_x86() = default;
    instruction_x86(cs_insn cs_insn);
};
