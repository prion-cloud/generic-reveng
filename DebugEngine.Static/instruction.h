#pragma once

#include "../Bin-Capstone/capstone.h"

enum class operand_type
{
    reg,
    imm,
    mem,
    flp
};
enum class instruction_type
{
    any,
    jmp,
    call,
    ret,
    push,
    pop,
    mov,
    cond,
    arith
};

struct operand_x86
{
    operand_type type;

    union
    {
		x86_reg reg;
		int64_t imm;
		x86_op_mem mem;
		double flp;
	};

    operand_x86(cs_x86_op cs_op);
};
struct instruction_x86
{
    x86_insn id;

    instruction_type type;
    bool is_conditional;

    uint64_t address;

    std::vector<uint8_t> code;

    std::string str_mnemonic;
    std::string str_operands;

    std::vector<operand_x86> operands;

    instruction_x86(cs_insn cs_insn);
};
