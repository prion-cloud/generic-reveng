#pragma once

#include "../Bin-Capstone/capstone.h"

#define INS_MAX_OPS 2

struct operand_x86
{
    x86_op_type type;

    uint8_t value8;
    int64_t value64;

    operand_x86();
    operand_x86(x86_op_type type, uint8_t value8, int64_t value64);
};

class instruction_x86
{
    uint16_t id_;

    uint8_t size_;

    uint8_t op_count_;

    uint8_t op_type_[INS_MAX_OPS];

    uint8_t op_value8_[INS_MAX_OPS];
    int64_t op_value64_[INS_MAX_OPS];

    uint64_t address_;

public:

    instruction_x86();
    instruction_x86(cs_insn cs_instruction);

    x86_insn identification() const;

    size_t size() const;

    uint64_t address(uint64_t virtual_base) const;

    operand_x86 operand_at(unsigned index) const;
};
