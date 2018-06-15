#pragma once

#include "../Bin-Capstone/capstone.h"

#define INS_MAX_BYTES 16
#define INS_MAX_STR 64
#define INS_MAX_OPS 4

class instruction_x86
{
    uint16_t id_;

    uint8_t size_;
    uint8_t op_count_;

    uint8_t operand_types_[INS_MAX_OPS];

    uint64_t address_;

    uint8_t bytes_[INS_MAX_BYTES];

    char str_[INS_MAX_STR];

    uint64_t operand_values_[INS_MAX_OPS];

public:

    instruction_x86();
    instruction_x86(cs_insn cs_instruction);
};
