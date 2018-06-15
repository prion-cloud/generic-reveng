#pragma once

#include "../Bin-Capstone/capstone.h"

#define MAX_BYTES 16
#define MAX_STR 64
#define MAX_OPS 4

class instruction_x86
{
    uint16_t id_;

    uint8_t size_;
    uint8_t op_count_;

    uint8_t operand_types_[MAX_OPS];

    uint64_t address_;

    uint8_t bytes_[MAX_BYTES];

    char str_[MAX_STR];

    uint64_t operand_values_[MAX_OPS];

public:

    instruction_x86();
    instruction_x86(cs_insn cs_instruction);

    static std::shared_ptr<std::set<instruction_x86>> load(std::string file_name);
    static void save(std::string file_name, std::shared_ptr<std::vector<instruction_x86>> disassembly);

    friend bool operator<(const instruction_x86& left, const instruction_x86& right);
};
