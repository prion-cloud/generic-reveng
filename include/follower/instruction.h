#pragma once

#include <string>
#include <unordered_set>
#include <vector>

#include "../../submodules/capstone/include/capstone.h"

struct instruction
{
    unsigned id { };

    std::unordered_set<unsigned> groups;

    uint64_t address { };

    std::vector<uint8_t> code;

    std::string mnemonic;
    std::string operand_string;

    instruction() = default;
    explicit instruction(cs_insn cs_instruction);
};
