#pragma once

#include <string>
#include <unordered_set>
#include <vector>

#include "../../submodules/capstone/include/capstone.h"
#include "../../submodules/unicorn/include/unicorn/unicorn.h"

enum class architecture
{
    arm,
    arm64,
    mips,
    x86,
    ppc,
    sparc
};

enum class mode
{
    width16,
    width32,
    width64
};

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

cs_arch to_cs(architecture const architecture);
cs_mode to_cs(mode const mode);

uc_arch to_uc(architecture const architecture);
uc_mode to_uc(mode const mode);
