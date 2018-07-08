#pragma once

#include "../Bin-Capstone/capstone.h"
#include "../Bin-Unicorn/unicorn.h"

#include "instruction.h"

class disassembly
{
    csh cs_;
    uc_engine* uc_;

public:

    explicit disassembly(std::vector<uint8_t> code);

    // TODO

    std::map<x86_reg, uint64_t> get_context();
    void set_context(std::map<x86_reg, uint64_t> context);
};
