#pragma once

#include "../Bin-Capstone/capstone.h"

#include "instruction.h"

class disassembler
{
    csh cs_;

public:

    explicit disassembler(uint16_t machine);
    ~disassembler();

    instruction_x86 disassemble(uint64_t address, std::vector<uint8_t> code) const;
};
