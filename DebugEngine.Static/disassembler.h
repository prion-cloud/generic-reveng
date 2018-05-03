#pragma once

#include "../Bin-Capstone/capstone.h"

#define MAX_BYTES 16

// Disassembled machine code instruction
struct instruction
{
    unsigned id { };

    uint64_t address { };

    std::vector<uint8_t> bytes { };

    std::string mnemonic { };
    std::string operands { };

    std::map<x86_reg, std::string> registers { };
};

class disassembler
{
    csh cs_;

public:

    explicit disassembler(uint16_t machine);
    ~disassembler();

    void disassemble(uint8_t bytes[MAX_BYTES], uint64_t address, instruction& instruction) const;
};
