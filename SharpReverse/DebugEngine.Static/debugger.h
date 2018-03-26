#pragma once

#include "loader.h"

struct instruction_info
{
    uint32_t id;

    uint64_t address;

    uint16_t size;
    
    uint8_t bytes[16];
    
    char mnemonic[32];
    char operands[160];
};
struct register_info
{
    uint64_t registers[9];
};

class debugger
{
    target_machine target_ { };

    csh cs_ { };
    uc_engine* uc_ { };

public:

    target_machine open(std::vector<char> bytes);
    void close();

    instruction_info debug() const;

    register_info inspect_registers() const;
};
