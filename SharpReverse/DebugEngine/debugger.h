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
    uint64_t eax, ebx, ecx, edx, esp, ebp, esi, edi, eip;
};

class debugger
{
    csh cs_ { };
    uc_engine* uc_ { };

public:

    target_machine open(std::vector<char> bytes);
    void close();

    instruction_info debug() const;

    register_info inspect_registers() const;
};
