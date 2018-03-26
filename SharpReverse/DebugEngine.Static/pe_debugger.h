#pragma once

#include "pe_loader.h"

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

class pe_debugger
{
    pe_header header_ { };

    csh cs_ { };
    uc_engine* uc_ { };

public:

    int open(std::vector<char> bytes);
    int close();

    pe_header header() const;

    int debug(instruction_info& ins_info) const;

    int inspect_registers(register_info& reg_info) const;
};
