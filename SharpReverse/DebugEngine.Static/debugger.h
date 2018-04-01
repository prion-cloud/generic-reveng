#pragma once

#include "loader.h"

struct instruction_info
{
    uint32_t id;

    char address[19];

    uint16_t size;
    
    uint8_t bytes[16];
    
    char mnemonic[32];
    char operands[160];
};

struct register_info
{
    char name[4];
    char value[19];
};

struct memory_info
{
    char begin[19];
    char size[19];

    char permissions[4];
};

class debugger
{
    csh cs_ { };
    uc_engine* uc_ { };

    uint64_t scale_ { };

    std::vector<int> regs_ { };
    int ip_index_ { };

    std::string format_ { };

    unsigned reg_index_;
    unsigned mem_index_;

public:

    debugger();
    
    int load(const loader& l, std::vector<char> bytes);
    int unload();

    int ins(instruction_info& ins_info) const;

    int reg(register_info& reg_info);

    int mem(memory_info& mem_info);
};
