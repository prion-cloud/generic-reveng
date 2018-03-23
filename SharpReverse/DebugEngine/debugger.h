#pragma once

#include "instruction_32.h"
#include "register_state_32.h"

class debugger
{
    csh cs_ { };
    uc_engine* uc_ { };

public:

    explicit debugger(std::vector<char> bytes);

    void close();

    instruction_32 debug_32() const;

    register_state_32 get_registers_32() const;
};
