#pragma once

#include "../Bin-Unicorn/unicorn.h"

#include "disassembly.h"

class control_flow_x86
{
    const disassembly_x86* disassembly_;

    uint64_t address_;

public:

    explicit control_flow_x86(const disassembly_x86* disassembly, uint64_t address);

    std::vector<control_flow_x86> next() const;
};
