#pragma once

#include "control_flow.h"
#include "disassembly.h"

class obfuscation_framed_x86
{
    const disassembly_x86* disassembly_;

    uint64_t address_;

    control_flow_x86 control_flow_;

public:

    explicit obfuscation_framed_x86(const disassembly_x86* disassembly, uint64_t address);

    void test() const;

    static std::vector<obfuscation_framed_x86> pick_all(const disassembly_x86* disassembly);
};
