#pragma once

#include <functional>

#include "control_flow.h"
#include "disassembly.h"
#include "taint.h"

class obfuscation_x86
{
    const disassembly_x86* disassembly_;

    uint64_t address_;

    control_flow_x86 current_;

    std::map<operand_x86, var_expr> taints_;

    std::vector<std::vector<instruction_x86>> emerged_;

public:

    explicit obfuscation_x86(const disassembly_x86* disassembly, uint64_t address);

    void emerge_calls();

    static std::vector<obfuscation_x86> pick_all(const disassembly_x86* disassembly);
};
