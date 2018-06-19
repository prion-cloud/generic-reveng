#pragma once

#include "../Bin-Unicorn/unicorn.h"

#include "disassembly.h"
#include "taint.h"

struct assignment
{
    operand_x86 source, destination;

    assignment(operand_x86 source, operand_x86 destination);
};

class control_flow_x86
{
    const disassembly_x86* disassembly_;

    uint64_t address_;

    code_constraint constraint_;

public:

    explicit control_flow_x86(const disassembly_x86* disassembly, uint64_t address, code_constraint constraint);

    instruction_x86 instruction() const;

    std::vector<control_flow_x86> next(std::optional<assignment>& asng) const;

private:

    operand_x86 normalize(operand_x86 operand) const;
};
