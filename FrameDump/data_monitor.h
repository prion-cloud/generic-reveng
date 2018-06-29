#pragma once

#include "expr.h"

class data_monitor
{
    std::map<x86_reg, expr> map_;

public:

    data_monitor() = default;

    void apply(const instruction_x86& instruction);

private:

    expr safe_at(x86_reg reg) const;

    std::map<x86_reg, expr> inspect_changes(const instruction_x86& instruction) const;
};
