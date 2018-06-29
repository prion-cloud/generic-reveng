#pragma once

#include "expr.h"

class data_monitor
{
    std::map<x86_reg, expr> register_map_;
    std::map<expr, expr> memory_map_;

public:

    data_monitor() = default;

    void apply(const instruction_x86& instruction);

    std::string check(x86_reg reg) const;

private:

    expr safe_at_reg(x86_reg reg) const;
    expr safe_at_mem(expr expr) const;

    expr to_expr(x86_op_mem mem) const;

    void inspect_updates(const instruction_x86& instruction,
        std::map<x86_reg, expr>& reg_updates, std::map<expr, expr>& mem_updates) const;
};
