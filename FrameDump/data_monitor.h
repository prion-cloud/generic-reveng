#pragma once

#include "expr_tree.h"

class data_monitor_x86
{
    std::map<x86_reg, const expr_tree_x86*> register_map_;
    std::map<expr_tree_x86, const expr_tree_x86*> memory_map_;

public:

    data_monitor_x86() = default;

    void apply(const instruction_x86& instruction);

    std::string check(x86_reg reg) const;

    std::vector<std::string> all() const;

private:

    const expr_tree_x86* safe_at_reg(x86_reg reg) const;
    const expr_tree_x86* safe_at_mem(const expr_tree_x86* expr) const;

    const expr_tree_x86* to_expr(x86_op_mem mem) const;

    void inspect_updates(const instruction_x86& instruction,
        std::map<x86_reg, const expr_tree_x86*>& reg_updates, std::map<expr_tree_x86, const expr_tree_x86*>& mem_updates) const;
};
