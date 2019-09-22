#pragma once

#include <unordered_map>

#include <reil_ir.h>
#include <z3++.h>

namespace dec
{
    class monitor
    {
        z3::context context_;

        std::unordered_map<std::string, z3::expr> impact_;
        std::unordered_map<std::string, z3::expr> impact_temp_;

    public:

        z3::expr get(reil_arg_t const& arg);
        void set(reil_arg_t const& arg, z3::expr expr);

        std::unordered_map<std::string, z3::expr> impact();
    };
}
