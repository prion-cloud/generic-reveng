#pragma once

#include <vector>

#include <reil_ir.h>
#include <z3++.h>

#include <decompilation/instruction_impact.hpp>

namespace dec
{
    class monitor
    {
        z3::context context_;

        z3::func_decl mem_;

        instruction_impact impact_;
        std::unordered_map<std::string, z3::expr> impact_temporary_;

    public:

        monitor();

        std::unordered_map<z3::expr, z3::expr> trace(std::vector<reil_inst_t> const& intermediate_instructions);

    private:

        // TODO Make intermediate_instruction an adaptor class?
        z3::expr get(reil_arg_t const& source);
        z3::expr get_mem(reil_arg_t const& source);

        void set(reil_arg_t const& destination, z3::expr const& expression); // TODO -> impact?
        void set_mem(reil_arg_t const& destination, z3::expr const& expression);

        z3::expr create_constant(std::string const& name);
        z3::expr create_value(std::uint_fast64_t value);
    };
}
