#pragma once

#include <unordered_map>
#include <unordered_set>
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

    public:

        monitor();

        instruction_impact trace(std::vector<reil_inst_t> const& intermediate_instructions);

    private:

        // TODO Make intermediate_instruction an adaptor class?
        z3::expr get(instruction_impact const& impact, reil_arg_t const& reil_argument);
        void set(instruction_impact& impact, reil_arg_t const& reil_argument, z3::expr const& expression); // TODO -> impact?

        z3::expr get_mem(instruction_impact const& impact, reil_arg_t const& reil_argument);
        void set_mem(instruction_impact& impact, reil_arg_t const& reil_argument, z3::expr const& expression);

        z3::expr create_constant(std::string const& name);
        z3::expr create_value(std::uint_fast64_t value);
    };
}
