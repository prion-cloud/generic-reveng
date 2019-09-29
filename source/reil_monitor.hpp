#pragma once

#include <z3++.h>

#include <decompilation/instruction.hpp>
#include <decompilation/instruction_set_architecture.hpp>

#include "reil_disassembler.hpp"

namespace dec
{
    class reil_monitor
    {
        static z3::context context_;

        z3::func_decl mem_;

        reil_disassembler disassembler_;

        std::unordered_set<z3::expr> ip_;

        std::unordered_map<z3::expr, z3::expr> impact_;
        std::unordered_map<z3::expr, z3::expr> temporary_impact_;

    public:

        explicit reil_monitor(instruction_set_architecture const& architecture);

        instruction trace(std::uint64_t const& address, std::basic_string_view<std::uint8_t> const& code);

    private:

        // TODO Make intermediate_instruction an adaptor class?
        z3::expr get(reil_arg_t const& source);
        z3::expr get_mem(reil_arg_t const& source);

        void set(reil_arg_t const& destination, z3::expr const& expression); // TODO -> impact?
        void set_mem(reil_arg_t const& destination, z3::expr const& expression);

        z3::expr create_constant(std::string const& name);
        z3::expr create_value(std::uint64_t value);
    };
}
