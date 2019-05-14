#pragma once

#include <vector>

#include <decompilation/instruction.hpp>
#include <decompilation/instruction_set_architecture.hpp>

#include <libopenreil.h>

namespace dec
{
    class execution_engine
    {
        reil_t reil_handle_;

        std::vector<reil_inst_t> recent_reil_instructions_;

    public:

        explicit execution_engine(instruction_set_architecture architecture);
        ~execution_engine();

        instruction disassemble(std::uint_fast64_t address, std::basic_string_view<std::byte> const& code);

    private:

        std::unordered_set<std::optional<std::uint_fast64_t>> recent_instruction_jumps();
    };
}
