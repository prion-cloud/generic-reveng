#pragma once

#include <decompilation/instruction.hpp>
#include <decompilation/instruction_set_architecture.hpp>

#include "reil_disassembler.hpp"

namespace dec
{
    class reil_monitor
    {
        reil_disassembler disassembler_;

    public:

        explicit reil_monitor(instruction_set_architecture const& architecture);

        instruction trace(std::uint64_t const& address, std::basic_string_view<std::uint8_t> const& code) const;
    };
}
