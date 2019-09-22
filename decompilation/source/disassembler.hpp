#pragma once

#include <memory>
#include <vector>

#include <libopenreil.h>

#include <decompilation/instruction_set_architecture.hpp>

namespace dec
{
    class disassembler
    {
        reil_t reil_handle_;

        std::unique_ptr<std::vector<reil_inst_t>> recent_reil_instructions_;

    public:

        explicit disassembler(instruction_set_architecture architecture);

        std::vector<reil_inst_t>
            read(std::uint_fast64_t address, std::basic_string_view<std::uint_fast8_t> const& code) const;
    };
}
