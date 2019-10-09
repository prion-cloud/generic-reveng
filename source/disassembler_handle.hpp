#pragma once

#include <cstdint>
#include <vector>

#include <libopenreil.h>

#include <decompilation/disassembler.hpp>

namespace dec
{
    class disassembler::handle
    {
        reil_t reil_;
        std::vector<reil_inst_t> reil_instructions_;

    public:

        explicit handle(instruction_set_architecture architecture);

        std::vector<reil_inst_t> disassemble(data_section const& data_section);
    };
}
