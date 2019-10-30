#pragma once

#include <cstdint>
#include <vector>

#include <libopenreil.h>

#include <revengine/reil_disassembler.hpp>

namespace rev::dis
{
    class reil_disassembler::handle
    {
        reil_t reil_;
        std::vector<reil_inst_t> reil_instructions_;

    public:

        explicit handle(machine_architecture architecture);

        std::vector<reil_inst_t> disassemble(data_section* data_section);
    };
}
