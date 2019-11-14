#pragma once

#include <cstdint>

#include <libopenreil.h>

#include <generic-reveng/analysis-disassembly/reil_disassembler.hpp>

namespace grev
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
