#pragma once

#include <revengine/data_section.hpp>
#include <revengine/machine_impact.hpp>

namespace rev
{
    class instruction
    {
    public:

        struct address_order
        {
            using is_transparent = std::true_type;

            bool operator()(instruction const& instruction_1, instruction const& instruction_2) const;

            bool operator()(instruction const& instruction, std::uint64_t address) const;
            bool operator()(std::uint64_t address, instruction const& instruction) const;
        };

    private:

        std::uint64_t address_;
        std::size_t size_;

        machine_impact impact_;

    public:

        template <typename Disassembler>
        instruction(Disassembler const& disassembler, data_section data_section);

        std::uint64_t address() const;
        std::size_t size() const;

        machine_impact const& impact() const;
    };
}

#ifndef LINT
#include <template_instruction.cpp>
#endif
