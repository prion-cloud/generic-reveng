#pragma once

#include <set>

#include <revengine/instruction.hpp>

namespace rev
{
    class instruction_block : public std::set<instruction, instruction::address_order> // TODO private
    {
    public:

        struct exclusive_address_order
        {
            using is_transparent = std::true_type;

            bool operator()(instruction_block const& instruction_block_1, instruction_block const& instruction_block_2) const;

            bool operator()(instruction_block const& instruction_block, std::uint64_t address) const;
            bool operator()(std::uint64_t address, instruction_block const& instruction_block) const;
        };

    private:

        instruction_block();

    public:

        template <typename Disassembler>
        instruction_block(Disassembler const& disassembler, data_section data_section);

        std::uint64_t address() const;

        machine_impact impact() const;

        instruction_block extract_head(iterator last);
    };
}

#ifndef LINT
#include <template_instruction_block.cpp>
#endif
