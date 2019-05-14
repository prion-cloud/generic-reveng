#pragma once

#include <set>

#include <decompilation/instruction.hpp>

namespace dec
{
    struct instruction_block : std::set<instruction, instruction::address_order>
    {
        struct exclusive_address_order
        {
            using is_transparent = std::true_type;

            bool operator()(instruction_block const& instruction_block_1, instruction_block const& instruction_block_2) const;

            bool operator()(instruction_block const& instruction_block, std::uint_fast64_t address) const;
            bool operator()(std::uint_fast64_t address, instruction_block const& instruction_block) const;
        };

        using std::set<instruction, instruction::address_order>::set;
    };
}
