#pragma once

#include <cstdint>
#include <type_traits>

namespace dec
{
    /*!
     *  Disassembled machine code instruction
     */
    struct instruction
    {
        struct address_order
        {
            using is_transparent = std::true_type;

            bool operator()(instruction const& instruction_1, instruction const& instruction_2) const;

            bool operator()(instruction const& instruction, std::uint_fast64_t address) const;
            bool operator()(std::uint_fast64_t address, instruction const& instruction) const;
        };

        std::uint_fast64_t address;
        std::size_t size;
    };
}
