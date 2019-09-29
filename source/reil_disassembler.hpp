#pragma once

#include <memory>
#include <vector>

#include <libopenreil.h>

namespace dec
{
    class reil_disassembler
    {
        reil_t reil_handle_;

        std::unique_ptr<std::vector<reil_inst_t>> reil_instructions_;

    public:

        explicit reil_disassembler(reil_arch_t architecture);

        [[nodiscard]] std::vector<reil_inst_t>
            lift(std::uint64_t const& address, std::basic_string_view<std::uint8_t> const& code) const;
    };
}
