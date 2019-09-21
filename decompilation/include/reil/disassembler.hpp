#pragma once

#include <memory>
#include <string_view>
#include <vector>

#include <libopenreil.h>

namespace reil
{
    class disassembler
    {
        reil_t reil_handle_;

        std::unique_ptr<std::vector<reil_inst_t>> recent_reil_instructions_;

    public:

        explicit disassembler(reil_arch_t architecture);

        std::vector<reil_inst_t> operator()(std::uint_fast64_t address, std::basic_string_view<std::byte> const& code) const;
    };
}
