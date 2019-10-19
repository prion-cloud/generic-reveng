#pragma once

#include <string_view>

namespace dec
{
    struct data_section
    {
        struct exclusive_address_order
        {
            using is_transparent = std::true_type;

            bool operator()(data_section const& section_1, data_section const& section_2) const;

            bool operator()(data_section const& section, std::uint64_t address) const;
            bool operator()(std::uint64_t address, data_section const& section) const;
        };

        std::uint64_t address;
        std::basic_string_view<std::uint8_t> data; // TODO std::span<std::uint8_t>
    };
}
