#pragma once

#include <string_view>

namespace dec
{
    struct data_section
    {
        struct exclusive_address_order
        {
            using is_transparent = std::true_type;

            bool operator()(data_section const& a, data_section const& b) const;

            bool operator()(data_section const& a, std::uint_fast64_t b) const;
            bool operator()(std::uint_fast64_t a, data_section const& b) const;
        };

        std::uint_fast64_t address;
        std::basic_string_view<std::byte> bytes;
    };
}
