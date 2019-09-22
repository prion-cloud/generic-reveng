#pragma once

#include <set>
#include <vector>

namespace dec
{
    class memory
    {
        struct section
        {
            struct exclusive_address_order
            {
                using is_transparent = std::true_type;

                bool operator()(section const& section_1, section const& section_2) const;

                bool operator()(section const& section, std::uint_fast64_t address) const;
                bool operator()(std::uint_fast64_t address, section const& section) const;
            };

            std::uint_fast64_t address;
            std::basic_string_view<std::uint_fast8_t> data;
        };

        std::vector<std::uint_fast8_t> data_;

        std::set<section, section::exclusive_address_order> sections_;

    public:

        explicit memory(std::vector<std::uint_fast8_t> data); // TODO Real loading mechanism

        std::basic_string_view<std::uint_fast8_t> operator[](std::uint_fast64_t address) const;
    };
}
