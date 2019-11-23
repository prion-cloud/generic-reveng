#pragma once

#include <generic-reveng/analysis/data_section.hpp>

namespace grev
{
    class address_space_segment
    {
    public:

        struct exclusive_address_order
        {
            using is_transparent = std::true_type;

            bool operator()(address_space_segment const& segment_1, address_space_segment const& segment_2) const;

            bool operator()(address_space_segment const& segment, std::uint32_t address) const;
            bool operator()(std::uint32_t address, address_space_segment const& segment) const;
        };

    private:

        std::uint32_t address_;

        std::size_t raw_offset_;
        std::size_t raw_size_;

        // TODO std::size_t virtual_size_;

    public:

        address_space_segment(std::uint32_t address, std::size_t raw_offset, std::size_t raw_size);

        data_section dissect(std::u8string_view const& data_view, std::uint32_t address) const;
    };
}
