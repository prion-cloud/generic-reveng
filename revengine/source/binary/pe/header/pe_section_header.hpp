#pragma once

#include <string_view>

namespace rev::bin::pe
{
    struct pe_section_header
    {
        std::uint32_t miscellaneous;
        std::uint32_t relative_section_address;
        std::uint32_t section_size;
        std::uint32_t section_offset;

        static pe_section_header inspect(std::u8string_view* data_view);
    };
}
