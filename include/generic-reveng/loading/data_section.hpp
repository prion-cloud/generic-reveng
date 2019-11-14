#pragma once

#include <string_view>

namespace grev
{
    struct data_section
    {
        std::uint64_t address;
        std::u8string_view data;
    };
}
