#pragma once

#include <cstdint>

namespace grev
{
    struct import_descriptor
    {
        std::uint32_t name_address;
        std::uint32_t origin_address;
        std::uint32_t reference_address;
    };
}
