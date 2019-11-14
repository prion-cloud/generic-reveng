#include "pe_section_header.hpp"
#include "reinterpret_copy.hpp"

namespace rev::pe
{
    pe_section_header pe_section_header::inspect(std::u8string_view* const data_view)
    {
        pe_section_header section_header { };

        constexpr std::size_t        pos_miscellaneous{8};
        reinterpret_copy(&section_header.miscellaneous,
                   data_view->substr(pos_miscellaneous));

        constexpr std::size_t        pos_relative_section_address{12};
        reinterpret_copy(&section_header.relative_section_address,
                   data_view->substr(pos_relative_section_address));

        constexpr std::size_t        pos_section_size{16};
        reinterpret_copy(&section_header.section_size,
                   data_view->substr(pos_section_size));

        constexpr std::size_t        pos_section_offset{20};
        reinterpret_copy(&section_header.section_offset,
                   data_view->substr(pos_section_offset));

        constexpr std::size_t    size{40};
        data_view->remove_prefix(size);

        return section_header;
    }
}
