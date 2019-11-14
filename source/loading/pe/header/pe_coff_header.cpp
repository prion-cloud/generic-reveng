#include "loading/reinterpret_copy.hpp"

#include "pe_coff_header.hpp"

namespace grev
{
    pe_coff_header pe_coff_header::inspect(std::u8string_view* const data_view)
    {
        pe_coff_header coff_header { };

        constexpr std::size_t     pos_machine_id{4};
        reinterpret_copy(&coff_header.machine_id,
                data_view->substr(pos_machine_id));

        constexpr std::size_t     pos_section_count{6};
        reinterpret_copy(&coff_header.section_count,
                data_view->substr(pos_section_count));

        constexpr std::size_t     pos_optional_header_size{20};
        reinterpret_copy(&coff_header.optional_header_size,
                data_view->substr(pos_optional_header_size));

        constexpr std::size_t     pos_relative_entry_point_address{40};
        reinterpret_copy(&coff_header.relative_entry_point_address,
                data_view->substr(pos_relative_entry_point_address));

        constexpr std::size_t    size{48};
        data_view->remove_prefix(size);

        return coff_header;
    }
}
