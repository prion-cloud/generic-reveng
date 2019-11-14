#include "loading/reinterpret_copy.hpp"

#include "pe_dos_header.hpp"

namespace grev
{
    pe_dos_header pe_dos_header::inspect(std::u8string_view* const data_view)
    {
        pe_dos_header dos_header { };

        constexpr std::size_t    pos_pe_offset{60};
        reinterpret_copy(&dos_header.pe_offset,
               data_view->substr(pos_pe_offset));

        constexpr std::size_t    size{64};
        data_view->remove_prefix(size);

        return dos_header;
    }
}
