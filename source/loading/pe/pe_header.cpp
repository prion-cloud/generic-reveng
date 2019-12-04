#include "pe_header.hpp"

namespace grev
{
    pe_header pe_header::inspect(std::u8string_view data_view)
    {
        pe_header header { };

        auto const size = data_view.size();

        header.dos = pe_dos_header::inspect(&data_view);
        data_view.remove_prefix(header.dos.pe_offset - (size - data_view.size()) + 4);

        // TODO PE/0/0 error (?)

        header.coff = pe_coff_header::inspect(&data_view);

        switch (header.coff.optional_header_size)
        {
        case 224:
            header.optional = pe_optional_header::inspect(&data_view);
            break;
        // TODO error (?)
        }

        for (std::size_t section_index{0}; section_index < header.coff.section_count; ++section_index)
            header.sections.push_back(pe_section_header::inspect(&data_view)); // TODO section_header.miscellaneous

        return header;
    }
}
