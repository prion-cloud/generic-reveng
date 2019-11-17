#include "pe_file.hpp"

namespace grev
{
    pe_file pe_file::inspect(std::u8string_view data_view)
    {
        pe_file file { };

        auto const size = data_view.size();

        file.dos_header = pe_dos_header::inspect(&data_view);
        data_view.remove_prefix(file.dos_header.pe_offset - (size - data_view.size()) + 4);

        // TODO PE/0/0 error (?)

        file.coff_header = pe_coff_header::inspect(&data_view);

        switch (file.coff_header.optional_header_size)
        {
        case 224:
            file.optional_header = pe_optional_header::inspect_32(&data_view);
            break;
        // TODO error (?)
        }

        for (std::size_t section_index{0}; section_index < file.coff_header.section_count; ++section_index)
        {
            auto section_header = pe_section_header::inspect(&data_view);

            if (section_header.section_size < section_header.miscellaneous)
                continue; // TODO (?)

            file.section_headers.push_back(std::move(section_header));
        }

        return file;
    }
}
