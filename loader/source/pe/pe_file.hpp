#pragma once

#include <vector>

#include "header/pe_coff_header.hpp"
#include "header/pe_dos_header.hpp"
#include "header/pe_optional_header.hpp"
#include "header/pe_section_header.hpp"

namespace rev::pe
{
    struct pe_file
    {
        pe_dos_header dos_header;
        pe_coff_header coff_header;
        pe_optional_header optional_header;

        std::vector<pe_section_header> section_headers;

        static pe_file inspect(std::u8string_view* data_view);
    };
}
