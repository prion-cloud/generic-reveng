#pragma once

struct pe_header_32
{
    IMAGE_DOS_HEADER dos_header { };
    IMAGE_FILE_HEADER file_header { };

    IMAGE_OPTIONAL_HEADER32 optional_header { };

    std::vector<IMAGE_SECTION_HEADER> section_headers { };
};
