#pragma once

struct pe_header
{
    IMAGE_DOS_HEADER dos_header { };
    IMAGE_FILE_HEADER file_header { };

    std::optional<IMAGE_OPTIONAL_HEADER32> optional_header32 { };
    std::optional<IMAGE_OPTIONAL_HEADER64> optional_header64 { };

    std::vector<IMAGE_SECTION_HEADER> section_headers { };
};
