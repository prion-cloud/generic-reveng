#pragma once

struct pe_header
{
    IMAGE_DOS_HEADER dos_header { };
    IMAGE_FILE_HEADER file_header { };

    std::variant<IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64> optional_header;

    std::vector<IMAGE_SECTION_HEADER> section_headers { };
};

void load_x86(std::vector<char> bytes, csh& cs, uc_engine*& uc);
