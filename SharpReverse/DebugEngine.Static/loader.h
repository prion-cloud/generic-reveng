#pragma once

struct pe_header
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_FILE_HEADER file_header;

    std::variant<IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64> optional_header;

    std::vector<IMAGE_SECTION_HEADER> section_headers;
};

enum target_machine : uint8_t
{
    machine_x86_32,
    machine_x86_64
};

target_machine load_x86(std::vector<char> bytes, csh& cs, uc_engine*& uc);
