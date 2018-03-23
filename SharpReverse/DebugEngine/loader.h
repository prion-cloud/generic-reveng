#pragma once

#define VISIT(var, member) visit([](auto x) { return x.member; }, var)
#define VISIT_CAST(var, member, cast) visit([](auto x) { return static_cast<cast>(x.member); }, var)

struct pe_header
{
    IMAGE_DOS_HEADER dos_header { };
    IMAGE_FILE_HEADER file_header { };

    std::variant<IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64> optional_header;

    std::vector<IMAGE_SECTION_HEADER> section_headers { };
};

void load_x86(std::vector<char> bytes, csh& cs, uc_engine*& uc);
