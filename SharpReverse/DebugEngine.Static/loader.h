#pragma once

class loader
{
public:

    virtual ~loader() = default;

    virtual int load(std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index) const = 0;
};

struct pe_header
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_FILE_HEADER file_header;

    std::variant<IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64> optional_header;

    std::vector<IMAGE_SECTION_HEADER> section_headers;
};

class pe_loader : public loader
{
public:

    int load(std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index) const override;
};
