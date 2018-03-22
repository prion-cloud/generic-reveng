#include "stdafx.h"

#include "binary_reader.h"

binary_reader::binary_reader(const std::string file_name)
{
    fopen_s(&stream_, file_name.c_str(), "rb");

    fseek(stream_, 0, SEEK_END);
    length_ = ftell(stream_);
    rewind(stream_);
}

void binary_reader::close() const
{
    fclose(stream_);
}

long binary_reader::length() const
{
    return length_;
}

long binary_reader::offset() const
{
    return ftell(stream_);
}

std::optional<pe_header_32> binary_reader::inspect_header()
{
    const auto n = offset();

    const auto find = [this](std::optional<pe_header_32>& header_opt)
    {
        header_opt = std::nullopt;

        auto mz_id = read_value<uint16_t>(0);
        if (mz_id != 0x5A4D)
            return;

        auto dh = read_value<IMAGE_DOS_HEADER>(0);

        // TODO: dh -> magic_number?

        auto pe_id = read_value<uint32_t>(dh.e_lfanew);
        if (pe_id != 0x00004550)
            return;

        auto fh = read_value<IMAGE_FILE_HEADER>();

        const auto oh_size = fh.SizeOfOptionalHeader;

        IMAGE_OPTIONAL_HEADER32 oh;
        if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER32))
            oh = read_value<IMAGE_OPTIONAL_HEADER32>();
        else return;

        auto shs = read_vector<IMAGE_SECTION_HEADER>(fh.NumberOfSections);

        std::optional<pe_header_32> header = pe_header_32();

        header->dos_header = dh;
        header->file_header = fh;

        header->optional_header = oh;

        header->section_headers = shs;

        header_opt = header;
    };

    std::optional<pe_header_32> header_opt;
    find(header_opt); // TODO: Catch exception?

    seek(n);

    return header_opt;
}

void binary_reader::seek() const
{
    seek(0);
}
void binary_reader::seek(const long offset) const
{
    seek(offset, SEEK_SET);
}
void binary_reader::seek(const long offset, const int origin) const
{
    fseek(stream_, offset, origin);
}
