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

std::optional<pe_header_32> binary_reader::search_header()
{
    const auto n = offset();

    const auto find = [this](std::optional<pe_header_32>& header_opt)
    {
        header_opt = std::nullopt;

        seek();

        uint16_t mz_id;
        if (read(mz_id) || mz_id != 0x5A4D)
            return;

        seek();

        IMAGE_DOS_HEADER dh;
        if (read(dh))
            return;

        seek(dh.e_lfanew);

        uint32_t pe_id;
        if (read(pe_id) || pe_id != 0x00004550)
            return;

        IMAGE_FILE_HEADER fh;
        if (read(fh))
            return;

        const auto oh_size = fh.SizeOfOptionalHeader;

        IMAGE_OPTIONAL_HEADER32 oh;
        if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER32))
        {
            if (read(oh))
                return;
        }
        else return;

        std::vector<IMAGE_SECTION_HEADER> shs;
        if (read(shs, fh.NumberOfSections))
            return;

        std::optional<pe_header_32> header = pe_header_32();

        header->dos_header = dh;
        header->file_header = fh;

        header->optional_header = oh;

        header->section_headers = shs;

        header_opt = header;
    };

    std::optional<pe_header_32> header_opt;
    find(header_opt);

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
