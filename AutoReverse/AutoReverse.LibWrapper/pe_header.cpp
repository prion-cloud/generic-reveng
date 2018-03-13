#include "stdafx.h"

#include "pe_header.h"

#include "binary_reader.h"

std::optional<pe_header> pe_header::find(binary_reader reader)
{
    const auto offset = reader.offset();

    std::optional<pe_header> header;
    find(reader, header);

    reader.seek(offset);

    return header;
}

void pe_header::find(binary_reader reader, std::optional<pe_header>& header)
{
    header = std::nullopt;

    reader.seek();

    uint16_t mz_id;
    if (reader.read(mz_id) || mz_id != 0x5A4D)
        return;

    reader.seek();

    IMAGE_DOS_HEADER dh;
    if (reader.read(dh))
        return;

    reader.seek(dh.e_lfanew);

    uint32_t pe_id;
    if (reader.read(pe_id) || pe_id != 0x00004550)
        return;

    IMAGE_FILE_HEADER fh;
    if (reader.read(fh))
        return;

    const auto oh_size = fh.SizeOfOptionalHeader;

    std::optional<IMAGE_OPTIONAL_HEADER32> oh32;
    std::optional<IMAGE_OPTIONAL_HEADER64> oh64;
    if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        if (reader.read(oh32))
            return;
        oh64 = std::nullopt;
    }
    else if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        if (reader.read(oh64))
            return;
        oh32 = std::nullopt;
    }
    else return;

    std::vector<IMAGE_SECTION_HEADER> shs;
    if (reader.read(shs, fh.NumberOfSections))
        return;

    header = pe_header();
    
    header->dos_header = dh;
    header->file_header = fh;

    header->optional_header32 = oh32;
    header->optional_header64 = oh64;

    header->section_headers = shs;
}
