#include "stdafx.h"

#include "pe_header.h"

pe_header* pe_header::find(binary_reader reader)
{
    const auto offset = reader.offset();

    pe_header* result;
    find(reader, result);

    reader.seek(offset);

    return result;
}

void pe_header::find(binary_reader reader, pe_header*& p_pe_h)
{
    p_pe_h = nullptr;

    reader.seek();

    uint16_t* mz_id;
    if (reader.read(mz_id) || *mz_id != 0x5A4D)
        return;
    free(mz_id);

    reader.seek();

    IMAGE_DOS_HEADER* dh;
    if (reader.read(dh))
        return;

    reader.seek(dh->e_lfanew);

    uint32_t* pe_id;
    if (reader.read(pe_id) || *pe_id != 0x00004550)
        return;
    free(pe_id);

    IMAGE_FILE_HEADER* fh;
    if (reader.read(fh))
        return;

    const auto oh_size = fh->SizeOfOptionalHeader;

    IMAGE_OPTIONAL_HEADER32* oh32;
    IMAGE_OPTIONAL_HEADER64* oh64;
    if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        if (reader.read(oh32))
            return;
        oh64 = nullptr;
    }
    else if (oh_size == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        oh32 = nullptr;
        if (reader.read(oh64))
            return;
    }
    else return;

    const auto shs = static_cast<IMAGE_SECTION_HEADER**>(malloc(sizeof(IMAGE_SECTION_HEADER*) * fh->NumberOfSections));
    for (auto i = 0; i < fh->NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER* sh;
        if (reader.read(sh))
            return;
        shs[i] = sh;
    }

    p_pe_h = static_cast<pe_header*>(malloc(sizeof(pe_header)));
    
    p_pe_h->dos_header = dh;
    p_pe_h->file_header = fh;

    p_pe_h->optional_header32 = oh32;
    p_pe_h->optional_header64 = oh64;

    p_pe_h->section_headers = shs;
}
