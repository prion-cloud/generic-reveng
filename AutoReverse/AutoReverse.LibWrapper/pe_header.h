#pragma once

#include "stdafx.h"

#include "binary_reader.h"

struct pe_header
{
    IMAGE_DOS_HEADER* dos_header { };
    IMAGE_FILE_HEADER* file_header { };

    IMAGE_OPTIONAL_HEADER32* optional_header32 { };
    IMAGE_OPTIONAL_HEADER64* optional_header64 { };

    IMAGE_SECTION_HEADER** section_headers { };

    static pe_header* find(binary_reader reader);

private:

    static void find(binary_reader reader, pe_header*& p_pe_h);
};
