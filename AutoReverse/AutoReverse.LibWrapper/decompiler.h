#pragma once

#include "binary_reader.h"
#include "pe_header.h"

class decompiler
{
    binary_reader reader_;

    std::optional<pe_header> header_ { };

    csh handle_ { };

public:

    explicit decompiler(std::string file_name);

    void close();

    int disassemble(cs_insn& instruction);
};
