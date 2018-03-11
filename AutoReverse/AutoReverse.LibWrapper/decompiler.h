#pragma once

#include "binary_reader.h"

class decompiler
{
    binary_reader reader_;

    csh handle_ { };

public:

    explicit decompiler(const char* file_name);

    void close();

    int disassemble(cs_insn& instruction);
};