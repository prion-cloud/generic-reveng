// disassembler.h

#pragma once

#include "include/capstone.h"

class disassembler
{
    FILE *file_ { };
    size_t size_ { };

    csh handle_ { };

public:
    explicit disassembler(const char *file_name);

    void close();

    int disassemble(cs_insn &instruction);
};
