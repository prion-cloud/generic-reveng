// api.cpp

#include "stdafx.h"

#include "disassembler.h"

#include "include/capstone.h"

#define API extern "C" __declspec(dllexport)

API disassembler *disassembler_open(
    const char *file_name)
{
    return new disassembler(file_name);
}

API void disassembler_close(
    disassembler *disassembler)
{
    disassembler->close();
}

API int disassemble(
    disassembler *disassembler,
    cs_insn &instruction)
{
    return disassembler->disassemble(instruction);
}
