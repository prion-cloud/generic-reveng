#include "stdafx.h"

#include "decompiler.h"

#define API extern "C" __declspec(dllexport)

API decompiler* disassembler_open(
    const char *file_name)
{
    return new decompiler(file_name);
}

API void disassembler_close(
    decompiler* decompiler)
{
    decompiler->close();
}

API int disassemble(
    decompiler* decompiler,
    cs_insn &instruction)
{
    return decompiler->disassemble(instruction);
}
