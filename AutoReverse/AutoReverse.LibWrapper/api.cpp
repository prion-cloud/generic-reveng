// api.cpp

#include "stdafx.h"

#include "disassembler.h"

#include "include/capstone.h"

#define API extern "C" __declspec(dllexport)

API disassembler *disassembler_open(
    const cs_arch architecture,
    const cs_mode mode,
    const uint8_t *bytes,
    const size_t size)
{
    return new disassembler(architecture, mode, bytes, size);
}

API void disassembler_close(
    disassembler *disassembler)
{
    delete disassembler;
}

API int disassemble(
    disassembler *disassembler,
    cs_insn &instruction)
{
    return disassembler->disassemble(instruction);
}
