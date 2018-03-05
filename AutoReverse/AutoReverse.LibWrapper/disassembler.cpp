// disassembler.cpp

#include "stdafx.h"
#include "disassembler.h"

disassembler::disassembler(const cs_arch architecture, const cs_mode mode, const uint8_t *bytes, const size_t size)
    : bytes(bytes), size(size), architecture(architecture)
{
    cs_open(architecture, mode, &handle);

    offset = 0;
}

disassembler::~disassembler()
{
    cs_close(&handle);
}

int disassembler::disassemble(cs_insn &instruction)
{
    cs_insn *insn;

    cs_disasm(handle, bytes + offset, 16, offset, 1, &insn);

    instruction = insn[0];

    return skip(instruction.size);
}

int disassembler::skip(const size_t length)
{
    offset += length;

    if (offset < size)
        return 0;

    return -1;
}
