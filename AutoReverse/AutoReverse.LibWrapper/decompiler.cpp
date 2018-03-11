#include "stdafx.h"

#include "binary_reader.h"
#include "decompiler.h"

decompiler::decompiler(const char* file_name)
    : reader_(file_name)
{
    cs_open(CS_ARCH_X86, CS_MODE_32, &handle_);
}

void decompiler::close()
{
    cs_close(&handle_);

    reader_.close();
}

int decompiler::disassemble(cs_insn& instruction)
{
    const auto count = 16;
    const uint64_t address = reader_.offset();

    auto code = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * count));
    const auto res = reader_.read(code, count);

    cs_insn* insn;
    cs_disasm(handle_, code, count, address, 1, &insn);

    instruction = *insn;

    reader_.seek(instruction.size - (res + count), SEEK_CUR);

    return reader_.offset() >= reader_.length();
}
