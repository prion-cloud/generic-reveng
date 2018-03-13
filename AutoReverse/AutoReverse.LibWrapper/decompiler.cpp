#include "stdafx.h"

#include "decompiler.h"

#include "binary_reader.h"

decompiler::decompiler(const std::string file_name)
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
    const size_t size = 16;
    const auto address = reader_.offset();

    uint8_t* bytes;
    const auto res = reader_.read(bytes, size);

    auto def = false;

    cs_insn* insn;
    cs_disasm(handle_, bytes, size, address, 1, &insn);

    if (insn == nullptr)
        def = true;
    else instruction = *insn;

    if (def)
    {
        instruction = cs_insn();

        instruction.id = -1;

        instruction.address = address;
        instruction.size = size;

        for (auto i = 0; i < size; i++)
            instruction.bytes[i] = bytes[i];
    }

    free(bytes);

    reader_.seek(instruction.size - static_cast<long>(res + size), SEEK_CUR);

    return reader_.offset() >= reader_.length();
}
