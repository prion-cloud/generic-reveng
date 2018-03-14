#include "stdafx.h"

#include "decompiler.h"

decompiler::decompiler(const std::string file_name)
    : reader_(file_name), header_(reader_.search_header())
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

    std::array<uint8_t, size> bytes;
    const auto res = reader_.read(bytes);

    auto def = false;

    cs_insn* insn;
    cs_disasm(handle_, bytes._Unchecked_begin(), size, address, 1, &insn);

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

    reader_.seek(instruction.size - static_cast<long>(res + size), SEEK_CUR);

    return reader_.offset() >= reader_.length();
}
