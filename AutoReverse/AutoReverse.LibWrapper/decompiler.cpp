#include "stdafx.h"

#include "binary_reader.h"
#include "decompiler.h"
#include "pe_header.h"

decompiler::decompiler(const char* file_name)
    : reader_(file_name)
{
    const auto pe_h = pe_header::find(reader_);

    if (pe_h == nullptr)
    {
        text_start_ = 0;
        text_end_ = reader_.length();
    }
    else
    {
        const auto th = pe_h->section_headers[0];
        text_start_ = th->PointerToRawData;
        text_end_ = text_start_ + th->SizeOfRawData;
    }

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

    if (address >= text_start_ && address < text_end_)
    {
        cs_insn* insn;
        cs_disasm(handle_, bytes, size, address, 1, &insn);

        if (insn == nullptr)
            def = true;
        else instruction = *insn;
    }
    else def = true;

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
