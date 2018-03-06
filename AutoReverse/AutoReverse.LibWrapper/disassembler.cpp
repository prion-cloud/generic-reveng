// disassembler.cpp

#include "stdafx.h"

#include "disassembler.h"

#include <fstream>
#include <vector>

disassembler::disassembler(const char *file_name)
{
    fopen_s(&file_, file_name, "r+");
    fseek(file_, 0, SEEK_END);
    size_ = ftell(file_);
    rewind(file_);

    cs_open(CS_ARCH_X86, CS_MODE_32, &handle_);
}

void disassembler::close()
{
    cs_close(&handle_);

    fclose(file_);
}

int disassembler::disassemble(cs_insn &instruction)
{
    const size_t count = 16;
    const uint64_t address = ftell(file_);

    uint8_t code[count];
    const auto r = fread(code, sizeof(uint8_t), count, file_);

    cs_insn *insn;

    cs_disasm(handle_, code, count, address, 1, &insn);
    
    instruction = insn[0];

    fseek(file_, instruction.size - r, SEEK_CUR);

    return ftell(file_) >= size_;
}
