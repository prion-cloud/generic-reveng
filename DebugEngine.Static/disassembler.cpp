#include "stdafx.h"

#include "disassembler.h"

disassembler::disassembler(const uint16_t machine)
{
    auto mode = static_cast<cs_mode>(0);
    switch (machine)
    {
#ifdef _M_IX86
    case IMAGE_FILE_MACHINE_I386:
        mode = CS_MODE_32;
        break;
#elif _M_AMD64
    case IMAGE_FILE_MACHINE_AMD64:
        mode = CS_MODE_64;
        break;
#endif
    default:
        std::ostringstream message;
        message << "Invalid machine specification: " << std::hex << std::showbase << machine;
        THROW(message.str());
    }

    FATAL_IF(cs_open(CS_ARCH_X86, mode, &cs_));
    FATAL_IF(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));
}
disassembler::~disassembler()
{
    cs_close(&cs_);
}

instruction_x86 disassembler::disassemble(const uint64_t address, const std::vector<uint8_t>& code) const
{
    cs_insn* insn;
    FATAL_IF(!cs_disasm(cs_, &code.at(0), code.size(), address, 1, &insn));

    instruction_x86 instruction(*insn);

    cs_free(insn, 1);

    return instruction;
}
