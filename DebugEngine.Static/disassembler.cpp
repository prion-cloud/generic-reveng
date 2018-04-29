#include "stdafx.h"

#include "disassembler.h"

disassembler::disassembler(const uint16_t machine)
{
    cs_arch arch;
    cs_mode mode;

    switch (machine)
    {
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:

        arch = CS_ARCH_X86;
        mode = CS_MODE_64;

        break;
#else
    case IMAGE_FILE_MACHINE_I386:

        arch = CS_ARCH_X86;
        mode = CS_MODE_32;

        break;
#endif
    default:
        THROW_E;
    }

    E_FAT(cs_open(arch, mode, &cs_));
    E_FAT(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));
}
disassembler::~disassembler()
{
    cs_close(&cs_);
}

uint64_t disassembler::disassemble(uint8_t bytes[MAX_BYTES], const uint64_t address, instruction& instruction) const
{
    cs_insn* insn;
    E_FAT(!cs_disasm(cs_, bytes, MAX_BYTES, address, 1, &insn));

    instruction.id = insn->id;

    instruction.address = address;

    instruction.bytes = std::vector<uint8_t>(insn->bytes, insn->bytes + insn->size);

    instruction.mnemonic = insn->mnemonic;
    instruction.operands = insn->op_str;
    
    auto incr = true;
    for (auto i = 0; i < insn->detail->groups_count; ++i)
    {
        switch (insn->detail->groups[i])
        {
        case CS_GRP_JUMP:
        case CS_GRP_CALL:
        case CS_GRP_RET:
        case CS_GRP_INT:
        case CS_GRP_IRET:
            incr = false;
        default:;
        }
    }

    if (incr)
        return address + insn->size;

    return 0x0;
}
