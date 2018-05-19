#include "stdafx.h"

#include "disassembler.h"

disassembler::disassembler(const uint16_t machine)
{
    auto mode = static_cast<cs_mode>(0);

    switch (machine)
    {
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:

        mode = CS_MODE_64;

        break;
#else
    case IMAGE_FILE_MACHINE_I386:

        mode = CS_MODE_32;

        break;
#endif
    default:
        THROW;
    }

    E_FAT(cs_open(CS_ARCH_X86, mode, &cs_));
    E_FAT(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));
}
disassembler::~disassembler()
{
    cs_close(&cs_);
}

std::shared_ptr<instruction> disassembler::disassemble(std::vector<uint8_t> bytes, const uint64_t address) const
{
    cs_insn* insn;
    E_FAT(!cs_disasm(cs_, &bytes.at(0), MAX_BYTES, address, 1, &insn));

    const auto instruction_ptr = std::make_shared<instruction>();

    instruction_ptr->id = insn->id;

    instruction_ptr->address = address;

    instruction_ptr->bytes = std::vector<uint8_t>(insn->bytes, insn->bytes + insn->size);

    instruction_ptr->mnemonic = insn->mnemonic;
    instruction_ptr->operands = insn->op_str;

    for (auto i = 0; i < insn->detail->x86.op_count; ++i) // TODO: Enforce x86 ?
    {
        const auto operand = insn->detail->x86.operands[i];
        const auto reg = operand.reg;

        if (reg == X86_REG_INVALID)
            continue;

        switch (operand.type)
        {
        case X86_OP_REG:
        case X86_OP_MEM:
            instruction_ptr->registers.emplace(reg, cs_reg_name(cs_, reg));
            break;
        default:;
        }
    }

    return instruction_ptr;
}
