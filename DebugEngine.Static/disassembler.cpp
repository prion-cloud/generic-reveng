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

instruction disassembler::disassemble(std::vector<uint8_t> bytes, const uint64_t address) const
{
    cs_insn* insn;
    FATAL_IF(!cs_disasm(cs_, &bytes.at(0), MAX_BYTES, address, 1, &insn));

    instruction instruction;

    instruction.id = insn->id;

    instruction.address = address;

    instruction.bytes = std::vector<uint8_t>(insn->bytes, insn->bytes + insn->size);

    instruction.mnemonic = insn->mnemonic;
    instruction.operands = insn->op_str;

    switch(insn->id)
    {
    case 0x244: // push
    case 0x22e: // pop
    case 0x38:  // call
    case 0x95:  // ret
        instruction.registers.emplace(X86_REG_RSP, cs_reg_name(cs_, X86_REG_RSP));
    default:;
    }

    for (auto i = 0; i < insn->detail->x86.op_count; ++i) // TODO: Enforce x86 ?
    {
        const auto operand = insn->detail->x86.operands[i];

        if (operand.reg == X86_REG_INVALID)
            continue;

        switch (operand.type)
        {
        case X86_OP_REG:
        case X86_OP_MEM:
            instruction.registers.emplace(operand.reg, cs_reg_name(cs_, operand.reg));
            break;
        default:;
        }
    }

    instruction.jump = { };

    for (auto i = 0; i < insn->detail->groups_count; ++i)
    {
        switch (insn->detail->groups[i])
        {
        case CS_GRP_JUMP:
        case CS_GRP_CALL:
            const auto op = insn->detail->x86.operands[0];
            switch (op.type)
            {
            case X86_OP_IMM:
                instruction.jump = op.imm;
                break;
            default:;
            }
            break;
        default:;
        }
    }

    return instruction;
}
