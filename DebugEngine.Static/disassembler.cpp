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

    const auto cs_mnem = insn->mnemonic;
    instruction.mnemonic = std::string(cs_mnem, cs_mnem + std::strlen(cs_mnem));
    const auto cs_op = insn->op_str;
    instruction.operands = std::string(cs_op, cs_op + std::strlen(cs_op));

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

    cs_free(insn, 1);

    return instruction;
}

/* TODO
assembler::assembler(const uint16_t machine)
{
    auto mode = static_cast<ks_mode>(0);

    switch (machine)
    {
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:

        mode = KS_MODE_64;

        break;
#else
    case IMAGE_FILE_MACHINE_I386:

        mode = KS_MODE_32;

        break;
#endif
    default:
        std::ostringstream message;
        message << "Invalid machine specification: " << std::hex << std::showbase << machine;
        THROW(message.str());
    }

    FATAL_IF(ks_open(KS_ARCH_X86, mode, &ks_));
}
assembler::~assembler()
{
    ks_close(ks_);
}

std::vector<uint8_t> assembler::assemble(const uint64_t address, const std::string string) const
{
    uint8_t* code;

    size_t size;
    size_t count;

    FATAL_IF(ks_asm(ks_, string.c_str(), address, &code, &size, &count) != 0);
    FATAL_IF(count != 1);

    std::vector<uint8_t> code_vector(code, code + size);

    ks_free(code);

    return code_vector;
}
*/
