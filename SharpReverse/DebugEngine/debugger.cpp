#include "stdafx.h"

#include "debugger.h"

#include "loader.h"

debugger::debugger(const std::vector<char> bytes)
{
    load(bytes, cs_, uc_);

    cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);
}

void debugger::close()
{
    cs_close(&cs_);
    uc_close(uc_);
}

instruction_32 debugger::debug_32() const
{
    const size_t size = 16;

    uint32_t cur_addr;
    uc_reg_read(uc_, X86_REG_EIP, &cur_addr);

    uint8_t bytes[size];
    uc_mem_read(uc_, cur_addr, bytes, size);

    cs_insn* instruction;
    cs_disasm(cs_, bytes, size, cur_addr, 1, &instruction);

    uc_emu_start(uc_, cur_addr, -1, 0, 1);

    auto incr = true;

    for (auto i = 0; i < instruction->detail->groups_count; ++i)
    {
        switch (instruction->detail->groups[i])
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
    {
        auto next_addr = cur_addr + instruction->size;
        uc_reg_write(uc_, X86_REG_EIP, &next_addr);
    }

    auto result = instruction_32();

    result.id = instruction->id;

    result.address = static_cast<uint32_t>(instruction->address);

    result.size = instruction->size;

    memcpy(result.bytes, instruction->bytes, instruction->size);

    memcpy(result.mnemonic, instruction->mnemonic, strlen(instruction->mnemonic));
    memcpy(result.operands, instruction->op_str, strlen(instruction->op_str));

    return result;
}

register_state_32 debugger::get_registers_32() const
{
    auto result = register_state_32();

    uc_reg_read(uc_, X86_REG_EAX, &result.eax);
    uc_reg_read(uc_, X86_REG_EBX, &result.ebx);
    uc_reg_read(uc_, X86_REG_ECX, &result.ecx);
    uc_reg_read(uc_, X86_REG_EDX, &result.edx);

    uc_reg_read(uc_, X86_REG_ESP, &result.esp);
    uc_reg_read(uc_, X86_REG_EBP, &result.ebp);

    uc_reg_read(uc_, X86_REG_ESI, &result.esi);
    uc_reg_read(uc_, X86_REG_EDI, &result.edi);

    uc_reg_read(uc_, X86_REG_EIP, &result.eip);

    return result;
}
