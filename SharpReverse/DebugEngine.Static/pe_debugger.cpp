#include "stdafx.h"

#include "pe_debugger.h"

int pe_debugger::open(const std::vector<char> bytes)
{
    C_IMP(load_pe(bytes, header_, cs_, uc_));

    C_VIT(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));

    return F_SUCCESS;
}
int pe_debugger::close()
{
    C_VIT(cs_close(&cs_) || uc_close(uc_));

    return F_SUCCESS; // TODO: F_FAILURE
}

pe_header pe_debugger::header() const
{
    return header_;
}

int pe_debugger::debug(instruction_info& ins_info) const
{
    const size_t size = 16;

    uint32_t cur_addr;
    C_VIT(uc_reg_read(uc_, X86_REG_EIP, &cur_addr));

    uint8_t bytes[size];
    C_VIT(uc_mem_read(uc_, cur_addr, bytes, size));

    cs_insn* instruction;
    C_VIT(!cs_disasm(cs_, bytes, size, cur_addr, 1, &instruction));

    C_VIT(uc_emu_start(uc_, cur_addr, -1, 0, 1));

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

    ins_info = instruction_info();

    ins_info.id = instruction->id;

    ins_info.address = instruction->address;

    ins_info.size = instruction->size;

    memcpy(ins_info.bytes, instruction->bytes, instruction->size);

    memcpy(ins_info.mnemonic, instruction->mnemonic, strlen(instruction->mnemonic));
    memcpy(ins_info.operands, instruction->op_str, strlen(instruction->op_str));

    return F_SUCCESS; // TODO: F_FAILURE
}

int pe_debugger::inspect_registers(register_info& reg_info) const
{
    reg_info = register_info();

    if (header_.targets_32())
    {
        C_VIT(uc_reg_read(uc_, X86_REG_EAX, &reg_info.registers[0]));
        C_VIT(uc_reg_read(uc_, X86_REG_EBX, &reg_info.registers[1]));
        C_VIT(uc_reg_read(uc_, X86_REG_ECX, &reg_info.registers[2]));
        C_VIT(uc_reg_read(uc_, X86_REG_EDX, &reg_info.registers[3]));
        C_VIT(uc_reg_read(uc_, X86_REG_ESP, &reg_info.registers[4]));
        C_VIT(uc_reg_read(uc_, X86_REG_EBP, &reg_info.registers[5]));
        C_VIT(uc_reg_read(uc_, X86_REG_ESI, &reg_info.registers[6]));
        C_VIT(uc_reg_read(uc_, X86_REG_EDI, &reg_info.registers[7]));
        C_VIT(uc_reg_read(uc_, X86_REG_EIP, &reg_info.registers[8]));

        return F_SUCCESS; // TODO: F_FAILURE
    }

    if (header_.targets_64())
    {
        C_VIT(uc_reg_read(uc_, X86_REG_RAX, &reg_info.registers[0]));
        C_VIT(uc_reg_read(uc_, X86_REG_RBX, &reg_info.registers[1]));
        C_VIT(uc_reg_read(uc_, X86_REG_RCX, &reg_info.registers[2]));
        C_VIT(uc_reg_read(uc_, X86_REG_RDX, &reg_info.registers[3]));
        C_VIT(uc_reg_read(uc_, X86_REG_RSP, &reg_info.registers[4]));
        C_VIT(uc_reg_read(uc_, X86_REG_RBP, &reg_info.registers[5]));
        C_VIT(uc_reg_read(uc_, X86_REG_RSI, &reg_info.registers[6]));
        C_VIT(uc_reg_read(uc_, X86_REG_RDI, &reg_info.registers[7]));
        C_VIT(uc_reg_read(uc_, X86_REG_RIP, &reg_info.registers[8]));

        return F_SUCCESS; // TODO: F_FAILURE
    }

    E_THROW;
}
