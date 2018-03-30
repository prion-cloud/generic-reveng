#include "stdafx.h"

#include "debugger.h"

int debugger::load(const loader& l, const std::vector<char> bytes)
{
    C_IMP(const_cast<loader&>(l).load(bytes, cs_, uc_, scale_, regs_));
    C_IMP(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));

    return F_SUCCESS;
}
int debugger::unload()
{
    C_IMP(cs_close(&cs_) || uc_close(uc_));

    return F_SUCCESS;
}

uint64_t debugger::scale() const
{
    return scale_;
}

int debugger::ins(instruction_info& ins_info) const
{
    const auto size = 16;
    const auto cur_addr = uc_ext_reg_read(uc_, regs_[8], scale_);

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
        uc_reg_write(uc_, regs_[8], &next_addr);
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

int debugger::reg(register_info& reg_info) const
{
    for (auto i = 0; i < regs_.size(); ++i)
        reg_info.registers[i] = uc_ext_reg_read(uc_, regs_[i], scale_);

    return F_SUCCESS; // TODO: F_FAILURE
}

int debugger::mem(std::vector<memory_info>& mem_info_vec) const
{
    uc_mem_region* regions;
    uint32_t count;
    C_IMP(uc_mem_regions(uc_, &regions, &count));

    mem_info_vec = std::vector<memory_info>();

    for (auto i = 0; i < count; ++i)
    {
        auto mem_info = memory_info();

        mem_info.begin = regions[i].begin;
        mem_info.size = regions[i].end - regions[i].begin;

        mem_info.permissions = regions[i].perms;

        mem_info_vec.push_back(mem_info);
    }

    return F_SUCCESS;
}
