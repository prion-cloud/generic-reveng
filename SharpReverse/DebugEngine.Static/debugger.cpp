#include "stdafx.h"

#include "debugger.h"

debugger::debugger()
{
    reg_index_ = 0;
    mem_index_ = 0;
}

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

    uint64_t cur_addr;
    C_VIT(uc_reg_read(uc_, regs_[8], &cur_addr));
    cur_addr &= scale_;

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

int debugger::reg(register_info& reg_info)
{
    reg_info = register_info();

    if (reg_index_ >= regs_.size())
    {
        reg_index_ = 0;
        return F_FAILURE;
    }

    uint64_t value;
    C_VIT(uc_reg_read(uc_, regs_[reg_index_], &value));
    
    sprintf_s(reg_info.name, cs_reg_name(cs_, regs_[reg_index_]));
    sprintf_s(reg_info.value, "0x%08llx", value & scale_);

    ++reg_index_;

    return F_SUCCESS;
}

int debugger::mem(memory_info& mem_info)
{
    uc_mem_region* regions;
    uint32_t count;
    C_VIT(uc_mem_regions(uc_, &regions, &count));

    mem_info = memory_info();

    if (mem_index_ >= count)
    {
        mem_index_ = 0;
        return F_FAILURE;
    }

    const auto b = regions[mem_index_].begin;
    const auto e = regions[mem_index_].end;
    const auto p = regions[mem_index_].perms;

    sprintf_s(mem_info.begin, "0x%016llx", b);
    sprintf_s(mem_info.size, "0x%016llx", e - b + 1);

    mem_info.permissions[0] = (p & UC_PROT_READ) == UC_PROT_READ ? 'R' : ' ';
    mem_info.permissions[1] = (p & UC_PROT_WRITE) == UC_PROT_WRITE ? 'W' : ' ';
    mem_info.permissions[2] = (p & UC_PROT_EXEC) == UC_PROT_EXEC ? 'E' : ' ';

    ++mem_index_;

    return F_SUCCESS;
}
