#include "stdafx.h"
#include "macro.h"

#include "debugger.h"

debugger::debugger()
{
    reg_index_ = 0;
    mem_index_ = 0;
}

int debugger::load(loader* loader, const std::vector<char> bytes)
{
    loader_ = loader;

    E_ERR(loader_->load(bytes, cs_, uc_));
    E_ERR(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));

    auto s = loader_->scale();
    auto x = 0;

    for (auto i = 0;; ++i)
    {
        if (s == 0x0)
            break;

        ++x;
        s = s >> 4;
    }

    auto format = std::ostringstream();
    format << "%0" << x << "llx";
    format_ = format.str();

    return R_SUCCESS;
}
int debugger::unload()
{
    E_ERR(cs_close(&cs_) || uc_close(uc_));

    if (loader_ != nullptr)
        delete loader_;

    return R_SUCCESS;
}

int debugger::ins(instruction_info& ins_info) const
{
    const auto ip_reg = loader_->regs()[loader_->ip_index()];

    uint64_t cur_addr;
    E_FAT(uc_reg_read(uc_, ip_reg, &cur_addr));
    cur_addr &= loader_->scale();

    std::string comment = { };

    std::string dll_name, proc_name;
    if (loader_->find_proc(cur_addr, dll_name, proc_name))
    {
        auto stream = std::ostringstream();
        stream << dll_name << "." << proc_name;
        comment = stream.str();
    }
    
    const auto size = 16;

    uint8_t bytes[size];
    E_FAT(uc_mem_read(uc_, cur_addr, bytes, size));

    cs_insn* instruction;
    E_FAT(!cs_disasm(cs_, bytes, size, cur_addr, 1, &instruction));

    E_ERR(uc_emu_start(uc_, cur_addr, -1, 0, 1));

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
        uc_reg_write(uc_, ip_reg, &next_addr);
    }

    ins_info = instruction_info();

    ins_info.id = instruction->id;

    sprintf_s(ins_info.address, format_.c_str(), instruction->address);

    ins_info.size = instruction->size;

    memcpy(ins_info.bytes, instruction->bytes, instruction->size);

    memcpy(ins_info.mnemonic, instruction->mnemonic, strlen(instruction->mnemonic));
    memcpy(ins_info.operands, instruction->op_str, strlen(instruction->op_str));

    std::copy(comment.begin(), comment.end(), ins_info.comment);

    return R_SUCCESS;
}

int debugger::reg(register_info& reg_info)
{
    reg_info = register_info();

    const auto regs = loader_->regs();

    if (reg_index_ >= regs.size())
    {
        reg_index_ = 0;
        return R_FAILURE;
    }

    uint64_t value;
    E_FAT(uc_reg_read(uc_, regs[reg_index_], &value));
    
    sprintf_s(reg_info.name, cs_reg_name(cs_, regs[reg_index_]));
    sprintf_s(reg_info.value, format_.c_str(), value & loader_->scale());

    ++reg_index_;

    return R_SUCCESS;
}

int debugger::mem(memory_info& mem_info)
{
    uc_mem_region* regions;
    uint32_t count;
    E_FAT(uc_mem_regions(uc_, &regions, &count));

    mem_info = memory_info();

    if (mem_index_ >= count)
    {
        mem_index_ = 0;
        return R_FAILURE;
    }

    const auto b = regions[mem_index_].begin;
    const auto e = regions[mem_index_].end;
    const auto p = regions[mem_index_].perms;

    sprintf_s(mem_info.address, format_.c_str(), b);
    sprintf_s(mem_info.size, format_.c_str(), e - b + 1);

    std::string o, d;
    loader_-> find_sec(b, o, d);
    memcpy(mem_info.owner, o.c_str(), strlen(o.c_str()));
    memcpy(mem_info.description, d.c_str(), strlen(d.c_str()));

    mem_info.access[0] = (p & UC_PROT_READ) == UC_PROT_READ ? 'R' : ' ';
    mem_info.access[1] = (p & UC_PROT_WRITE) == UC_PROT_WRITE ? 'W' : ' ';
    mem_info.access[2] = (p & UC_PROT_EXEC) == UC_PROT_EXEC ? 'E' : ' ';
    mem_info.access[3] = '\0';

    ++mem_index_;

    return R_SUCCESS;
}
