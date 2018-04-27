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
    const auto machine = IMAGE_FILE_MACHINE_I386;

    E_FAT(cs_open(CS_ARCH_X86, CS_MODE_32, &cs_));
    E_FAT(cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON));

    emulator_ = new emulator(machine);

    E_ERR(loader->load(emulator_, bytes));

    sections_ = loader->sections();
    labels_ = loader->labels();

    return R_SUCCESS;
}
int debugger::unload()
{
    E_ERR(cs_close(&cs_));

    if (emulator_ != nullptr)
        delete emulator_;

    return R_SUCCESS;
}

int debugger::debug(instruction_info& ins_info) const
{
    const auto address = emulator_->reg_read<uint64_t>(reg_ip);
    const auto size = 16;

    uint8_t bytes[size];
    emulator_->mem_read(address, bytes, size);

    cs_insn* instruction;
    E_FAT(!cs_disasm(cs_, bytes, size, address, 1, &instruction));

    emulator_->step_into();

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
        emulator_->jump(address + instruction->size);

    ins_info = instruction_info();

    ins_info.id = instruction->id;

    sprintf_s(ins_info.address, "%08llx", instruction->address);

    ins_info.size = instruction->size;

    memcpy(ins_info.bytes, instruction->bytes, instruction->size);

    memcpy(ins_info.mnemonic, instruction->mnemonic, strlen(instruction->mnemonic));
    memcpy(ins_info.operands, instruction->op_str, strlen(instruction->op_str));

    std::string label = { };
    if (labels_.find(address) != labels_.end())
        label = labels_.at(address);
    std::copy(label.begin(), label.end(), ins_info.label);

    return R_SUCCESS;
}
