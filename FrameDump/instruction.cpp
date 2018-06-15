#include "stdafx.h"

#include "instruction.h"

instruction_x86::instruction_x86() = default;
instruction_x86::instruction_x86(const cs_insn cs_instruction)
{
    id_ = cs_instruction.id;
    address_ = static_cast<uint32_t>(cs_instruction.address);

    size_ = static_cast<uint8_t>(cs_instruction.size);
    memcpy_s(bytes_, size_, cs_instruction.bytes, cs_instruction.size);

    _snprintf_s(str_, INS_MAX_STR - 1, "%s %s", cs_instruction.mnemonic, cs_instruction.op_str);

    if (cs_instruction.detail == nullptr)
    {
        op_count_ = 0;
        return;
    }

    const auto cs_detail = cs_instruction.detail->x86;

    op_count_ = cs_detail.op_count;
    for (auto i = 0; i < op_count_ && i < INS_MAX_OPS; ++i)
    {
        operand_types_[i] = cs_detail.operands[i].type;
        operand_values_[i] = cs_detail.operands[i].imm;
    }
}

x86_insn instruction_x86::get_id() const
{
    return static_cast<x86_insn>(id_);
}

uint64_t instruction_x86::get_address() const
{
    return address_;
}

std::string instruction_x86::get_string() const
{
    return std::string(str_);
}

std::vector<uint8_t> instruction_x86::get_bytes() const
{
    return std::vector<uint8_t>(bytes_, bytes_ + size_);
}

std::vector<std::pair<x86_op_type, uint64_t>> instruction_x86::get_operands() const
{
    std::vector<std::pair<x86_op_type, uint64_t>> operands;
    for (auto i = 0; i < op_count_; ++i)
        operands.push_back(std::make_pair(static_cast<x86_op_type>(operand_types_[i]), operand_values_[i]));

    return operands;
}
