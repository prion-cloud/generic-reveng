#include "stdafx.h"

#include "instruction.h"

instruction_x86::instruction_x86() = default;
instruction_x86::instruction_x86(const cs_insn cs_instruction)
{
    id_ = cs_instruction.id;
    address_ = static_cast<uint32_t>(cs_instruction.address);

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

x86_insn instruction_x86::identification() const
{
    return static_cast<x86_insn>(id_);
}

uint64_t instruction_x86::address() const
{
    return address_;
}

std::vector<std::pair<x86_op_type, uint64_t>> instruction_x86::operands() const
{
    std::vector<std::pair<x86_op_type, uint64_t>> operands;
    for (auto i = 0; i < op_count_; ++i)
        operands.push_back(std::make_pair(static_cast<x86_op_type>(operand_types_[i]), operand_values_[i]));

    return operands;
}
