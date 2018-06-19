#include "stdafx.h"

#include "instruction.h"

operand_x86::operand_x86() = default;
operand_x86::operand_x86(const x86_op_type type, const uint8_t value8, const int64_t value64)
    : type(type), value8(value8), value64(value64) { }

bool operator<(const operand_x86& op1, const operand_x86& op2)
{
    if (op1.type == op2.type)
    {
        switch (op1.type)
        {
        case X86_OP_MEM:
            if (op1.value8 != op2.value8)
        case X86_OP_REG:
            return op1.value8 < op2.value8;
        case X86_OP_IMM:
        case X86_OP_FP:
            return op1.value64 < op2.value64;
        default:
            return false;
        }
    }

    return op1.type < op2.type;
}

instruction_x86::instruction_x86() = default;
instruction_x86::instruction_x86(const cs_insn cs_instruction)
{
    id_ = cs_instruction.id;

    size_ = static_cast<uint8_t>(cs_instruction.size);

    address_ = cs_instruction.address;

    if (cs_instruction.detail == nullptr)
    {
        op_count_ = 0;
        return;
    }

    const auto cs_detail = cs_instruction.detail->x86;

    op_count_ = cs_detail.op_count < INS_MAX_OPS ? cs_detail.op_count : INS_MAX_OPS;
    for (auto i = 0; i < op_count_ && i < INS_MAX_OPS; ++i)
    {
        const auto op = cs_detail.operands[i];

        switch (op_type_[i] = op.type)
        {
        case X86_OP_REG:
            op_value8_[i] = op.reg;
            op_value64_[i] = 0;
            break;
        case X86_OP_IMM:
            op_value8_[i] = 0;
            op_value64_[i] = op.imm;
            break;
        case X86_OP_MEM:
            op_value8_[i] = op.mem.base;
            op_value64_[i] = op.mem.disp;
            break;
        case X86_OP_FP:
            op_value8_[i] = 0;
            op_value64_[i] = *reinterpret_cast<const int64_t*>(&op.fp);
            break;
        default:;
        }
    }
}

x86_insn instruction_x86::identification() const
{
    return static_cast<x86_insn>(id_);
}

size_t instruction_x86::size() const
{
    return size_;
}

uint64_t instruction_x86::address(const uint64_t virtual_base) const
{
    return virtual_base + address_;
}

operand_x86 instruction_x86::operand_at(const unsigned index) const
{
    if (index >= INS_MAX_OPS)
        throw std::runtime_error("Index was out of range.");

    return operand_x86(static_cast<x86_op_type>(op_type_[index]), op_value8_[index], op_value64_[index]);
}
