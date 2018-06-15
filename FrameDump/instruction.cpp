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
