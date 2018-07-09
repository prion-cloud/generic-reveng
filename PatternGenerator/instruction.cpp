#include "stdafx.h"

#include "instruction.h"
#include <utility>

instruction::operand::operand(cs_x86_op cs_operand)
{
    switch (cs_operand.type)
    {
    case X86_OP_REG:
        type = op_register;
        value = cs_operand.reg;
        break;
    case X86_OP_IMM:
        type = op_immediate;
        value = cs_operand.imm;
        break;
    case X86_OP_MEM:
        type = op_memory;
        value = cs_operand.mem;
        break;
    case X86_OP_FP:
        type = op_float;
        value = cs_operand.fp;
        break;
    default:;
    }
}

instruction::instruction(cs_insn cs_instruction)
{
    id = static_cast<x86_insn>(cs_instruction.id);

    address = cs_instruction.address;

    code = std::vector<uint8_t>(cs_instruction.bytes, cs_instruction.bytes + cs_instruction.size);

    str_mnemonic = cs_instruction.mnemonic;
    str_operands = cs_instruction.op_str;

    flag = false;

    const auto detail = cs_instruction.detail;
    if (detail == nullptr)
        return;

    for (auto i = 0; i < detail->x86.op_count; ++i)
        operands.emplace_back(cs_instruction.detail->x86.operands[i]);

    for (auto i = 0; i < detail->regs_write_count; ++i)
    {
        if (cs_instruction.detail->regs_write[i] != X86_REG_EFLAGS)
            continue;

        flag = true;
        break;
    }
}

bool instruction::is_jump() const
{
    switch (id)
    {
    case X86_INS_CALL:
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JMP:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return true;
    default:
        return false;
    }
}
bool instruction::is_conditional() const
{
    switch (id)
    {
    case X86_INS_CMOVA:
    case X86_INS_CMOVAE:
    case X86_INS_CMOVB:
    case X86_INS_CMOVBE:
    case X86_INS_CMOVE:
    case X86_INS_CMOVG:
    case X86_INS_CMOVGE:
    case X86_INS_CMOVL:
    case X86_INS_CMOVLE:
    case X86_INS_CMOVNE:
    case X86_INS_CMOVNO:
    case X86_INS_CMOVNP:
    case X86_INS_CMOVNS:
    case X86_INS_CMOVO:
    case X86_INS_CMOVP:
    case X86_INS_CMOVS:
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
        return true;
    default:
        return false;
    }
}

std::string instruction::to_string(const bool full) const
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << address;

    if (full)
    {
        ss << " " << str_mnemonic;
        if (!str_operands.empty())
        {
            ss << " ";

            const auto str_op = str_operands;
            if (operands.size() == 1 && operands.front().type == op_immediate)
                ss << std::hex << std::uppercase << std::get<op_immediate>(operands.front().value);
            else ss << str_operands;
        }
    }

    return ss.str();
}

instruction_sequence::instruction_sequence(std::vector<instruction> instructions)
    : instructions_(std::move(instructions)) { }

std::vector<instruction> const* instruction_sequence::operator->() const
{
    return &instructions_;
}
