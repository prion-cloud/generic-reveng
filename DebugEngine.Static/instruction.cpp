#include "stdafx.h"

#include "instruction.h"

static void inspect_type(x86_insn id, instruction_type& type, bool& is_conditional);

operand_x86::operand_x86(const cs_x86_op cs_op)
{
    switch (cs_op.type)
    {
    case X86_OP_REG:
        type = op_register;
        value = cs_op.reg;
        break;
    case X86_OP_IMM:
        type = op_immediate;
        value = cs_op.imm;
        break;
    case X86_OP_MEM:
        type = op_memory;
        value = cs_op.mem;
        break;
    case X86_OP_FP:
        type = op_float;
        value = cs_op.fp;
        break;
    default:;
    }
}
instruction_x86::instruction_x86(const cs_insn cs_insn)
{
    id = static_cast<x86_insn>(cs_insn.id);

    inspect_type(id, type, is_conditional);

    address = cs_insn.address;

    code = std::vector<uint8_t>(cs_insn.bytes, cs_insn.bytes + cs_insn.size);

    str_mnemonic = std::string(cs_insn.mnemonic, cs_insn.mnemonic + std::strlen(cs_insn.mnemonic));
    str_operands = std::string(cs_insn.op_str, cs_insn.op_str + std::strlen(cs_insn.op_str));

    operands = std::vector<operand_x86>(cs_insn.detail->x86.operands, cs_insn.detail->x86.operands + cs_insn.detail->x86.op_count);

    is_volatile = type == ins_return || (type == ins_jump || type == ins_call) && operands.at(0).type != op_immediate;

    sets_flags = false;
    for (auto i = 0; i < cs_insn.detail->regs_write_count; ++i)
    {
        if (cs_insn.detail->regs_write[i] == X86_REG_EFLAGS)
        {
            sets_flags = true;
            break;
        }
    }
}

std::string instruction_x86::to_string(const bool full) const
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

static void inspect_type(const x86_insn id, instruction_type& type, bool& is_conditional)
{
    type = ins_unknown;
    is_conditional = false;

    switch (id)
    {
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
        is_conditional = true;
    case X86_INS_JMP:
        type = ins_jump;
        break;
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
        is_conditional = true;
    case X86_INS_MOV:
    case X86_INS_MOVABS:
    case X86_INS_MOVUPD:
    case X86_INS_XCHG:
        type = ins_move;
        break;
    case X86_INS_PUSH:
    case X86_INS_PUSHAL:
    case X86_INS_PUSHAW:
    case X86_INS_PUSHF:
    case X86_INS_PUSHFD:
    case X86_INS_PUSHFQ:
        type = ins_push;
        break;
    case X86_INS_POP:
    case X86_INS_POPAL:
    case X86_INS_POPAW:
    case X86_INS_POPCNT:
    case X86_INS_POPF:
    case X86_INS_POPFD:
    case X86_INS_POPFQ:
        type = ins_pop;
        break;
    case X86_INS_CALL:
        type = ins_call;
        break;
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        type = ins_return;
        break;
    case X86_INS_ADD:
    case X86_INS_DIV:
    case X86_INS_MUL:
    case X86_INS_SUB:
        type = ins_arithmetic;
        break;
    default:;
    }
}
