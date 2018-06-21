#include "stdafx.h"

#include "instruction.h"

static void inspect(x86_insn id, instruction_type& type, bool& is_conditional);

operand_x86::operand_x86(const cs_x86_op cs_op)
{
    switch (cs_op.type)
    {
    case X86_OP_REG:
        type = operand_type::reg;
        reg = cs_op.reg;
        break;
    case X86_OP_IMM:
        type = operand_type::imm;
        imm = cs_op.imm;
        break;
    case X86_OP_MEM:
        type = operand_type::mem;
        mem = cs_op.mem;
        break;
    case X86_OP_FP:
        type = operand_type::flp;
        flp = cs_op.fp;
        break;
    default:;
    }
}
instruction_x86::instruction_x86(const cs_insn cs_insn)
{
    inspect(id = static_cast<x86_insn>(cs_insn.id),
        type, is_conditional);

    address = cs_insn.address;
    
    code = std::vector<uint8_t>(cs_insn.bytes, cs_insn.bytes + cs_insn.size);

    str_mnemonic = std::string(cs_insn.mnemonic, cs_insn.mnemonic + std::strlen(cs_insn.mnemonic));
    str_operands = std::string(cs_insn.op_str, cs_insn.op_str + std::strlen(cs_insn.op_str));

    operands = std::vector<operand_x86>(cs_insn.detail->x86.operands, cs_insn.detail->x86.operands + cs_insn.detail->x86.op_count);
}

static void inspect(const x86_insn id, instruction_type& type, bool& is_conditional)
{
    type = instruction_type::any;
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
        type = instruction_type::jmp;
        break;
    case X86_INS_CALL:
        type = instruction_type::call;
        break;
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        type = instruction_type::ret;
        break;
    case X86_INS_PUSH:
    case X86_INS_PUSHAL:
    case X86_INS_PUSHAW:
    case X86_INS_PUSHF:
    case X86_INS_PUSHFD:
    case X86_INS_PUSHFQ:
        type = instruction_type::push;
        break;
    case X86_INS_POP:
    case X86_INS_POPAL:
    case X86_INS_POPAW:
    case X86_INS_POPCNT:
    case X86_INS_POPF:
    case X86_INS_POPFD:
    case X86_INS_POPFQ:
        type = instruction_type::pop;
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
        type = instruction_type::mov;
        break;
    case X86_INS_CMP:
    case X86_INS_TEST:
        type = instruction_type::cond;
        break;
    case X86_INS_ADD:
    case X86_INS_DIV:
    case X86_INS_MUL:
    case X86_INS_SUB:
        type = instruction_type::arith;
        break;
    default:;
    }
}
