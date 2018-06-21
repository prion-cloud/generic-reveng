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

instruction_x86_live::instruction_x86_live(const instruction_x86 base, const uc_err error, const std::function<uint64_t(x86_reg)> read_reg)
    : base_(base), error_(error)
{
    const auto op0 = base_.operands.size() > 0 ? base_.operands.at(0) : operand_x86();
    const auto op1 = base_.operands.size() > 1 ? base_.operands.at(1) : operand_x86();

    switch (base_.type)
    {
    case instruction_type::push:
        memory_write_ = std::make_pair(
            read_reg(X86_REG_RSP) + sizeof(void*),
            read_reg(op0.reg));
        break;
    case instruction_type::pop:
        memory_read_ = std::make_pair(
            read_reg(X86_REG_RSP) - sizeof(void*),
            read_reg(op0.reg));
        break;
    case instruction_type::move:
        if (op1.type == operand_type::mem)
            memory_read_ = std::make_pair(
                read_reg(static_cast<x86_reg>(op1.mem.base)) + op1.mem.disp,
                read_reg(op0.reg));
        if (op0.type == operand_type::mem)
        {
            switch (base_.operands.at(1).type)
            {
            case operand_type::reg:
                memory_write_ = std::make_pair(
                    read_reg(static_cast<x86_reg>(op0.mem.base)) + op0.mem.disp,
                    read_reg(static_cast<x86_reg>(op1.reg)));
                break;
            case operand_type::imm:
                memory_write_ = std::make_pair(
                    read_reg(static_cast<x86_reg>(op0.mem.base)) + op0.mem.disp,
                    op1.imm);
                break;
            default:;
            }
        }
        break;
    default:;
    }
}

bool instruction_x86_live::has_failed() const
{
    return error_ != UC_ERR_OK;
}

bool instruction_x86_live::memory_read(uint64_t& address, uint64_t& value) const
{
    if (!memory_read_.has_value())
        return false;

    address = memory_read_->first;
    value = memory_read_->second;

    return true;
}
bool instruction_x86_live::memory_write(uint64_t& address, uint64_t& value) const
{
    if (!memory_write_.has_value())
        return false;

    address = memory_write_->first;
    value = memory_write_->second;

    return true;
}

const instruction_x86* instruction_x86_live::operator->() const
{
    return &base_;
}

static void inspect(const x86_insn id, instruction_type& type, bool& is_conditional)
{
    type = instruction_type::unknown;
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
        type = instruction_type::jump;
        break;
    case X86_INS_CALL:
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
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
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
    case X86_INS_XCHG:
        type = instruction_type::move;
        break;
    case X86_INS_CMP:
    case X86_INS_TEST:
        type = instruction_type::conditon;
        break;
    case X86_INS_ADD:
    case X86_INS_DIV:
    case X86_INS_MUL:
    case X86_INS_SUB:
        type = instruction_type::arithmetic;
        break;
    default:;
    }
}
