#include "stdafx.h"

#include "control_flow.h"

assignment::assignment(const operand_x86 source, const operand_x86 destination)
    : source(source), destination(destination)
{
    switch (source.type)
    {
    case X86_OP_INVALID:
        throw std::runtime_error("Invalid source");
    default:;
    }

    switch (destination.type)
    {
    case X86_OP_INVALID:
    case X86_OP_IMM:
    case X86_OP_FP:
        throw std::runtime_error("Invalid destination");
    default:;
    }
}

control_flow_x86::control_flow_x86(const disassembly_x86* disassembly, const uint64_t address, const code_constraint constraint)
    : disassembly_(disassembly), address_(address), constraint_(constraint) { }

instruction_x86 control_flow_x86::instruction() const
{
    return disassembly_->find(address_);
}

std::vector<control_flow_x86> control_flow_x86::next(std::optional<assignment>& asgn) const
{
    asgn = std::nullopt;

    const auto uc = disassembly_->uc();
    const auto ins = instruction();

    uc_reg_write(uc, UC_X86_REG_RIP, &address_);

    const auto err = uc_emu_start(uc, address_, -1, 0, 1);

    uint64_t address;
    uc_reg_read(uc, UC_X86_REG_RIP, &address);

    auto op1 = ins.operands().at(0);
    auto op2 = ins.operands().at(1);

    switch (ins.identification())
    {
    case X86_INS_JNE:
        return
        {
            control_flow_x86(disassembly_, address_ + ins.size()),
            control_flow_x86(disassembly_, op1.value64)
        };
    case X86_INS_LEA:
        op2 = normalize(op2);
        if (op2.value8 == X86_REG_INVALID && op2.value64 != 0)
            op2 = operand_x86(X86_OP_IMM, 0, op2.value64);
        else if (op2.value8 != X86_REG_INVALID && op2.value64 == 0)
            op2 = operand_x86(X86_OP_REG, op2.value8, 0);
        else throw std::runtime_error("Unexpected LEA");
    case X86_INS_MOV:
        asgn = assignment(normalize(op2), normalize(op1));
    default:
        return
        {
            control_flow_x86(disassembly_, address)
        };
    }
}

operand_x86 control_flow_x86::normalize(const operand_x86 operand) const
{
    if (operand.type != X86_OP_MEM)
        return operand;

    switch (operand.value8)
    {
    case X86_REG_IP:
    case X86_REG_EIP:
    case X86_REG_RIP:
        break;
    default:
        return operand;
    }

    return operand_x86(X86_OP_MEM, 0, address_ + instruction().size() + operand.value64);
}
