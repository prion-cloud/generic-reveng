#include "stdafx.h"

#include "data_monitor.h"

void data_monitor::apply(const instruction_x86& instruction)
{
    for (const auto& [reg, data] : inspect_changes(instruction))
        map_[reg] = data;
}

static std::string reg_name(const unsigned reg)
{
    csh cs;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs);

    const std::string name = cs_reg_name(cs, reg);

    cs_close(&cs);

    return name;
}
std::string data_monitor::safe_at(const x86_reg reg) const
{
    const auto it = map_.find(reg);

    if (it == map_.end())
        return reg_name(reg);

    return it->second;
}

std::map<x86_reg, std::string> data_monitor::inspect_changes(const instruction_x86& instruction) const
{
    std::map<x86_reg, std::string> changes
    {
        { X86_REG_RIP, std::to_string(instruction.address) }
    };

    std::optional<operand_x86> op0 = std::nullopt;
    if (!instruction.operands.empty())
        op0.emplace(instruction.operands.at(0));
    std::optional<operand_x86> op1 = std::nullopt;
    if (instruction.operands.size() > 1)
        op1.emplace(instruction.operands.at(1));

    switch (instruction.type)
    {
    case ins_push:
    case ins_call:
        changes.emplace(X86_REG_RSP, "(" + safe_at(X86_REG_RSP) + " - 8)");
        break;
    case ins_pop:
    case ins_return:
        changes.emplace(X86_REG_RSP, "(" + safe_at(X86_REG_RSP) + " + 8)");
        break;
    case ins_move:
        if (op0->type == op_register)
        {
            const auto reg0 = std::get<op_register>(op0->value);
            if (op1->type == op_register)
                changes.emplace(reg0, safe_at(std::get<op_register>(op1->value)));
            if (op1->type == op_immediate)
            {
                std::ostringstream ss;
                ss << std::hex << std::uppercase << std::get<op_immediate>(op1->value);
                changes.emplace(reg0, ss.str());
            }
            if (op1->type == op_memory)
                changes.emplace(reg0, "[???]");
        }
        break;
    case ins_arithmetic:
        if (instruction.id == X86_INS_MUL)
        {
            changes.emplace(X86_REG_RAX, "(" + safe_at(X86_REG_RAX) + " * " + safe_at(std::get<op_register>(op0->value)));
            changes.emplace(X86_REG_RDX, "0");
        }
        else if (instruction.id == X86_INS_DIV)
        {
            const auto rax = safe_at(X86_REG_RAX);
            const auto reg0 = safe_at(std::get<op_register>(op0->value));
            changes.emplace(X86_REG_RAX, "(" + rax + " / " + reg0 + ")");
            changes.emplace(X86_REG_RDX, "(" + rax + " % " + reg0 + ")");
        }
        else if (op0->type == op_register)
        {
            std::ostringstream ss;
            ss << "(" << safe_at(std::get<op_register>(op0->value));
            if (instruction.id == X86_INS_ADD)
                ss << " + ";
            if (instruction.id == X86_INS_SUB)
                ss << " - ";
            if (op1->type == op_register)
                ss << safe_at(std::get<op_register>(op1->value));
            if (op1->type == op_immediate)
                ss << std::hex << std::uppercase << std::get<op_immediate>(op1->value);
            if (op1->type == op_memory)
                ss << "[???]";
            ss << ")";
            changes.emplace(std::get<op_register>(op0->value), ss.str());
        }
        break;
    default:
        if (instruction.id == X86_INS_DEC)
        {
            if (op0->type == op_register)
            {
                const auto reg0 = std::get<op_register>(op0->value);
                changes.emplace(reg0, "(" + safe_at(reg0) + " - 1)");
            }
        }
        if (instruction.id == X86_INS_INC)
        {
            if (op0->type == op_register)
            {
                const auto reg0 = std::get<op_register>(op0->value);
                changes.emplace(reg0, "(" + safe_at(reg0) + " + 1)");
            }
        }
        if (instruction.id == X86_INS_LEA)
        {
            const auto mem1 = std::get<op_memory>(op1->value);
            std::ostringstream ss;
            ss << "(";
            if (mem1.base != 0)
            {
                ss << safe_at(static_cast<x86_reg>(mem1.base));
                if (mem1.index != 0 || mem1.disp != 0)
                    ss << " + ";
            }
            if (mem1.index != 0)
            {
                ss << safe_at(static_cast<x86_reg>(mem1.index));
                if (mem1.scale != 1)
                    ss << " * " << mem1.scale;
                if (mem1.disp != 0)
                    ss << " + ";
            }
            if (mem1.disp != 0)
                ss << std::hex << std::uppercase << mem1.disp;
            ss << ")";
            changes.emplace(std::get<op_register>(op0->value), ss.str());
        }
        if (instruction.id == X86_INS_NEG)
        {
            if (op0->type == op_register)
            {
                const auto reg0 = std::get<op_register>(op0->value);
                changes.emplace(reg0, "(-(" + safe_at(reg0) + "))");
            }
        }
        if (instruction.id == X86_INS_XCHG)
        {
            if (op0->type == op_register)
            {
                const auto reg0 = std::get<op_register>(op0->value);
                if (op1->type == op_register)
                {
                    const auto reg1 = std::get<op_register>(op1->value);
                    changes.emplace(reg0, safe_at(reg1));
                    changes.emplace(reg1, safe_at(reg0));
                }
                if (op1->type == op_memory)
                    changes.emplace(reg0, "[???]");
            }
            if (op0->type == op_memory)
                changes.emplace(std::get<op_register>(op1->value), "[???]");
        }
        break;
    }

    return changes;
}
