#include "stdafx.h"

#include "traceback.h"

static uint64_t resolve_address(x86_op_mem op_mem, const std::function<uint64_t(x86_reg)>& reg_read_func)
{
    return reg_read_func(static_cast<x86_reg>(op_mem.base)) + reg_read_func(static_cast<x86_reg>(op_mem.index)) * op_mem.scale + op_mem.disp;
}

traceback_x86::traceback_x86(const instruction_x86 instruction, const uc_err error, const context context)
    : instruction(instruction), has_failed(error != UC_ERR_OK)
{
    std::optional<operand_x86> op0 = std::nullopt;
    if (!instruction.operands.empty())
        op0.emplace(instruction.operands.at(0));

    std::optional<operand_x86> op1 = std::nullopt;
    if (instruction.operands.size() > 1)
        op1.emplace(instruction.operands.at(1));

    switch (instruction.type)
    {
    case ins_push:
        data_transfers.push_back(data_transfer_x86 { operand_x86::from_memory(context.instruction_pointer), *op0 });
        break;
    case ins_pop:
        data_transfers.push_back(data_transfer_x86 { *op0, operand_x86::from_memory(context.instruction_pointer) });
        break;
    case ins_move:
        data_transfers.push_back(data_transfer_x86 { *op0, *op1 });
        break;
    default:
        if (instruction.id == X86_INS_LEA)
        {
            data_transfers.push_back(
                data_transfer_x86
                {
                    *op0,
                    operand_x86::from_immediate(resolve_address(std::get<op_memory>(op1->value),
                        [context](const x86_reg reg)
                        {
                            if (reg == X86_REG_INVALID)
                                return uint64_t { 0 };

                            if (reg == X86_REG_RIP)
                                return context.instruction_pointer;
                            if (reg == X86_REG_RSP)
                                return context.stack_pointer;
                            if (reg == X86_REG_RBP)
                                return context.base_pointer;

                            return context.register_values.at(reg);
                        }))
                });
        }
        if (instruction.id == X86_INS_XCHG)
        {
            data_transfers.push_back(data_transfer_x86 { *op0, *op1 });
            data_transfers.push_back(data_transfer_x86 { *op1, *op0 });
        }
    }
}
