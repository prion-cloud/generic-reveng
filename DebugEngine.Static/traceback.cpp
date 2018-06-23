#include "stdafx.h"

#include "traceback.h"

static uint64_t resolve_address(x86_op_mem op_mem, const std::function<uint64_t(x86_reg)>& reg_read_func)
{
    return reg_read_func(static_cast<x86_reg>(op_mem.base)) + reg_read_func(static_cast<x86_reg>(op_mem.index)) * op_mem.scale + op_mem.disp;
}

traceback_x86::traceback_x86(instruction_x86 instruction, const uc_err error,
    const std::function<uint64_t(x86_reg)>& reg_read_func, const std::function<uint64_t(uint64_t)>& mem_read_func)
    : instruction_(std::move(instruction)), error_(error)
{
    const auto op0 = !instruction_.operands.empty() ? instruction_.operands.at(0) : operand_x86();
    const auto op1 = instruction_.operands.size() > 1 ? instruction_.operands.at(1) : operand_x86();

    std::optional<uint64_t> address_write;
    std::optional<uint64_t> address_read;

    switch (instruction_.type)
    {
    case ins_push:
        address_write = reg_read_func(X86_REG_RSP);
        break;
    case ins_pop:
        address_read = reg_read_func(X86_REG_RSP);
        break;
    case ins_move:
        if (op0.type == op_memory)
        {
            address_write = resolve_address(std::get<op_memory>(op0.value), reg_read_func);
            //if () TODO: XCHG
        }
        if (op1.type == op_memory)
            address_read = resolve_address(std::get<op_memory>(op1.value), reg_read_func);
    default:;
    }

    if (address_write.has_value())
        memory_write_ = std::make_pair(address_write.value(), mem_read_func(address_write.value()));
    if (address_read.has_value())
        memory_read_ = std::make_pair(address_read.value(), mem_read_func(address_read.value()));
}

bool traceback_x86::has_failed() const
{
    return error_ != UC_ERR_OK;
}

bool traceback_x86::memory_write(uint64_t& address, uint64_t& value) const
{
    if (!memory_write_.has_value())
        return false;

    address = memory_write_->first;
    value = memory_write_->second;

    return true;
}
bool traceback_x86::memory_read(uint64_t& address, uint64_t& value) const
{
    if (!memory_read_.has_value())
        return false;

    address = memory_read_->first;
    value = memory_read_->second;

    return true;
}

const instruction_x86* traceback_x86::operator->() const
{
    return &instruction_;
}
