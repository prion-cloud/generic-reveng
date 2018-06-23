#pragma once

#include "../Bin-Unicorn/unicorn.h"

#include "instruction.h"

class traceback_x86
{
    instruction_x86 instruction_;

    uc_err error_ { };
    
    std::optional<std::pair<uint64_t, uint64_t>> memory_write_;
    std::optional<std::pair<uint64_t, uint64_t>> memory_read_;

public:

    traceback_x86() = default;
    traceback_x86(instruction_x86 instruction, uc_err error,
        const std::function<uint64_t(x86_reg)>& reg_read_func, const std::function<uint64_t(uint64_t)>& mem_read_func);

    bool has_failed() const;
    
    bool memory_write(uint64_t& address, uint64_t& value) const;
    bool memory_read(uint64_t& address, uint64_t& value) const;

    const instruction_x86* operator->() const;

    traceback_x86& operator=(const traceback_x86& step_into) = default;
};
