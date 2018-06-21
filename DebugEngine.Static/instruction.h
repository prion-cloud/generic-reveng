#pragma once

#include <functional>

#include "../Bin-Capstone/capstone.h"
#include "../Bin-Unicorn/unicorn.h"

enum class operand_type
{
    reg,
    imm,
    mem,
    flp
};
enum class instruction_type
{
    unknown,
    jump,
    push,
    pop,
    move,
    conditon,
    arithmetic
};

struct operand_x86
{
    operand_type type;

    union
    {
		x86_reg reg;
		int64_t imm;
		x86_op_mem mem;
		double flp;
	};
    
    operand_x86() = default;
    operand_x86(cs_x86_op cs_op);
};
struct instruction_x86
{
    x86_insn id;

    instruction_type type;
    bool is_conditional;

    uint64_t address;

    std::vector<uint8_t> code;

    std::string str_mnemonic;
    std::string str_operands;

    std::vector<operand_x86> operands;

    instruction_x86() = default;
    instruction_x86(cs_insn cs_insn);
};

class instruction_x86_live
{
    instruction_x86 base_;

    uc_err error_;

    std::optional<std::pair<uint64_t, uint64_t>> memory_read_;
    std::optional<std::pair<uint64_t, uint64_t>> memory_write_;

public:

    instruction_x86_live() = default;
    instruction_x86_live(instruction_x86 base, uc_err error, std::function<uint64_t(x86_reg)> read_reg);

    bool has_failed() const;

    bool memory_read(uint64_t& address, uint64_t& value) const;
    bool memory_write(uint64_t& address, uint64_t& value) const;

    const instruction_x86* operator->() const;
};
