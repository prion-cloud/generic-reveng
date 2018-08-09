#include "instruction.h"

memory_descriptor::memory_descriptor(x86_op_mem const& cs_memory_descriptor)
{
    segment = cs_memory_descriptor.segment;
    base = cs_memory_descriptor.base;
    index = cs_memory_descriptor.index;

    scale = cs_memory_descriptor.scale;

    displacement = cs_memory_descriptor.disp;
}

operand::operand(cs_x86_op const& cs_operand)
{
    switch (type = cs_operand.type)
    {
    case X86_OP_REG:
        value = static_cast<unsigned>(cs_operand.reg);
        break;
    case X86_OP_IMM:
        value = cs_operand.imm;
        break;
    case X86_OP_MEM:
        value = memory_descriptor(cs_operand.mem);
        break;
    case X86_OP_FP:
        value = cs_operand.fp;
        break;
    default:
        throw std::runtime_error("Unknown operand type");
    }
}

instruction::instruction(cs_insn const& cs_instruction)
{
    id = cs_instruction.id;

    code = std::vector<uint8_t>(cs_instruction.bytes, cs_instruction.bytes + cs_instruction.size);

    auto const detail = cs_instruction.detail;

    if (detail == nullptr)
        throw std::runtime_error("No instruction detail provided");

    auto const x86 = detail->x86; // TODO: x86

    operands = std::vector<operand>(x86.operands, x86.operands + x86.op_count);

    str_mnemonic = cs_instruction.mnemonic;
    str_operands = cs_instruction.op_str;
}
