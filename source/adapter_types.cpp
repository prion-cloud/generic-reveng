#include <stdexcept>

#include "../include/follower/adapter_types.h"

instruction::instruction(cs_insn const cs_instruction)
{
    id = cs_instruction.id;

    address = cs_instruction.address;

    code = std::vector<uint8_t>(
        cs_instruction.bytes,
        cs_instruction.bytes + cs_instruction.size);

    mnemonic = cs_instruction.mnemonic;
    operand_string = cs_instruction.op_str;
}

cs_arch to_cs(architecture const architecture)
{
    switch (architecture)
    {
    case architecture::arm:
        return CS_ARCH_ARM;
    case architecture::arm64:
        return CS_ARCH_ARM64;
    case architecture::mips:
        return CS_ARCH_MIPS;
    case architecture::x86:
        return CS_ARCH_X86;
    case architecture::ppc:
        return CS_ARCH_PPC;
    case architecture::sparc:
        return CS_ARCH_SPARC;
    default:
        throw std::invalid_argument("Invalid architecture");
    }
}
cs_mode to_cs(mode const mode)
{
    switch (mode)
    {
    case mode::bit16:
        return CS_MODE_16;
    case mode::bit32:
        return CS_MODE_32;
    case mode::bit64:
        return CS_MODE_64;
    default:
        throw std::invalid_argument("Invalid mode");
    }
}

uc_arch to_uc(architecture const architecture)
{
    switch (architecture)
    {
    case architecture::arm:
        return UC_ARCH_ARM;
    case architecture::arm64:
        return UC_ARCH_ARM64;
    case architecture::mips:
        return UC_ARCH_MIPS;
    case architecture::x86:
        return UC_ARCH_X86;
    case architecture::ppc:
        return UC_ARCH_PPC;
    case architecture::sparc:
        return UC_ARCH_SPARC;
    default:
        throw std::invalid_argument("Invalid architecture");
    }
}
uc_mode to_uc(mode const mode)
{
    switch (mode)
    {
    case mode::bit16:
        return UC_MODE_16;
    case mode::bit32:
        return UC_MODE_32;
    case mode::bit64:
        return UC_MODE_64;
    default:
        throw std::invalid_argument("Invalid mode");
    }
}
