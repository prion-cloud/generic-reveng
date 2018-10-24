#include <stdexcept>

#include "../include/follower/adapter_types.h"

instruction::instruction(cs_insn const cs_instruction)
{
    id = cs_instruction.id;

    address = cs_instruction.address;

    code = std::vector<uint8_t>(
        std::cbegin(cs_instruction.bytes),
        std::cend(cs_instruction.bytes));

    mnemonic = std::string(
        std::cbegin(cs_instruction.mnemonic),
        std::cend(cs_instruction.mnemonic));
    operand_string = std::string(
        std::cbegin(cs_instruction.op_str),
        std::cend(cs_instruction.op_str));

    code.resize(cs_instruction.size);

    mnemonic.erase(mnemonic.find_first_of('\0'));
    operand_string.erase(operand_string.find_first_of('\0'));
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
    case mode::width16:
        return CS_MODE_16;
    case mode::width32:
        return CS_MODE_32;
    case mode::width64:
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
    case mode::width16:
        return UC_MODE_16;
    case mode::width32:
        return UC_MODE_32;
    case mode::width64:
        return UC_MODE_64;
    default:
        throw std::invalid_argument("Invalid mode");
    }
}
