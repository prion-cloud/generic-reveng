#include <stdexcept>

#include "../include/scout/instruction.h"

instruction::instruction(cs_insn const cs_instruction)
{
    id = cs_instruction.id;

    groups = std::unordered_set<unsigned>(
        std::cbegin(cs_instruction.detail->groups),
        std::cend(cs_instruction.detail->groups));
    groups.erase(CS_GRP_INVALID);

    address = cs_instruction.address;

    code = std::vector<uint8_t>(
        std::cbegin(cs_instruction.bytes),
        std::cend(cs_instruction.bytes));
    code.resize(cs_instruction.size);

    mnemonic = std::string(
        std::cbegin(cs_instruction.mnemonic),
        std::cend(cs_instruction.mnemonic));
    mnemonic.erase(mnemonic.find_first_of('\0'));

    operand_string = std::string(
        std::cbegin(cs_instruction.op_str),
        std::cend(cs_instruction.op_str));
    operand_string.erase(operand_string.find_first_of('\0'));
}
