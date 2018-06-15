#include "stdafx.h"

#include "instruction.h"
#include "serialization.h"

instruction_x86::instruction_x86() = default;
instruction_x86::instruction_x86(const cs_insn cs_instruction)
{
    id_ = cs_instruction.id;
    address_ = static_cast<uint32_t>(cs_instruction.address);

    size_ = static_cast<uint8_t>(cs_instruction.size);
    memcpy_s(bytes_, size_, cs_instruction.bytes, cs_instruction.size);

    _snprintf_s(str_, MAX_STR - 1, "%s %s", cs_instruction.mnemonic, cs_instruction.op_str);

    if (cs_instruction.detail == nullptr)
    {
        op_count_ = 0;
        return;
    }

    const auto cs_detail = cs_instruction.detail->x86;

    op_count_ = cs_detail.op_count;
    for (auto i = 0; i < op_count_ && i < 4; ++i)
    {
        operand_types_[i] = cs_detail.operands[i].type;
        operand_values_[i] = cs_detail.operands[i].imm;
    }
}

std::shared_ptr<std::set<instruction_x86>> instruction_x86::load(const std::string file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    const auto size = get_size(file_stream);
    const auto count = size / sizeof(instruction_x86);

    const auto c_disassembly = new instruction_x86[count];
    file_stream.read(reinterpret_cast<char*>(c_disassembly), size);

    const auto disassembly = std::make_shared<std::set<instruction_x86>>(c_disassembly, c_disassembly + count);

    delete[] c_disassembly;

    return disassembly;
}
void instruction_x86::save(const std::string file_name, std::shared_ptr<std::vector<instruction_x86>> disassembly)
{
    std::ofstream(file_name, std::ios::binary)
        .write(reinterpret_cast<const char*>(&disassembly->at(0)), disassembly->size() * sizeof(instruction_x86));
}

bool operator<(const instruction_x86& left, const instruction_x86& right)
{
    return left.address_ < right.address_;
}
