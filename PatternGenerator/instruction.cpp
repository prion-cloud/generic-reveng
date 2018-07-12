#include "stdafx.h"

#include "instruction.h"

instruction::operand::operand(cs_x86_op cs_operand)
{
    switch (cs_operand.type)
    {
    case X86_OP_REG:
        type = op_register;
        value = cs_operand.reg;
        break;
    case X86_OP_IMM:
        type = op_immediate;
        value = cs_operand.imm;
        break;
    case X86_OP_MEM:
        type = op_memory;
        value = cs_operand.mem;
        break;
    case X86_OP_FP:
        type = op_float;
        value = cs_operand.fp;
        break;
    default:;
    }
}

instruction::instruction(cs_insn cs_instruction)
{
    id = static_cast<x86_insn>(cs_instruction.id);

    address = cs_instruction.address;

    code = std::vector<uint8_t>(cs_instruction.bytes, cs_instruction.bytes + cs_instruction.size);

    str_mnemonic = cs_instruction.mnemonic;
    str_operands = cs_instruction.op_str;

    flag = false;

    const auto detail = cs_instruction.detail;
    if (detail == nullptr)
        return;

    for (auto i = 0; i < detail->x86.op_count; ++i)
        operands.emplace_back(cs_instruction.detail->x86.operands[i]);

    for (auto i = 0; i < detail->regs_write_count; ++i)
    {
        if (cs_instruction.detail->regs_write[i] != X86_REG_EFLAGS)
            continue;

        flag = true;
        break;
    }
}

//bool instruction::is_jump() const
//{
//    switch (id)
//    {
//    case X86_INS_CALL:
//    case X86_INS_JA:
//    case X86_INS_JAE:
//    case X86_INS_JB:
//    case X86_INS_JBE:
//    case X86_INS_JCXZ:
//    case X86_INS_JE:
//    case X86_INS_JG:
//    case X86_INS_JGE:
//    case X86_INS_JL:
//    case X86_INS_JLE:
//    case X86_INS_JMP:
//    case X86_INS_JNE:
//    case X86_INS_JNO:
//    case X86_INS_JNP:
//    case X86_INS_JNS:
//    case X86_INS_JO:
//    case X86_INS_JP:
//    case X86_INS_JS:
//    case X86_INS_RET:
//    case X86_INS_RETF:
//    case X86_INS_RETFQ:
//        return true;
//    default:
//        return false;
//    }
//}
//bool instruction::is_conditional() const
//{
//    switch (id)
//    {
//    case X86_INS_CMOVA:
//    case X86_INS_CMOVAE:
//    case X86_INS_CMOVB:
//    case X86_INS_CMOVBE:
//    case X86_INS_CMOVE:
//    case X86_INS_CMOVG:
//    case X86_INS_CMOVGE:
//    case X86_INS_CMOVL:
//    case X86_INS_CMOVLE:
//    case X86_INS_CMOVNE:
//    case X86_INS_CMOVNO:
//    case X86_INS_CMOVNP:
//    case X86_INS_CMOVNS:
//    case X86_INS_CMOVO:
//    case X86_INS_CMOVP:
//    case X86_INS_CMOVS:
//    case X86_INS_JA:
//    case X86_INS_JAE:
//    case X86_INS_JB:
//    case X86_INS_JBE:
//    case X86_INS_JCXZ:
//    case X86_INS_JE:
//    case X86_INS_JG:
//    case X86_INS_JGE:
//    case X86_INS_JL:
//    case X86_INS_JLE:
//    case X86_INS_JNE:
//    case X86_INS_JNO:
//    case X86_INS_JNP:
//    case X86_INS_JNS:
//    case X86_INS_JO:
//    case X86_INS_JP:
//    case X86_INS_JS:
//        return true;
//    default:
//        return false;
//    }
//}

std::string instruction::to_string(const bool full) const
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << address;

    if (full)
    {
        ss << " " << str_mnemonic;
        if (!str_operands.empty())
        {
            ss << " ";

            const auto str_op = str_operands;
            if (operands.size() == 1 && operands.front().type == op_immediate)
                ss << std::hex << std::uppercase << std::get<op_immediate>(operands.front().value);
            else ss << str_operands;
        }
    }

    return ss.str();
}

bool operator<(const instruction_sequence_representation& seq1, const instruction_sequence_representation& seq2)
{
    for (unsigned i = 0; i < seq1.value.size() && i < seq2.value.size(); ++i)
    {
        const auto r1 = seq1.value.at(i);
        const auto r2 = seq2.value.at(i);

        if (r1 != r2)
            return r1 < r2;
    }

    return seq1.value.size() < seq2.value.size();
}

instruction_sequence::instruction_sequence(std::vector<instruction> instructions)
    : instructions_(std::move(instructions)) { }

instruction_sequence_representation instruction_sequence::get_representation(std::map<x86_reg, std::wstring>& reg_map, std::map<int64_t, std::wstring>& num_map) const
{
    reg_map.clear();
    num_map.clear();
    const std::function<std::wstring(x86_reg)> get_reg = [&reg_map](const x86_reg reg)
    {
        if (reg == X86_REG_RSP)             //
            return std::wstring(L"rsp");    // TODO

        if (reg_map.find(reg) == reg_map.end())
        {
            const auto str = L"$reg:r" + std::to_wstring(reg_map.size() + 1);
            reg_map.emplace(reg, str);
            return str;
        }

        return reg_map.at(reg);
    };
    const std::function<std::wstring(int64_t)> get_num = [&num_map](const int64_t num)
    {
        if (num == -8)                      // TODO
            return std::wstring(L"0x8");    // TODO
        if (num == 0x10)                    // TODO
            return std::wstring(L"0x10");   // TODO

        if (num_map.find(num) == num_map.end())
        {
            const auto str = L"$num:n" + std::to_wstring(num_map.size() + 1);
            num_map.emplace(num, str);
            return str;
        }

        return num_map.at(num);
    };

    std::vector<std::wstring> value;
    for (const auto& ins : instructions_)
    {
        std::wostringstream ss;

        ss << std::wstring(ins.str_mnemonic.begin(), ins.str_mnemonic.end());

        if (!ins.operands.empty())
            ss << " ";
        for (unsigned i = 0; i < ins.operands.size(); ++i)
        {
            if (i > 0)
                ss << L", ";
            switch (ins.operands.at(i).type)
            {
            case instruction::op_register:
                ss << get_reg(std::get<x86_reg>(ins.operands.at(i).value));
                break;
            case instruction::op_immediate:
                ss << get_num(std::get<int64_t>(ins.operands.at(i).value));
                break;
            case instruction::op_float:
                ss << get_num(static_cast<int64_t>(std::get<double>(ins.operands.at(i).value)));
                break;
            case instruction::op_memory:
                {
                    ss << L"[";
                    const auto mem = std::get<x86_op_mem>(ins.operands.at(i).value);
                    if (mem.base != X86_REG_INVALID)
                    {
                        ss << get_reg(static_cast<x86_reg>(mem.base));
                        if (mem.index != X86_REG_INVALID && mem.scale != 0 || mem.disp > 0)
                            ss << L" + ";
                        else if (mem.disp < 0)
                            ss << L" - ";
                    }
                    if (mem.index != X86_REG_INVALID && mem.scale != 0)
                    {
                        ss << get_reg(static_cast<x86_reg>(mem.index));
                        if (mem.scale != 1)
                            ss << L" * " << get_num(mem.scale);
                        if (mem.disp > 0)
                            ss << L" + ";
                        else if (mem.disp < 0)
                            ss << L" - ";
                    }
                    if (mem.disp != 0)
                        ss << get_num(mem.disp);
                    ss << L"]";
                }
                break;
            }
        }

        value.push_back(ss.str());
    }

    return instruction_sequence_representation { value };
}

std::vector<instruction_sequence> instruction_sequence::power() const
{
    std::vector<instruction_sequence> result;

    for (unsigned i = 0; i < instructions_.size(); ++i)
    {
        instruction_sequence seq;
        seq->push_back(instructions_.at(i));
        for (auto j = i + 1; j < instructions_.size(); ++j)
        {
            seq->push_back(instructions_.at(j));
            result.push_back(seq);
        }
    }

    return result;
}

std::vector<instruction>* instruction_sequence::operator->()
{
    return &instructions_;
}
std::vector<instruction> const* instruction_sequence::operator->() const
{
    return &instructions_;
}

bool operator<(const instruction_sequence & sequence1, const instruction_sequence & sequence2)
{
    if (sequence1->size() != sequence2->size())
        return sequence1->size() < sequence2->size();

    for (unsigned i = 0; i < sequence1->size(); ++i)
    {
        const auto ins1 = sequence1->at(i);
        const auto ins2 = sequence2->at(i);

        const auto s1 = ins1.str_mnemonic + ins1.str_operands;
        const auto s2 = ins2.str_mnemonic + ins2.str_operands;

        if (s1 != s2)
            return s1 < s2;
    }

    return false;
}
