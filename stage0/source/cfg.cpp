#include "cfg.hpp"

bool cfg::machine_instruction_compare::operator()(cs_insn const& ins1, cs_insn const& ins2) const
{
    return ins1.address < ins2.address;
}

bool cfg::machine_instruction_compare::operator()(cs_insn const& ins, uint64_t const address) const
{
    return ins.address < address;
}
bool cfg::machine_instruction_compare::operator()(uint64_t const address, cs_insn const& ins) const
{
    return address < ins.address;
}

bool cfg::block::operator<(block const& other) const
{
    return crbegin()->address < other.cbegin()->address;
}

bool operator<(cfg::block const& block, uint64_t const address)
{
    return block.crbegin()->address < address;
}
bool operator<(uint64_t const address, cfg::block const& block)
{
    return address < block.cbegin()->address;
}

cfg::block const* cfg::root() const
{
    return root_;
}

decltype(cfg::blocks_.begin()) cfg::begin() const
{
    return blocks_.begin();
}
decltype(cfg::blocks_.end()) cfg::end() const
{
    return blocks_.end();
}

std::vector<std::optional<uint64_t>> cfg::get_next_addresses(cs_insn const& instruction)
{
    if (instruction.detail == nullptr)
        throw std::runtime_error("Missing instruction detail");

    // TODO only x86?

    auto const op0 = instruction.detail->x86.operands[0];

    std::vector<std::optional<uint64_t>> successors;

    switch (instruction.id)
    {
    case X86_INS_INVALID:
    case X86_INS_INT3:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        break;
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
        successors.emplace_back(instruction.address + instruction.size);
    case X86_INS_JMP:
        switch (op0.type)
        {
        case X86_OP_IMM:
            successors.emplace_back(op0.imm);
            break;
        default:
            successors.emplace_back(std::nullopt);
            break;
        }
        break;
    default:
        successors.emplace_back(instruction.address + instruction.size);
        break;
    }

    return successors;
}
