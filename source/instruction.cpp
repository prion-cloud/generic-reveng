#include <list>
#include <stdexcept>
#include <unordered_set>

#include <scout/instruction.hpp>

assembly_instruction::assembly_instruction(cs_insn* const base)
    : base_(base) { }

assembly_instruction::~assembly_instruction()
{
    cs_free(base_, 1);
}

bool assembly_instruction::has_detail() const
{
    return base_->detail != nullptr;
}

bool assembly_instruction::belongs_to(cs_group_type const group) const
{
    if (!has_detail())
        throw std::runtime_error("Missing instruction detail");

    return std::unordered_set<int>(
        std::cbegin(base_->detail->groups),
        std::cend(base_->detail->groups))
            .count(group) > 0;
}

std::vector<std::optional<uint64_t>> assembly_instruction::get_successors() const
{
    if (!has_detail())
        throw std::runtime_error("Missing instruction detail");

    // TODO: Denote x86

    auto const op0 = base_->detail->x86.operands[0];

    std::vector<std::optional<uint64_t>> successors;

    switch (base_->id)
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
        successors.push_back(base_->address + base_->size);
    case X86_INS_JMP:
        switch (op0.type)
        {
        case X86_OP_IMM:
            successors.push_back(op0.imm);
            break;
        default:
            successors.push_back(std::nullopt);
            break;
        }
        break;
    default:
        successors.push_back(base_->address + base_->size);
        break;
    }

    return successors;
}

cs_insn const* assembly_instruction::operator->() const
{
    return base_;
}

machine_instruction::machine_instruction(std::shared_ptr<csh> cs, uint64_t const address, std::array<uint8_t, SIZE> const& code)
    : cs_(std::move(cs)), address(address), code(code) { }

assembly_instruction machine_instruction::disassemble() const
{
    cs_insn* cs_instruction;
    cs_disasm(*cs_, &code.front(), code.size(), address, 1, &cs_instruction);

    auto const error_code = cs_errno(*cs_);
    if (error_code != CS_ERR_OK)
        throw std::runtime_error(std::string("Disassembly failed: ") + cs_strerror(error_code));

    return assembly_instruction(cs_instruction);
}
