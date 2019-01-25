#include <sstream>

#include <utility/disassembler.hpp>

#define HANDLE_CS_ERROR(cs_call)                            \
{                                                           \
    cs_err const error_code = cs_call;                      \
    if (error_code != CS_ERR_OK)                            \
    {                                                       \
        std::ostringstream message;                         \
        message          << cs_strerror(error_code)         \
            << std::endl << #cs_call                        \
            << std::endl << __FILE__ << ':' << __LINE__;    \
                                                            \
        throw std::runtime_error(message.str());            \
    }                                                       \
}

std::unordered_set<std::optional<uint64_t>> instruction::get_called_addresses() const
{
    // TODO only x86?

    auto const op0 = detail->x86.operands[0];

    std::unordered_set<std::optional<uint64_t>> called_addresses;

    switch (id)
    {
    case X86_INS_CALL:
        switch (op0.type)
        {
        case X86_OP_IMM:
            called_addresses.emplace(op0.imm);
            break;
        default:
            called_addresses.emplace(std::nullopt);
            break;
        }
        break;
    }

    return called_addresses;
}
std::unordered_set<std::optional<uint64_t>> instruction::get_jumped_addresses() const
{
    // TODO only x86?

    auto const op0 = detail->x86.operands[0];

    std::unordered_set<std::optional<uint64_t>> jumped_addresses;

    switch (id)
    {
    case X86_INS_INT3:
    case X86_INS_INVALID:
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
        jumped_addresses.emplace(address + size);
    case X86_INS_JMP:
        switch (op0.type)
        {
        case X86_OP_IMM:
            jumped_addresses.emplace(op0.imm);
            break;
        default:
            jumped_addresses.emplace(std::nullopt);
            break;
        }
        break;
    default:
        jumped_addresses.emplace(address + size);
        break;
    }

    return jumped_addresses;
}

csh* allocate_cs()
{
    return new csh; // NOLINT [cppcoreguidelines-owning-memory]
}
void free_cs(csh* const cs)
{
    cs_close(cs);
    delete cs; // NOLINT [cppcoreguidelines-owning-memory]
}

disassembler::disassembler() = default;
disassembler::disassembler(cs_arch const architecture, cs_mode const mode)
    : cs_(::allocate_cs(), ::free_cs)
{
    HANDLE_CS_ERROR(
        cs_open(architecture, mode, cs_.get()));
    HANDLE_CS_ERROR(
        cs_option(*cs_, CS_OPT_DETAIL, CS_OPT_ON));
}

instruction* allocate_instruction(csh const& cs)
{
    return static_cast<instruction*>(cs_malloc(cs)); // NOLINT [cppcoreguidelines-pro-type-static-cast-downcast]
}
void free_instruction(instruction* const instruction)
{
    cs_free(instruction, 1);
}

std::shared_ptr<instruction> disassembler::operator()(uint64_t* const address,
    std::basic_string_view<uint8_t>* const code) const
{
    auto const* code_ptr = code->data();
    auto size = code->size();

    std::shared_ptr<instruction> const instruction(::allocate_instruction(*cs_), ::free_instruction);
    cs_disasm_iter(*cs_, &code_ptr, &size, address, instruction.get());

    HANDLE_CS_ERROR(
        cs_errno(*cs_));

    *code = std::basic_string_view<uint8_t>(code_ptr, size);

    return instruction;
}
