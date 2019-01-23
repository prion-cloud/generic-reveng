#include <sstream>

#include "../include/utility/disassembler.hpp"

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

void delete_cs(csh* const cs)
{
    cs_close(cs);
    delete cs; // NOLINT [cppcoreguidelines-owning-memory]
}

void delete_instruction(cs_insn* const instruction)
{
    cs_free(instruction, 1);
}

disassembler::disassembler() = default;
disassembler::disassembler(cs_arch const architecture, cs_mode const mode)
    : cs_(new csh, ::delete_cs)
{
    HANDLE_CS_ERROR(
        cs_open(architecture, mode, cs_.get()));
    HANDLE_CS_ERROR(
        cs_option(*cs_, CS_OPT_DETAIL, CS_OPT_ON));
}

std::shared_ptr<cs_insn const> disassembler::operator()(uint64_t* const address,
    std::basic_string_view<uint8_t>* const code) const
{
    auto const* code_ptr = code->data();
    auto size = code->size();

    std::shared_ptr<cs_insn> const instruction(cs_malloc(*cs_), ::delete_instruction);
    cs_disasm_iter(*cs_, &code_ptr, &size, address, instruction.get());

    HANDLE_CS_ERROR(
        cs_errno(*cs_));

    *code = std::basic_string_view<uint8_t>(code_ptr, size);

    return instruction;
}
