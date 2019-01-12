#include "../include/utility/disassembler.hpp"

inline void handle_cs_error(cs_err const cs_error)
{
    if (cs_error != CS_ERR_OK)
        throw std::runtime_error(cs_strerror(cs_error));
}

disassembler::disassembler(machine_architecture const& architecture)
    : std::shared_ptr<csh>(
        new csh,
        cs_close)
{
    cs_arch cs_architecture;
    cs_mode cs_mode;
    switch (architecture)
    {
    case machine_architecture::x86_32:
        cs_architecture = CS_ARCH_X86;
        cs_mode = CS_MODE_32;
        break;
    case machine_architecture::x86_64:
        cs_architecture = CS_ARCH_X86;
        cs_mode = CS_MODE_64;
        break;
    }

    handle_cs_error(
        cs_open(cs_architecture, cs_mode, get()));
    handle_cs_error(
        cs_option(operator*(), CS_OPT_DETAIL, CS_OPT_ON));
}

cs_insn disassembler::operator()(std::vector<uint8_t>* const code, uint64_t* const address) const
{
    auto const cs = operator*();

    auto const* code_ptr = &code->front();
    auto size = code->size();

    auto* cs_instruction_ptr = cs_malloc(cs);
    cs_disasm_iter(cs, &code_ptr, &size, address, cs_instruction_ptr);

    handle_cs_error(
        cs_errno(cs));

    *code = std::vector<uint8_t>(code_ptr, code_ptr + size);

    auto const cs_instruction = *cs_instruction_ptr;
    cs_free(cs_instruction_ptr, 1);

    return cs_instruction;
}
