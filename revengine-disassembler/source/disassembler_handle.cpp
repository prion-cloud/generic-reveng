#include "disassembler_handle.hpp"

namespace rev::dis
{
    static int store_reil_instruction(reil_inst_t* const reil_instruction, void* const reil_instructions)
    {
        static_cast<std::vector<reil_inst_t>*>(reil_instructions)->push_back(*reil_instruction);
        return 0;
    }

    disassembler::handle::handle(instruction_set_architecture const architecture)
    {
        reil_arch_t reil_architecture;
        switch (architecture)
        {
            case instruction_set_architecture::x86_32:
            case instruction_set_architecture::x86_64:
                reil_architecture = ARCH_X86;
                break;
            default:
                throw std::runtime_error("Unknown architecture");
        }

        reil_ = reil_init(reil_architecture, store_reil_instruction, &reil_instructions_);
    }

    std::vector<reil_inst_t> disassembler::handle::disassemble(data_section const& data_section)
    {
        constexpr std::size_t max_code_size = MAX_INST_LEN;

        std::vector code(
            data_section.data.begin(),
            std::next(
                data_section.data.begin(),
                std::min(data_section.data.size(), max_code_size)));

        reil_translate_insn(reil_, data_section.address, code.data(), code.size());
        return std::move(reil_instructions_);
    }
}
