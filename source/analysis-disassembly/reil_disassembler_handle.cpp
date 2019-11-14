#include "reil_disassembler_handle.hpp"

namespace grev
{
    static int store_reil_instruction(reil_inst_t* const reil_instruction, void* const reil_instructions)
    {
        static_cast<std::vector<reil_inst_t>*>(reil_instructions)->push_back(*reil_instruction);
        return 0;
    }

    reil_disassembler::handle::handle(machine_architecture const architecture)
    {
        reil_arch_t reil_architecture;
        switch (architecture)
        {
            case machine_architecture::x86_32:
            case machine_architecture::x86_64:
                reil_architecture = ARCH_X86;
                break;
            default:
                throw std::runtime_error("Unknown architecture");
        }

        reil_ = reil_init(reil_architecture, store_reil_instruction, &reil_instructions_);
    }

    std::vector<reil_inst_t> reil_disassembler::handle::disassemble(data_section* const data_section)
    {
        constexpr std::size_t max_code_size = MAX_INST_LEN;

        std::vector<unsigned char> code(
            data_section->data.begin(),
            std::next(
                data_section->data.begin(),
                std::min(data_section->data.size(), max_code_size)));

        reil_translate_insn(reil_, data_section->address, code.data(), code.size());

        auto const size = reil_instructions_.front().raw_info.size;
        data_section->address += size;
        data_section->data.remove_prefix(size);

        return std::move(reil_instructions_);
    }
}
