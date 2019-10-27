#ifdef LINTER
#include <revengine/instruction_block.hpp>
#endif

namespace rev
{
    template <typename Disassembler>
    instruction_block::instruction_block(Disassembler const& disassembler, data_section data_section)
    {
        if (data_section.data.empty())
            throw std::invalid_argument("Empty data section");

        do
        {
            auto const& instruction = *insert(end(), disassembler(data_section));

            if (instruction.jump.size() != 1)
                break;

            auto const next_address = instruction.jump.begin()->evaluate();

            if (!next_address || *next_address != instruction.address + instruction.size)
                break;

            data_section.address = *next_address;
            data_section.data.remove_prefix(instruction.size);
        }
        while (!data_section.data.empty());
    }
}
