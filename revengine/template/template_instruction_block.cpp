#ifdef LINT
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

            if (!instruction.impact.jump())
                break;

            auto const step = *instruction.impact.jump();

            if (step != instruction.address + instruction.size)
                break;

            data_section.address = step;
            data_section.data.remove_prefix(instruction.size);
        }
        while (!data_section.data.empty());
    }
}

#ifdef LINT
#include <revengine/reil_disassembler.hpp>
template rev::instruction_block::instruction_block(rev::dis::reil_disassembler const&, data_section);
#endif
