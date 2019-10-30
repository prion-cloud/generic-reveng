#ifdef LINT
#include <revengine/instruction_block.hpp>
#endif

namespace rev
{
    template <typename Disassembler>
    instruction::instruction(Disassembler const& disassembler, data_section data_section)
    {
        impact_ = disassembler(&data_section);

        address_ = data_section.address;
        size_ = data_section.data.size();
    }
}

#ifdef LINT
#include <revengine/reil_disassembler.hpp>
template rev::instruction::instruction(rev::dis::reil_disassembler const&, data_section);
#endif
