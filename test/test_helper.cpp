#include <sstream>

#include "test_helper.h"

std::string to_cfg_string(control_flow_graph const& cfg)
{
    auto const blocks = cfg.get_blocks();

    std::ostringstream cfg_stream;
    for (size_t i = 0; i < blocks.size(); ++i)
    {
        if (i > 0)
        {
            cfg_stream
                << std::endl
                << std::endl;
        }

        cfg_stream << std::dec << i << ":";

        auto const [block, successor_indices] = blocks.at(i);

        for (auto const& instruction : *block)
        {
            cfg_stream
                << std::endl
                << std::hex << std::uppercase << instruction.address << " ";

            auto const disassembly = instruction.disassemble();

            cfg_stream << disassembly->mnemonic;

            if (disassembly->op_str[0] != '\0')
                cfg_stream << " " << disassembly->op_str;
        }

        if (!successor_indices.empty())
        {
            cfg_stream
                << std::endl
                << "-> ";
        }

        for (size_t j = 0; j < successor_indices.size(); ++j)
        {
            if (j > 0)
                cfg_stream << " ";

            cfg_stream << std::dec << successor_indices.at(j);
        }
    }

    return cfg_stream.str();
}
