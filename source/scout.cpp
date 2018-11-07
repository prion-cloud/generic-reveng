#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../include/scout/control_flow_graph.h"
#include "../include/scout/debugger.h"

int main(int const argc, char const* const argv[])
{
    std::vector<std::string> const args(argv + 1, argv + argc);

    if (args.empty())
    {
        std::cerr << "Missing arguments" << std::endl;
        return 1;
    }

    auto const file_name = args.front();
    std::cout << file_name << std::endl;

    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.good())
    {
        std::cerr << "File could not be opened." << std::endl;
        return 1;
    }

    debugger debugger;
    file_stream >> debugger;

    if (file_stream.fail())
    {
        std::cerr << "File has invalid format." << std::endl;
        return 1;
    }

    auto const cfg = control_flow_graph(debugger);

    auto const blocks = cfg.get_blocks();
    for (auto const* block : blocks)
    {
        for (auto const& instruction : *block)
        {
            auto const dis = instruction.disassemble();

            std::cout
                << std::hex << std::uppercase << dis->address << " "
                << dis->mnemonic << " "
                << dis->op_str << std::endl;
        }

        std::cout << "-----//-----" << std::endl;
    }

    // TODO

    return 0;
}
