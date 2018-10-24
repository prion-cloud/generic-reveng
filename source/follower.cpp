#include <fstream>
#include <iostream>
#include <string>
#include <vector>

//#include "../include/follower/control_flow_graph.h"
#include "../include/follower/debugger.h"

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

    debugger const debugger(architecture::x86, mode::width64);
    file_stream >> debugger;

    if (file_stream.fail())
    {
        std::cerr << "File has invalid format." << std::endl;
        return 1;
    }

    std::cout << "0x" << std::hex << std::uppercase << debugger.position() << std::endl;

    // TODO

    return 0;
}
