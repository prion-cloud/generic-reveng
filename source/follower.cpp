#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../include/follower/loader.h"

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
        std::cerr << "Invalid file" << std::endl;
        return 1;
    }

    loader_pe load(UC_ARCH_X86, UC_MODE_64);

    std::shared_ptr<uc_engine> context;

    try
    {
        context = load(file_stream);
    }
    catch (std::runtime_error const& error)
    {
        std::cerr << error.what() << std::endl;
        return 1;
    }

    // TODO

    std::cout << "Success!" << std::endl;
    return 0;
}
