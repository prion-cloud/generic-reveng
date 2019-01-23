#include <fstream>

#include "debugger.hpp"

debugger::debugger()
    : loader_(&disassembler_, &emulator_) { }

void debugger::load_executable_file(std::string const& path)
{
    std::ifstream file_stream(path);

    if (!file_stream)
        throw std::runtime_error("Invalid file");

    std::vector<char> data(
        (std::istreambuf_iterator<char>(file_stream)),
        std::istreambuf_iterator<char>());

    load_executable(*reinterpret_cast<std::vector<uint8_t>*>(&data)); // NOLINT [cppcoreguidelines-pro-type-reinterpret-cast]
}
void debugger::load_executable(std::vector<uint8_t> const& data)
{
    loader_(data);
}

uint64_t debugger::position() const
{
    return emulator_.position();
}

control_flow_graph debugger::cfg() const
{
    return control_flow_graph(disassembler_, [this](uint64_t const address) { return emulator_.get_memory(address); },
        emulator_.position());
}
