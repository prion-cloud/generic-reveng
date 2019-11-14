#include "mock_program.hpp"

mock_program::mock_program(std::u8string data, grev::machine_architecture const architecture) :
    program(std::move(data)),
    architecture_(std::move(architecture))
{
    segments_.emplace(0, 0, data_size());
}

grev::machine_architecture mock_program::architecture() const
{
    return architecture_;
}
std::uint64_t mock_program::start_address() const
{
    return 0;
}

std::set<grev::address_space_segment, grev::address_space_segment::exclusive_address_order> const&
    mock_program::segments() const
{
    return segments_;
}
