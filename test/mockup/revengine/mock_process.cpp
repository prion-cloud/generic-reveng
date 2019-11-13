#include "mock_process.hpp"

mock_process::mock_process(std::u8string data, rev::machine_architecture const architecture) :
    process(std::move(data)),
    architecture_(std::move(architecture))
{
    segments_.emplace(0, 0, data_size());
}

rev::machine_architecture mock_process::architecture() const
{
    return architecture_;
}
std::uint64_t mock_process::start_address() const
{
    return 0;
}

std::set<rev::address_space_segment, rev::address_space_segment::exclusive_address_order> const&
    mock_process::segments() const
{
    return segments_;
}
