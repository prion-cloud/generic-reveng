#pragma once

#include <revengine/process.hpp>

class mock_process : public rev::process
{
    rev::machine_architecture architecture_;

    std::set<rev::address_space_segment, rev::address_space_segment::exclusive_address_order> segments_;

public:

    mock_process(std::u8string data, rev::machine_architecture architecture);

    rev::machine_architecture architecture() const override;
    std::uint64_t start_address() const override;

    std::set<rev::address_space_segment, rev::address_space_segment::exclusive_address_order> const& segments() const override;
};
