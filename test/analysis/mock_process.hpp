#pragma once

#include <generic-reveng/loading/process.hpp>

class mock_process : public grev::process
{
    grev::machine_architecture architecture_;

    std::set<grev::address_space_segment, grev::address_space_segment::exclusive_address_order> segments_;

public:

    mock_process(std::u8string data, grev::machine_architecture architecture);

    grev::machine_architecture architecture() const override;
    std::uint64_t start_address() const override;

    std::set<grev::address_space_segment, grev::address_space_segment::exclusive_address_order> const& segments() const override;
};
