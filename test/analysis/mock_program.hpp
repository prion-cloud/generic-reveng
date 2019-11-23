#pragma once

#include <generic-reveng/loading/program.hpp>

class mock_program : public grev::program
{
    grev::machine_architecture architecture_;

    std::set<grev::address_space_segment, grev::address_space_segment::exclusive_address_order> segments_;

public:

    mock_program(std::u8string data, grev::machine_architecture architecture);

    grev::machine_architecture architecture() const override;
    std::uint32_t start_address() const override;

    std::set<grev::address_space_segment, grev::address_space_segment::exclusive_address_order> const& segments() const override;
};
