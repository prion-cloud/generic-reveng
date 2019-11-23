#pragma once

#include <generic-reveng/loading/program.hpp>

namespace grev
{
    class pe_program : public program
    {
        machine_architecture architecture_;
        std::uint32_t start_address_;

        std::set<address_space_segment, address_space_segment::exclusive_address_order> segments_;

    public:

        explicit pe_program(std::u8string data);

        machine_architecture architecture() const override;
        std::uint32_t start_address() const override;

    protected:

        std::set<address_space_segment, address_space_segment::exclusive_address_order> const& segments() const override;
    };
}
