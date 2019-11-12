#pragma once

#include <set>

#include <revengine/data_section.hpp>
#include <revengine/machine_architecture.hpp>

namespace rev
{
    class process
    {
        std::u8string data_;
        std::set<data_section, data_section::exclusive_address_order> data_sections_;

        machine_architecture architecture_;

        std::uint64_t start_address_;

    public:

        explicit process(std::u8string data); // TODO Real loading mechanism
        process(std::u8string data, machine_architecture architecture);

        machine_architecture architecture() const;

        std::uint64_t start_address() const;

        data_section operator[](std::uint64_t address) const;
    };
}
