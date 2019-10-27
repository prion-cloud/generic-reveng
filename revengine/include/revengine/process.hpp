#pragma once

#include <set>
#include <vector>

#include <revengine/data_section.hpp>
#include <revengine/instruction_set_architecture.hpp>

namespace rev
{
    class process // TODO std::set<instruction> ?
    {
        std::vector<std::uint8_t> data_;
        std::set<data_section, data_section::exclusive_address_order> data_sections_;

        instruction_set_architecture architecture_;

        std::uint64_t start_address_;

    public:

        explicit process(std::vector<std::uint8_t> data); // TODO Real loading mechanism
        process(std::vector<std::uint8_t> data, instruction_set_architecture architecture);

        instruction_set_architecture architecture() const;

        std::uint64_t start_address() const;

        data_section operator[](std::uint64_t address) const;
    };
}
