#pragma once

#include <set>
#include <vector>

#include <decompilation/data_section.hpp>
#include <decompilation/instruction_set_architecture.hpp>

namespace dec
{
    class program
    {
        instruction_set_architecture architecture_ { };
        std::uint_fast64_t start_address_ { };

        std::vector<std::byte> data_ { };
        std::set<data_section, data_section::exclusive_address_order> sections_ { };

    public:

        explicit program(std::vector<std::byte> data);
        program(std::vector<std::byte> data, instruction_set_architecture architecture);

        instruction_set_architecture architecture() const;
        std::uint_fast64_t start_address() const;

        std::basic_string_view<std::byte> operator[](std::uint_fast64_t address) const;
    };
}
