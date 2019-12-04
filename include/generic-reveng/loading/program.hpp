#pragma once

#include <map>

#include <generic-reveng/analysis/machine_architecture.hpp>

namespace grev
{
    class program
    {
        std::u8string data_;

        machine_architecture architecture_;
        std::optional<std::uint32_t> entry_point_address_;

        std::map<std::uint32_t, std::u8string_view> memory_segments_;

    public:

        /*!
         *  Constructs a new program by reading formatted data.
         *  \param [in] data Formatted binary data
         */
        explicit program(std::u8string data);
        /*!
         *  Constructs a new program using unformatted machine code.
         *  \param [in] data Machine code data
         *  \param [in] architecture Instruction set architecture
         */
        program(std::u8string data, machine_architecture architecture);

        machine_architecture const& architecture() const;
        std::optional<std::uint32_t> const& entry_point_address() const;

        std::u8string_view operator[](std::uint32_t address) const;
    };
}
