#pragma once

#include <map>

#include <generic-reveng/analysis/machine_architecture.hpp>

namespace grev
{
    class machine_program
    {
        std::u8string data_;

        machine_architecture architecture_;
        std::uint32_t entry_point_address_;

        std::map<std::uint32_t, std::u8string_view> memory_segments_;

        machine_program();

    public:

        /*!
         *  Constructs a new program using unformatted machine code.
         *  \param [in] data Machine code data
         *  \param [in] architecture Instruction set architecture
         */
        machine_program(std::u8string data, machine_architecture architecture);

        machine_architecture architecture() const;
        std::uint32_t entry_point_address() const;

        std::u8string_view operator[](std::uint32_t address) const;

        template <typename Loader>
        static machine_program load(std::u8string data);
    };
}

#ifndef LINT
#include <generic-reveng/analysis/machine_program.tpp>
#endif
