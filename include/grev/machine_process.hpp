#pragma once

#include <grev/execution.hpp>
#include <grev/machine_program.hpp>

namespace grev
{
    class machine_process
    {
        machine_program program_;

        std::unordered_map<std::uint32_t, std::u8string> patches_;

    public:

        machine_process(machine_program program, std::unordered_map<std::uint32_t, std::u8string> patches);

        template <typename Disassembler>
        execution execute(Disassembler const& disassembler) const;

    private:

        execution_state memory_patch(std::unordered_set<z3::expression> const& dependencies) const;
    };
}

#ifndef LINT
#include <grev/machine_process.tpp>
#endif
