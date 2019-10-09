#pragma once

#include <memory>

#include <decompilation/data_section.hpp>
#include <decompilation/instruction.hpp>
#include <decompilation/instruction_set_architecture.hpp>

namespace dec
{
    class disassembler
    {
        class handle;
        std::unique_ptr<handle> handle_;

    public:

        explicit disassembler(instruction_set_architecture architecture);
        ~disassembler();

        instruction operator()(data_section const& data_section) const;
    };
}
