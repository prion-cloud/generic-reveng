#pragma once

#include <memory>

#include <revengine/data_section.hpp>
#include <revengine/instruction.hpp>
#include <revengine/instruction_set_architecture.hpp>

namespace rev::dis
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
